// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package webrelay

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	relayChunkBytes        = webproto.MaxRelayPayloadBytes
	directChunkBytes       = webproto.MaxPayloadBytes
	relayWindowBytes       = 256 << 10
	relayWindowFrames      = relayWindowBytes / relayChunkBytes
	maxPendingFrames       = relayWindowFrames * 2
	maxPendingBytes        = int64(maxPendingFrames * relayChunkBytes)
	maxDirectPendingBytes  = 128 << 20
	maxDirectPendingFrames = maxDirectPendingBytes / directChunkBytes
	claimRetryDelay        = 250 * time.Millisecond
	frameRetryDelay        = 250 * time.Millisecond
	offerTokenTTL          = time.Hour
	defaultClaimPar        = 1
	maxFilenameBytes       = 255
	statusWaitingClaim     = "waiting-for-claim"
	statusClaimed          = "claimed"
	statusProbing          = "probing-direct"
	statusRelay            = "connected-relay"
	statusDirect           = "connected-direct"
	statusComplete         = "complete"
)

type Progress struct {
	Bytes int64
	Total int64
}

type Callbacks struct {
	Status   func(string)
	Progress func(Progress)
	Trace    func(string)
}

type DirectRole string

const (
	DirectRoleSender   DirectRole = "sender"
	DirectRoleReceiver DirectRole = "receiver"
)

type DirectSignalPeer interface {
	SendSignal(context.Context, webproto.FrameKind, uint64, []byte) error
	Signals() <-chan webproto.Frame
}

type DirectTransport interface {
	Start(context.Context, DirectRole, DirectSignalPeer) error
	Ready() <-chan struct{}
	Failed() <-chan error
	SendFrame(context.Context, []byte) error
	ReceiveFrames() <-chan []byte
	Close() error
}

type TransferOptions struct {
	Direct DirectTransport
}

type sendPath uint8

const (
	sendPathRelay sendPath = iota
	sendPathDirect
)

func chooseSendPath(opts TransferOptions, directActive bool) sendPath {
	if opts.Direct != nil && directActive {
		return sendPathDirect
	}
	return sendPathRelay
}

type FileSource interface {
	Name() string
	Size() int64
	ReadChunk(context.Context, int64, int) ([]byte, error)
}

type FileSink interface {
	Open(context.Context, webproto.Meta) error
	WriteChunk(context.Context, []byte) error
	Close(context.Context) error
}

type derpClient interface {
	PublicKey() key.NodePublic
	Close() error
	Send(context.Context, key.NodePublic, []byte) error
	SubscribeLossless(func(derpbind.Packet) bool) (<-chan derpbind.Packet, func())
}

type Offer struct {
	client derpClient
	token  token.Token
	gate   *rendezvous.Gate
}

type directState struct {
	ready          bool
	active         bool
	fallbackReason string
}

func (s *directState) noteFailureBeforeSwitch(err error) {
	s.ready = false
	s.active = false
	if err != nil {
		s.fallbackReason = err.Error()
	}
}

func (s *directState) noteReady() {
	s.ready = true
}

func (s *directState) noteSwitched() {
	s.ready = true
	s.active = true
	s.fallbackReason = ""
}

func (s *directState) noteFailure(err error) {
	s.noteFailureBeforeSwitch(err)
}

type derpSignalPeer struct {
	ctx         context.Context
	client      derpClient
	peerDERP    key.NodePublic
	frames      <-chan derpbind.Packet
	unsubscribe func()
	signals     chan webproto.Frame
	stopOnce    sync.Once
}

func newDERPSignalPeer(ctx context.Context, client derpClient, peerDERP key.NodePublic) *derpSignalPeer {
	frames, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		if pkt.From != peerDERP || !webproto.IsWebFrame(pkt.Payload) {
			return false
		}
		frame, err := webproto.Parse(pkt.Payload)
		if err != nil {
			return false
		}
		return isDirectSignalFrame(frame.Kind)
	})
	p := &derpSignalPeer{
		ctx:         ctx,
		client:      client,
		peerDERP:    peerDERP,
		frames:      frames,
		unsubscribe: unsubscribe,
		signals:     make(chan webproto.Frame, 16),
	}
	go p.run()
	return p
}

func (p *derpSignalPeer) SendSignal(ctx context.Context, kind webproto.FrameKind, seq uint64, payload []byte) error {
	return sendFrame(ctx, p.client, p.peerDERP, kind, seq, payload)
}

func (p *derpSignalPeer) Signals() <-chan webproto.Frame {
	return p.signals
}

func (p *derpSignalPeer) close() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		if p.unsubscribe != nil {
			p.unsubscribe()
		}
	})
}

func (p *derpSignalPeer) run() {
	defer close(p.signals)
	defer p.close()
	for {
		pkt, err := nextPacket(p.ctx, p.frames)
		if err != nil {
			return
		}
		frame, err := webproto.Parse(pkt.Payload)
		if err != nil || !isDirectSignalFrame(frame.Kind) {
			continue
		}
		select {
		case p.signals <- frame:
		case <-p.ctx.Done():
			return
		}
	}
}

func isDirectSignalFrame(kind webproto.FrameKind) bool {
	switch kind {
	case webproto.FrameWebRTCOffer, webproto.FrameWebRTCAnswer, webproto.FrameWebRTCIceCandidate, webproto.FrameWebRTCIceComplete, webproto.FrameDirectFailed:
		return true
	default:
		return false
	}
}

func marshalDirectReadyFrame(nextSeq uint64, bytesReceived int64) (webproto.Frame, error) {
	payload, err := json.Marshal(webproto.DirectReady{
		BytesReceived: bytesReceived,
		NextSeq:       nextSeq,
	})
	if err != nil {
		return webproto.Frame{}, err
	}
	return webproto.Frame{
		Kind:    webproto.FrameDirectReady,
		Seq:     nextSeq,
		Payload: payload,
	}, nil
}

func unmarshalFramePayload(frame webproto.Frame, dst any) error {
	return json.Unmarshal(frame.Payload, dst)
}

func NewOffer(ctx context.Context) (*Offer, string, error) {
	node, err := fetchWebRelayDERPNode(ctx, 0, "no DERP node available")
	if err != nil {
		return nil, "", err
	}
	client, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return nil, "", err
	}
	tokValue, encoded, err := newEncodedOfferToken(client, node)
	if err != nil {
		_ = client.Close()
		return nil, "", err
	}
	return &Offer{
		client: client,
		token:  tokValue,
		gate:   rendezvous.NewGate(tokValue),
	}, encoded, nil
}

func fetchWebRelayDERPNode(ctx context.Context, regionID int, missingErr string) (*tailcfg.DERPNode, error) {
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, err
	}
	node := firstDERPNode(dm, regionID)
	if node == nil {
		return nil, errors.New(missingErr)
	}
	return node, nil
}

func newEncodedOfferToken(client derpClient, node *tailcfg.DERPNode) (token.Token, string, error) {
	tokValue, err := newToken(client.PublicKey(), node.RegionID)
	if err != nil {
		return token.Token{}, "", err
	}
	encoded, err := token.Encode(tokValue)
	return tokValue, encoded, err
}

func (o *Offer) Close() error {
	if o == nil || o.client == nil {
		return nil
	}
	return o.client.Close()
}

func (o *Offer) SendWithOptions(ctx context.Context, src FileSource, cb Callbacks, opts TransferOptions) error {
	return o.send(ctx, src, cb, opts)
}

func (o *Offer) Send(ctx context.Context, src FileSource, cb Callbacks) error {
	return o.send(ctx, src, cb, TransferOptions{})
}

func (o *Offer) send(ctx context.Context, src FileSource, cb Callbacks, opts TransferOptions) error {
	if err := validateOfferSend(o, src); err != nil {
		return err
	}
	peerDERP, err := o.claimSendPeer(ctx, cb)
	if err != nil {
		return err
	}
	cb.status(statusClaimed)
	cb.status(statusRelay)

	peerCh, unsubscribe := o.subscribePeerFrames(peerDERP)
	defer unsubscribe()

	directTransport, direct, stopDirect := o.startSendDirectPath(ctx, peerDERP, cb, opts.Direct)
	defer stopDirect()

	cb.status(statusRelay)
	meta := webproto.Meta{Name: safeName(src.Name()), Size: src.Size()}
	if err := o.sendMeta(ctx, peerDERP, peerCh, meta); err != nil {
		return err
	}

	offset, seq, directTransport, direct, err := o.sendDataWindowed(
		ctx, src, cb, peerDERP, peerCh, meta.Size, directTransport, direct,
	)
	if err != nil {
		return err
	}
	if err := o.finishSend(ctx, peerDERP, peerCh, cb, directTransport, direct, offset, seq); err != nil {
		return err
	}
	cb.progress(Progress{Bytes: offset, Total: meta.Size})
	cb.status(statusComplete)
	return nil
}

func validateOfferSend(o *Offer, src FileSource) error {
	if o == nil || o.client == nil {
		return errors.New("nil offer")
	}
	if src == nil {
		return errors.New("nil source")
	}
	return nil
}

func (o *Offer) claimSendPeer(ctx context.Context, cb Callbacks) (key.NodePublic, error) {
	cb.status(statusWaitingClaim)
	cb.trace("offer-wait-claim")
	return o.waitClaim(ctx, cb)
}

func (o *Offer) subscribePeerFrames(peerDERP key.NodePublic) (<-chan derpbind.Packet, func()) {
	return o.client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && webproto.IsWebFrame(pkt.Payload)
	})
}

func (o *Offer) startSendDirectPath(ctx context.Context, peerDERP key.NodePublic, cb Callbacks, transport DirectTransport) (DirectTransport, *directState, func()) {
	if transport == nil {
		return nil, nil, func() {}
	}
	direct := &directState{}
	signalPeer := newDERPSignalPeer(ctx, o.client, peerDERP)
	stop := func() {
		signalPeer.close()
		_ = transport.Close()
	}
	if err := transport.Start(ctx, DirectRoleSender, signalPeer); err != nil {
		direct.noteFailureBeforeSwitch(err)
		return nil, direct, stop
	}
	cb.status(statusProbing)
	return transport, direct, stop
}

func (o *Offer) sendMeta(ctx context.Context, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, meta webproto.Meta) error {
	metaPayload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameMeta, 0, metaPayload, 0)
}

func (o *Offer) finishSend(ctx context.Context, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, cb Callbacks, directTransport DirectTransport, direct *directState, offset int64, seq uint64) error {
	path := chooseSendPath(TransferOptions{Direct: directTransport}, direct != nil && direct.active)
	if path == sendPathDirect {
		return o.finishSendDirect(ctx, peerDERP, peerCh, cb, directTransport, direct, offset, seq)
	}
	return sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameDone, seq, nil, offset)
}

func (o *Offer) finishSendDirect(ctx context.Context, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, cb Callbacks, directTransport DirectTransport, direct *directState, offset int64, seq uint64) error {
	err := sendDirectFrame(ctx, directTransport, webproto.FrameDone, seq, nil)
	if err == nil {
		return notifyAbort(ctx, o.client, peerDERP, awaitAck(ctx, peerCh, offset, 5*time.Minute))
	}
	if direct != nil && direct.active {
		return notifyAbort(ctx, o.client, peerDERP, err)
	}
	if direct != nil {
		direct.noteFailure(err)
	}
	cb.status(statusRelay)
	return sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameDone, seq, nil, offset)
}

func (o *Offer) sendDataWindowed(ctx context.Context, src FileSource, cb Callbacks, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, total int64, directTransport DirectTransport, direct *directState) (int64, uint64, DirectTransport, *directState, error) {
	transfer := newSendDataTransfer(ctx, o, src, cb, peerDERP, peerCh, total, directTransport, direct)
	err := transfer.run()
	return transfer.offset, transfer.seq, transfer.directTransport, transfer.direct, err
}

type sendDataTransfer struct {
	ctx             context.Context
	offer           *Offer
	src             FileSource
	cb              Callbacks
	peerDERP        key.NodePublic
	peerCh          <-chan derpbind.Packet
	total           int64
	window          *relayWindow
	offset          int64
	seq             uint64
	eof             bool
	directTransport DirectTransport
	direct          *directState
}

func newSendDataTransfer(ctx context.Context, offer *Offer, src FileSource, cb Callbacks, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, total int64, directTransport DirectTransport, direct *directState) *sendDataTransfer {
	return &sendDataTransfer{
		ctx:             ctx,
		offer:           offer,
		src:             src,
		cb:              cb,
		peerDERP:        peerDERP,
		peerCh:          peerCh,
		total:           total,
		window:          newRelayWindow(relayWindowConfig{MaxBytes: relayWindowBytes, MaxFrames: relayWindowFrames}),
		seq:             1,
		directTransport: directTransport,
		direct:          direct,
	}
}

func (t *sendDataTransfer) run() error {
	for {
		if err := t.pollDirect(); err != nil {
			return err
		}
		if err := t.fillWindow(); err != nil {
			return err
		}
		if err := t.pollDirect(); err != nil {
			return err
		}
		if err := t.prepareDirectSwitch(); err != nil {
			return err
		}
		if err := t.trySwitchDirect(); err != nil {
			return err
		}
		done, err := t.waitForOutstanding()
		if err != nil || done {
			return err
		}
	}
}

func (t *sendDataTransfer) pollDirect() error {
	var err error
	t.directTransport, err = pollSendDirectState(t.cb, t.direct, t.directTransport)
	if err != nil {
		return notifyAbort(t.ctx, t.offer.client, t.peerDERP, err)
	}
	return nil
}

func (t *sendDataTransfer) fillWindow() error {
	for !t.eof {
		chunkSize, ok, err := t.nextChunkSize()
		if err != nil || !ok {
			return err
		}
		if t.pausingForDirectSwitch() {
			return nil
		}
		if err := t.readAndSendChunk(chunkSize); err != nil {
			return err
		}
		if t.pausingForDirectSwitch() {
			return nil
		}
	}
	return nil
}

func (t *sendDataTransfer) nextChunkSize() (int, bool, error) {
	chunkSize := relayChunkBytes
	if !t.directActive() {
		return chunkSize, t.window.canSend(chunkSize), nil
	}
	chunkSize = directChunkBytes
	if err := t.drainDirectAcks(); err != nil {
		return 0, false, err
	}
	return chunkSize, t.window.canSend(chunkSize), nil
}

func (t *sendDataTransfer) directActive() bool {
	return t.direct != nil && t.direct.active && t.directTransport != nil
}

func (t *sendDataTransfer) pausingForDirectSwitch() bool {
	return t.direct != nil && t.direct.ready && !t.direct.active && !t.window.empty()
}

func (t *sendDataTransfer) readAndSendChunk(chunkSize int) error {
	chunk, err := t.src.ReadChunk(t.ctx, t.offset, chunkSize)
	if err != nil {
		return t.notifySendError(err, true)
	}
	if len(chunk) == 0 {
		t.eof = true
		return nil
	}
	frame := t.nextRelayFrame(chunk)
	if err := t.sendDataFrame(frame); err != nil {
		return err
	}
	t.advance(frame.NextOffset)
	return nil
}

func (t *sendDataTransfer) nextRelayFrame(chunk []byte) relayFrame {
	nextOffset := t.offset + int64(len(chunk))
	frame := relayFrame{Seq: t.seq, Offset: t.offset, NextOffset: nextOffset, Payload: chunk}
	t.window.push(frame)
	return frame
}

func (t *sendDataTransfer) sendDataFrame(frame relayFrame) error {
	if t.directActive() {
		err := sendDirectFrame(t.ctx, t.directTransport, webproto.FrameData, frame.Seq, frame.Payload)
		if err != nil {
			return t.notifySendError(err, true)
		}
		t.window.markSent(frame.Seq)
		return nil
	}
	err := sendRelayDataFrame(t.ctx, t.offer.client, t.peerDERP, frame)
	if err != nil {
		return t.notifySendError(err, false)
	}
	t.window.markSent(frame.Seq)
	return nil
}

func (t *sendDataTransfer) advance(nextOffset int64) {
	t.offset = nextOffset
	if !t.directActive() {
		t.cb.progress(Progress{Bytes: t.offset, Total: t.total})
	}
	t.seq++
}

func (t *sendDataTransfer) prepareDirectSwitch() error {
	if t.direct == nil || !t.direct.ready || t.direct.active || t.window.empty() {
		return nil
	}
	if err := awaitRelayWindowAck(t.ctx, t.offer.client, t.peerDERP, t.peerCh, t.window); err != nil {
		return t.notifySendError(err, false)
	}
	return t.pollDirect()
}

func (t *sendDataTransfer) trySwitchDirect() error {
	if t.direct == nil || t.directTransport == nil || !t.direct.ready || t.direct.active || t.offset == 0 {
		return nil
	}
	switched, err := trySwitchDirectWithReplay(t.ctx, t.offer.client, t.peerDERP, t.peerCh, t.directTransport, t.seq, t.window, t.cb)
	if err != nil {
		return t.notifySendError(err, false)
	}
	if switched {
		t.direct.noteSwitched()
		t.window.cfg = relayWindowConfig{MaxBytes: maxDirectPendingBytes, MaxFrames: maxDirectPendingFrames}
		t.cb.status(statusDirect)
	}
	return nil
}

func (t *sendDataTransfer) waitForOutstanding() (bool, error) {
	if t.directActive() {
		return t.waitForDirectOutstanding()
	}
	if t.eof && t.window.empty() {
		return true, nil
	}
	if t.window.empty() {
		return false, nil
	}
	return false, t.awaitRelayAck()
}

func (t *sendDataTransfer) waitForDirectOutstanding() (bool, error) {
	if err := t.drainDirectAcks(); err != nil {
		return false, err
	}
	if t.eof && t.window.empty() {
		return true, nil
	}
	if t.window.empty() {
		return false, nil
	}
	err := awaitDirectWindowAck(t.ctx, t.peerCh, t.directTransport, t.window, t.cb, t.total)
	if err != nil {
		return false, t.notifySendError(err, true)
	}
	return false, nil
}

func (t *sendDataTransfer) drainDirectAcks() error {
	err := drainDirectWindowAcks(t.ctx, t.peerCh, t.directTransport, t.window, t.cb, t.total)
	if err != nil {
		return t.notifySendError(err, true)
	}
	return nil
}

func (t *sendDataTransfer) awaitRelayAck() error {
	err := awaitRelayWindowAck(t.ctx, t.offer.client, t.peerDERP, t.peerCh, t.window)
	if err != nil {
		return t.notifySendError(err, false)
	}
	return nil
}

func (t *sendDataTransfer) notifySendError(err error, notify bool) error {
	if ctxErr := abortIfContextDone(t.ctx, t.offer.client, t.peerDERP); ctxErr != nil {
		return ctxErr
	}
	if notify {
		return notifyAbort(t.ctx, t.offer.client, t.peerDERP, err)
	}
	return err
}

func ReceiveWithOptions(ctx context.Context, encodedToken string, sink FileSink, cb Callbacks, opts TransferOptions) error {
	return receive(ctx, encodedToken, sink, cb, opts)
}

func Receive(ctx context.Context, encodedToken string, sink FileSink, cb Callbacks) error {
	return receive(ctx, encodedToken, sink, cb, TransferOptions{})
}

func receive(ctx context.Context, encodedToken string, sink FileSink, cb Callbacks, opts TransferOptions) error {
	if sink == nil {
		return errors.New("nil sink")
	}
	tok, err := decodeWebFileToken(encodedToken)
	if err != nil {
		return err
	}
	node, err := fetchWebRelayDERPNode(ctx, int(tok.BootstrapRegion), "no bootstrap DERP node available")
	if err != nil {
		return err
	}
	client, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return receiveWithClient(ctx, tok, client, sink, cb, opts)
}

func decodeWebFileToken(encodedToken string) (token.Token, error) {
	tok, err := token.Decode(encodedToken, time.Now())
	if err != nil {
		return token.Token{}, err
	}
	if tok.Capabilities != token.CapabilityWebFile {
		return token.Token{}, errors.New("token is not a derphole web file offer")
	}
	return tok, nil
}

func receiveWithClient(ctx context.Context, tok token.Token, client derpClient, sink FileSink, cb Callbacks, opts TransferOptions) error {
	peerDERP := keyNodePublicFromRaw32(tok.DERPPublic)
	cb.trace("claim-peer=" + peerDERP.ShortString())

	directTransport := opts.Direct
	var signalPeer *derpSignalPeer
	if directTransport != nil {
		signalPeer = newDERPSignalPeer(ctx, client, peerDERP)
		defer signalPeer.close()
		defer func(transport DirectTransport) { _ = transport.Close() }(directTransport)
	}

	frames, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	claim, err := newClaim(tok, client.PublicKey())
	if err != nil {
		return err
	}
	if err := sendClaimUntilDecision(ctx, client, peerDERP, frames, claim, cb); err != nil {
		return err
	}

	if directTransport != nil {
		if err := directTransport.Start(ctx, DirectRoleReceiver, signalPeer); err != nil {
			directTransport = nil
		} else {
			cb.status(statusProbing)
		}
	}

	cb.status(statusRelay)
	mergedFrames, stopMerge := mergeFrameSources(ctx, frames, directTransport)
	defer stopMerge()
	return receiveFrames(ctx, client, peerDERP, mergedFrames, directTransport, sink, cb)
}

func receiveFrames(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan []byte, direct DirectTransport, sink FileSink, cb Callbacks) error {
	return newReceiveFrameTransfer(ctx, client, peerDERP, frames, direct, sink, cb).run()
}

type receiveFrameTransfer struct {
	ctx           context.Context
	client        derpClient
	peerDERP      key.NodePublic
	frames        <-chan []byte
	direct        DirectTransport
	sink          FileSink
	cb            Callbacks
	meta          webproto.Meta
	expectedSeq   uint64
	received      int64
	opened        bool
	directActive  bool
	pendingFrames map[uint64][]byte
	pendingBytes  int64
	doneSeen      bool
	doneSeq       uint64
}

func newReceiveFrameTransfer(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan []byte, direct DirectTransport, sink FileSink, cb Callbacks) *receiveFrameTransfer {
	return &receiveFrameTransfer{
		ctx:           ctx,
		client:        client,
		peerDERP:      peerDERP,
		frames:        frames,
		direct:        direct,
		sink:          sink,
		cb:            cb,
		expectedSeq:   1,
		pendingFrames: make(map[uint64][]byte),
	}
}

func (t *receiveFrameTransfer) run() error {
	for {
		frame, ok, err := t.nextFrame()
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := t.handleFrame(frame); err != nil {
			if errors.Is(err, errReceiveComplete) {
				return nil
			}
			return err
		}
	}
}

func (t *receiveFrameTransfer) nextFrame() (webproto.Frame, bool, error) {
	raw, err := nextRawFrame(t.ctx, t.frames, t.direct, t.directActive)
	if err != nil {
		return webproto.Frame{}, false, t.handleReadError(err)
	}
	frame, err := webproto.Parse(raw)
	if err != nil {
		return webproto.Frame{}, false, nil
	}
	return frame, true, nil
}

func (t *receiveFrameTransfer) handleReadError(err error) error {
	if ctxErr := abortIfContextDone(t.ctx, t.client, t.peerDERP); ctxErr != nil {
		return ctxErr
	}
	if t.directActive {
		_ = sendAbortBestEffort(t.ctx, t.client, t.peerDERP, err.Error())
	}
	return err
}

func (t *receiveFrameTransfer) handleFrame(frame webproto.Frame) error {
	switch frame.Kind {
	case webproto.FrameMeta:
		return t.handleMeta(frame)
	case webproto.FrameData:
		return t.handleData(frame)
	case webproto.FrameDirectReady:
		return t.handleDirectReady(frame)
	case webproto.FrameDone:
		return t.handleDone(frame)
	case webproto.FrameAbort:
		return decodeAbort(frame.Payload)
	default:
		return nil
	}
}

func (t *receiveFrameTransfer) handleMeta(frame webproto.Frame) error {
	if t.opened {
		_ = sendAck(t.ctx, t.client, t.peerDERP, t.received)
		return nil
	}
	if err := json.Unmarshal(frame.Payload, &t.meta); err != nil {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, "invalid metadata")
	}
	if err := t.sink.Open(t.ctx, t.meta); err != nil {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, err.Error())
	}
	t.opened = true
	t.cb.progress(Progress{Bytes: 0, Total: t.meta.Size})
	return sendAck(t.ctx, t.client, t.peerDERP, 0)
}

func (t *receiveFrameTransfer) handleData(frame webproto.Frame) error {
	if !t.opened {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, "data before metadata")
	}
	if frame.Seq < t.expectedSeq {
		return t.sendBestEffortAck()
	}
	if frame.Seq > t.expectedSeq {
		if err := t.bufferPendingFrame(frame); err != nil {
			return err
		}
		return t.sendBestEffortAck()
	}
	if err := t.writeFrame(frame); err != nil {
		return err
	}
	if err := t.drainPending(); err != nil {
		return err
	}
	if err := t.sendAck(); err != nil {
		return err
	}
	return t.completeIfDone()
}

func (t *receiveFrameTransfer) writeFrame(frame webproto.Frame) error {
	if err := t.sink.WriteChunk(t.ctx, frame.Payload); err != nil {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, err.Error())
	}
	t.received += int64(len(frame.Payload))
	t.expectedSeq++
	t.cb.progress(Progress{Bytes: t.received, Total: t.meta.Size})
	return nil
}

func (t *receiveFrameTransfer) drainPending() error {
	for {
		payload, ok := t.pendingFrames[t.expectedSeq]
		if !ok {
			return nil
		}
		delete(t.pendingFrames, t.expectedSeq)
		t.pendingBytes -= int64(len(payload))
		frame := webproto.Frame{Kind: webproto.FrameData, Seq: t.expectedSeq, Payload: payload}
		if err := t.writeFrame(frame); err != nil {
			return err
		}
	}
}

func (t *receiveFrameTransfer) bufferPendingFrame(frame webproto.Frame) error {
	if _, ok := t.pendingFrames[frame.Seq]; ok {
		return nil
	}
	if !t.canBufferPendingFrame(frame) {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, "too many out-of-order data frames")
	}
	t.pendingFrames[frame.Seq] = append([]byte(nil), frame.Payload...)
	t.pendingBytes += int64(len(frame.Payload))
	if len(t.pendingFrames) == 1 || len(t.pendingFrames)%64 == 0 {
		t.cb.trace(fmt.Sprintf("receive-buffered seq=%d expected=%d pending=%d", frame.Seq, t.expectedSeq, len(t.pendingFrames)))
	}
	return nil
}

func (t *receiveFrameTransfer) canBufferPendingFrame(frame webproto.Frame) bool {
	limitFrames := maxPendingFrames
	limitBytes := maxPendingBytes
	if t.directActive {
		limitFrames = maxDirectPendingFrames
		limitBytes = maxDirectPendingBytes
	}
	return len(t.pendingFrames) < limitFrames && t.pendingBytes+int64(len(frame.Payload)) <= limitBytes
}

func (t *receiveFrameTransfer) sendBestEffortAck() error {
	if t.directActive && t.direct != nil {
		_ = sendDirectAck(t.ctx, t.direct, t.received)
		return nil
	}
	_ = sendAck(t.ctx, t.client, t.peerDERP, t.received)
	return nil
}

func (t *receiveFrameTransfer) sendAck() error {
	if t.directActive && t.direct != nil {
		return sendDirectAck(t.ctx, t.direct, t.received)
	}
	return sendAck(t.ctx, t.client, t.peerDERP, t.received)
}

func (t *receiveFrameTransfer) completeIfDone() error {
	if !t.doneSeen || t.doneSeq > t.expectedSeq {
		return nil
	}
	if t.meta.Size >= 0 && t.received != t.meta.Size {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, "received byte count does not match metadata")
	}
	if err := sendAck(t.ctx, t.client, t.peerDERP, t.received); err != nil {
		return err
	}
	if t.opened {
		if err := t.sink.Close(t.ctx); err != nil {
			return err
		}
	}
	t.cb.progress(Progress{Bytes: t.received, Total: t.meta.Size})
	t.cb.status(statusComplete)
	return errReceiveComplete
}

func (t *receiveFrameTransfer) handleDirectReady(frame webproto.Frame) error {
	var ready webproto.DirectReady
	if err := json.Unmarshal(frame.Payload, &ready); err != nil {
		return abortAndReturn(t.ctx, t.client, t.peerDERP, "invalid direct ready")
	}
	t.cb.trace(fmt.Sprintf("receive-direct-ready bytes=%d next_seq=%d received=%d expected=%d", ready.BytesReceived, ready.NextSeq, t.received, t.expectedSeq))
	if ready.BytesReceived > t.received || ready.NextSeq > t.expectedSeq {
		return nil
	}
	payload, err := json.Marshal(webproto.PathSwitch{
		Path:          "webrtc",
		BytesReceived: ready.BytesReceived,
		NextSeq:       ready.NextSeq,
	})
	if err != nil {
		return err
	}
	if err := sendFrame(t.ctx, t.client, t.peerDERP, webproto.FramePathSwitch, ready.NextSeq, payload); err != nil {
		return err
	}
	t.directActive = true
	t.cb.trace(fmt.Sprintf("receive-path-switch bytes=%d next_seq=%d received=%d expected=%d", ready.BytesReceived, ready.NextSeq, t.received, t.expectedSeq))
	t.cb.status(statusDirect)
	return nil
}

func (t *receiveFrameTransfer) handleDone(frame webproto.Frame) error {
	t.doneSeen = true
	t.doneSeq = frame.Seq
	if err := t.completeIfDone(); err != nil {
		return err
	}
	if !t.directActive {
		_ = sendAck(t.ctx, t.client, t.peerDERP, t.received)
	}
	return nil
}

func (o *Offer) waitClaim(ctx context.Context, cb Callbacks) (key.NodePublic, error) {
	claimCh, unsubscribe := o.client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	for {
		frame, ok, err := nextClaimFrame(ctx, claimCh, cb)
		if err != nil {
			return key.NodePublic{}, err
		}
		if !ok {
			continue
		}
		peerDERP, accepted, err := o.acceptClaimFrame(ctx, frame, cb)
		if err != nil {
			return key.NodePublic{}, err
		}
		if accepted {
			return peerDERP, nil
		}
	}
}

func nextClaimFrame(ctx context.Context, claimCh <-chan derpbind.Packet, cb Callbacks) (webproto.Frame, bool, error) {
	pkt, err := nextPacket(ctx, claimCh)
	if err != nil {
		return webproto.Frame{}, false, err
	}
	frame, err := webproto.Parse(pkt.Payload)
	if err != nil {
		return webproto.Frame{}, false, nil
	}
	if frame.Kind != webproto.FrameClaim {
		cb.trace("offer-frame-ignored=" + frameKindName(frame.Kind))
		return webproto.Frame{}, false, nil
	}
	return frame, true, nil
}

func (o *Offer) acceptClaimFrame(ctx context.Context, frame webproto.Frame, cb Callbacks) (key.NodePublic, bool, error) {
	cb.trace("offer-claim-received")
	var claim rendezvous.Claim
	if err := json.Unmarshal(frame.Payload, &claim); err != nil {
		cb.trace("offer-claim-malformed")
		return key.NodePublic{}, false, nil
	}
	decision, _ := o.gate.Accept(time.Now(), claim)
	peerDERP := keyNodePublicFromRaw32(claim.DERPPublic)
	cb.trace("offer-claim-peer=" + peerDERP.ShortString())
	if err := o.sendDecision(ctx, peerDERP, decision); err != nil {
		return key.NodePublic{}, false, err
	}
	traceOfferDecision(cb, decision)
	return peerDERP, decision.Accepted, nil
}

func (o *Offer) sendDecision(ctx context.Context, peerDERP key.NodePublic, decision rendezvous.Decision) error {
	payload, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	return sendFrame(ctx, o.client, peerDERP, webproto.FrameDecision, 0, payload)
}

func traceOfferDecision(cb Callbacks, decision rendezvous.Decision) {
	if decision.Accepted {
		cb.trace("offer-decision=accepted")
		return
	}
	cb.trace("offer-decision=rejected")
}

func pollSendDirectState(cb Callbacks, direct *directState, transport DirectTransport) (DirectTransport, error) {
	if direct == nil || transport == nil {
		return transport, nil
	}
	if direct.active {
		return pollActiveDirectFailure(cb, direct, transport)
	}
	if direct.ready {
		return pollReadyDirectFailure(direct, transport)
	}
	return pollDirectReadiness(direct, transport)
}

func pollActiveDirectFailure(cb Callbacks, direct *directState, transport DirectTransport) (DirectTransport, error) {
	select {
	case err := <-transport.Failed():
		err = directFailureErr(err)
		direct.noteFailure(err)
		cb.status(statusRelay)
		return nil, err
	default:
		return transport, nil
	}
}

func pollReadyDirectFailure(direct *directState, transport DirectTransport) (DirectTransport, error) {
	select {
	case err := <-transport.Failed():
		direct.noteFailureBeforeSwitch(err)
		return nil, nil
	default:
		return transport, nil
	}
}

func pollDirectReadiness(direct *directState, transport DirectTransport) (DirectTransport, error) {
	select {
	case <-transport.Ready():
		direct.noteReady()
	case err := <-transport.Failed():
		direct.noteFailureBeforeSwitch(err)
		return nil, nil
	default:
	}
	return transport, nil
}

func directFailureErr(err error) error {
	if err != nil {
		return err
	}
	return errors.New("direct path failed")
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

func trySwitchDirectWithReplay(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, direct DirectTransport, nextSeq uint64, window *relayWindow, cb Callbacks) (bool, error) {
	if direct == nil || window == nil {
		return false, nil
	}
	return newDirectSwitchAttempt(ctx, client, peerDERP, frames, direct, nextSeq, window, cb).run()
}

type directSwitchAttempt struct {
	ctx      context.Context
	client   derpClient
	peerDERP key.NodePublic
	frames   <-chan derpbind.Packet
	direct   DirectTransport
	nextSeq  uint64
	window   *relayWindow
	cb       Callbacks
	timer    *time.Timer
}

func newDirectSwitchAttempt(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, direct DirectTransport, nextSeq uint64, window *relayWindow, cb Callbacks) *directSwitchAttempt {
	return &directSwitchAttempt{
		ctx:      ctx,
		client:   client,
		peerDERP: peerDERP,
		frames:   frames,
		direct:   direct,
		nextSeq:  nextSeq,
		window:   window,
		cb:       cb,
		timer:    time.NewTimer(frameRetryDelay),
	}
}

func (a *directSwitchAttempt) run() (bool, error) {
	defer a.timer.Stop()
	if err := a.sendReady(); err != nil {
		return false, err
	}
	for {
		switched, err := a.step()
		if err != nil || switched {
			return switched, err
		}
	}
}

func (a *directSwitchAttempt) step() (bool, error) {
	select {
	case pkt, ok := <-a.frames:
		if !ok {
			return false, io.ErrClosedPipe
		}
		return a.handlePacket(pkt)
	case <-a.timer.C:
		return false, a.sendReady()
	case err := <-a.direct.Failed():
		return false, directFailureErr(err)
	case <-a.ctx.Done():
		return false, a.ctx.Err()
	}
}

func (a *directSwitchAttempt) sendReady() error {
	switchOffset := a.window.ackedOffset()
	replay := a.window.replayFrom(switchOffset)
	switchSeq := a.nextSeq
	if len(replay) > 0 {
		switchSeq = replay[0].Seq
	}
	a.cb.trace(fmt.Sprintf("send-direct-ready bytes=%d next_seq=%d replay_frames=%d", switchOffset, switchSeq, len(replay)))
	ready, err := marshalDirectReadyFrame(switchSeq, switchOffset)
	if err != nil {
		return err
	}
	if err := sendFrame(a.ctx, a.client, a.peerDERP, ready.Kind, ready.Seq, ready.Payload); err != nil {
		return err
	}
	resetTimer(a.timer, frameRetryDelay)
	return nil
}

func (a *directSwitchAttempt) handlePacket(pkt derpbind.Packet) (bool, error) {
	frame, err := webproto.Parse(pkt.Payload)
	if err != nil {
		return false, nil
	}
	switch frame.Kind {
	case webproto.FramePathSwitch:
		return a.handlePathSwitch(frame)
	case webproto.FrameAbort:
		return false, decodeAbort(frame.Payload)
	case webproto.FrameAck:
		a.noteRelayAck(frame)
	}
	return false, nil
}

func (a *directSwitchAttempt) handlePathSwitch(frame webproto.Frame) (bool, error) {
	var sw webproto.PathSwitch
	if err := json.Unmarshal(frame.Payload, &sw); err != nil {
		return false, nil
	}
	if sw.Path != "webrtc" || sw.NextSeq > a.nextSeq {
		return false, nil
	}
	return a.replayPathSwitch(sw)
}

func (a *directSwitchAttempt) replayPathSwitch(sw webproto.PathSwitch) (bool, error) {
	replayOffset := sw.BytesReceived
	if acked := a.window.ackedOffset(); acked > replayOffset {
		replayOffset = acked
	}
	replay := a.window.replayFrom(replayOffset)
	a.cb.trace(fmt.Sprintf("send-path-switch bytes=%d next_seq=%d replay_frames=%d", sw.BytesReceived, sw.NextSeq, len(replay)))
	for _, replayFrame := range replay {
		if err := sendDirectFrame(a.ctx, a.direct, webproto.FrameData, replayFrame.Seq, replayFrame.Payload); err != nil {
			return false, err
		}
		a.window.ack(replayFrame.NextOffset)
	}
	a.cb.trace(fmt.Sprintf("send-direct-replay-complete frames=%d", len(replay)))
	return true, nil
}

func (a *directSwitchAttempt) noteRelayAck(frame webproto.Frame) {
	ack, err := decodeAck(frame.Payload)
	if err == nil {
		a.window.ack(ack.BytesReceived)
	}
}

func sendClaimUntilDecision(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, claim rendezvous.Claim, cb Callbacks) error {
	payload, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	attempt := 0
	send := func() error {
		attempt++
		cb.trace("claim-send-attempt=" + strconv.Itoa(attempt))
		return sendFrame(ctx, client, peerDERP, webproto.FrameClaim, 0, payload)
	}
	if err := send(); err != nil {
		return err
	}
	retry := time.NewTicker(claimRetryDelay)
	defer retry.Stop()
	for {
		done, err := claimDecisionStep(ctx, frames, retry.C, send, cb)
		if err != nil || done {
			return err
		}
	}
}

func claimDecisionStep(ctx context.Context, frames <-chan derpbind.Packet, retry <-chan time.Time, send func() error, cb Callbacks) (bool, error) {
	select {
	case pkt, ok := <-frames:
		if !ok {
			return false, io.ErrClosedPipe
		}
		return handleClaimDecisionPacket(pkt, cb)
	case <-retry:
		return false, send()
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func handleClaimDecisionPacket(pkt derpbind.Packet, cb Callbacks) (bool, error) {
	frame, err := webproto.Parse(pkt.Payload)
	if err != nil {
		return false, nil
	}
	if frame.Kind != webproto.FrameDecision {
		cb.trace("claim-frame-ignored=" + frameKindName(frame.Kind))
		return false, nil
	}
	cb.trace("claim-frame-received=decision")
	decision, ok := decodeClaimDecision(frame, cb)
	if !ok {
		return false, nil
	}
	return resolveClaimDecision(decision, cb)
}

func decodeClaimDecision(frame webproto.Frame, cb Callbacks) (rendezvous.Decision, bool) {
	var decision rendezvous.Decision
	if err := json.Unmarshal(frame.Payload, &decision); err != nil {
		cb.trace("claim-decision-malformed")
		return rendezvous.Decision{}, false
	}
	return decision, true
}

func resolveClaimDecision(decision rendezvous.Decision, cb Callbacks) (bool, error) {
	if decision.Accepted {
		cb.trace("claim-decision=accepted")
		return true, nil
	}
	cb.trace("claim-decision=rejected")
	if decision.Reject != nil && decision.Reject.Reason != "" {
		return false, errors.New(decision.Reject.Reason)
	}
	return false, errors.New("claim rejected")
}

var errAckTimeout = errors.New("timed out waiting for receiver ack")
var errReceiveComplete = errors.New("receive complete")

func sendDirectFrame(ctx context.Context, direct DirectTransport, kind webproto.FrameKind, seq uint64, payload []byte) error {
	raw, err := webproto.Marshal(kind, seq, payload)
	if err != nil {
		return err
	}
	return direct.SendFrame(ctx, raw)
}

func sendRelayDataFrame(ctx context.Context, client derpClient, peerDERP key.NodePublic, frame relayFrame) error {
	return sendFrame(ctx, client, peerDERP, webproto.FrameData, frame.Seq, frame.Payload)
}

func awaitAck(ctx context.Context, frames <-chan derpbind.Packet, wantBytes int64, timeout time.Duration) error {
	return awaitAckOrDirectFailure(ctx, frames, wantBytes, timeout, nil)
}

func awaitRelayWindowAck(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, window *relayWindow) error {
	waiter := newRelayAckWaiter(ctx, client, peerDERP, frames, window)
	return waiter.run()
}

type relayAckWaiter struct {
	ctx               context.Context
	client            derpClient
	peerDERP          key.NodePublic
	frames            <-chan derpbind.Packet
	window            *relayWindow
	timer             *time.Timer
	lastRetransmitAck int64
}

func newRelayAckWaiter(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, window *relayWindow) *relayAckWaiter {
	return &relayAckWaiter{
		ctx:               ctx,
		client:            client,
		peerDERP:          peerDERP,
		frames:            frames,
		window:            window,
		timer:             time.NewTimer(frameRetryDelay),
		lastRetransmitAck: -1,
	}
}

func (w *relayAckWaiter) run() error {
	defer w.timer.Stop()
	for {
		if w.window.empty() {
			return nil
		}
		done, err := w.step()
		if err != nil || done {
			return err
		}
	}
}

func (w *relayAckWaiter) step() (bool, error) {
	select {
	case pkt, ok := <-w.frames:
		if !ok {
			return false, io.ErrClosedPipe
		}
		return w.handlePacket(pkt)
	case <-w.timer.C:
		return false, w.handleTimer()
	case <-w.ctx.Done():
		return false, w.ctx.Err()
	}
}

func (w *relayAckWaiter) handleTimer() error {
	if err := w.retransmitOldest(); err != nil {
		return err
	}
	if !w.window.empty() {
		w.lastRetransmitAck = w.window.ackedOffset()
		w.timer.Reset(frameRetryDelay)
	}
	return nil
}

func (w *relayAckWaiter) handlePacket(pkt derpbind.Packet) (bool, error) {
	frame, err := webproto.Parse(pkt.Payload)
	if err != nil {
		return false, nil
	}
	switch frame.Kind {
	case webproto.FrameAck:
		return w.handleAck(frame)
	case webproto.FrameAbort:
		return false, decodeAbort(frame.Payload)
	default:
		return false, nil
	}
}

func (w *relayAckWaiter) handleAck(frame webproto.Frame) (bool, error) {
	ack, err := decodeAck(frame.Payload)
	if err != nil {
		return false, nil
	}
	before := w.window.ackedOffset()
	w.window.ack(ack.BytesReceived)
	after := w.window.ackedOffset()
	if after > before || w.window.empty() {
		return true, nil
	}
	if w.lastRetransmitAck == after {
		return false, nil
	}
	if err := w.retransmitOldest(); err != nil {
		return false, err
	}
	w.lastRetransmitAck = after
	resetTimer(w.timer, frameRetryDelay)
	return false, nil
}

func (w *relayAckWaiter) retransmitOldest() error {
	frame, ok := w.window.firstUnacked()
	if !ok {
		return nil
	}
	return sendRelayDataFrame(w.ctx, w.client, w.peerDERP, frame)
}

func drainDirectWindowAcks(ctx context.Context, relayFrames <-chan derpbind.Packet, direct DirectTransport, window *relayWindow, cb Callbacks, total int64) error {
	if direct == nil || window == nil {
		return nil
	}
	sources := newDirectWindowSources(relayFrames, direct)
	for {
		raw, ok, err := sources.next(ctx, false)
		if err != nil || !ok {
			return err
		}
		if err := handleDirectWindowFrame(raw, window, cb, total); err != nil {
			return err
		}
	}
}

func awaitDirectWindowAck(ctx context.Context, relayFrames <-chan derpbind.Packet, direct DirectTransport, window *relayWindow, cb Callbacks, total int64) error {
	if direct == nil || window == nil {
		return nil
	}
	sources := newDirectWindowSources(relayFrames, direct)
	for {
		if window.empty() {
			return nil
		}
		before := window.ackedOffset()
		raw, _, err := sources.next(ctx, true)
		if err != nil {
			return err
		}
		if err := handleDirectWindowFrame(raw, window, cb, total); err != nil {
			return err
		}
		if window.ackedOffset() > before || window.empty() {
			return nil
		}
	}
}

type directWindowSources struct {
	relayFrames  <-chan derpbind.Packet
	directFrames <-chan []byte
	directFailed <-chan error
}

func newDirectWindowSources(relayFrames <-chan derpbind.Packet, direct DirectTransport) directWindowSources {
	return directWindowSources{
		relayFrames:  relayFrames,
		directFrames: direct.ReceiveFrames(),
		directFailed: direct.Failed(),
	}
}

func (s directWindowSources) next(ctx context.Context, wait bool) ([]byte, bool, error) {
	if wait {
		return s.wait(ctx)
	}
	return s.poll(ctx)
}

func (s directWindowSources) poll(ctx context.Context) ([]byte, bool, error) {
	select {
	case raw, ok := <-s.directFrames:
		return raw, ok, closedPipeIfFalse(ok)
	case pkt, ok := <-s.relayFrames:
		return pkt.Payload, ok, closedPipeIfFalse(ok)
	case err := <-s.directFailed:
		return nil, false, directFailureErr(err)
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
		return nil, false, nil
	}
}

func (s directWindowSources) wait(ctx context.Context) ([]byte, bool, error) {
	select {
	case raw, ok := <-s.directFrames:
		return raw, ok, closedPipeIfFalse(ok)
	case pkt, ok := <-s.relayFrames:
		return pkt.Payload, ok, closedPipeIfFalse(ok)
	case err := <-s.directFailed:
		return nil, false, directFailureErr(err)
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

func closedPipeIfFalse(ok bool) error {
	if ok {
		return nil
	}
	return io.ErrClosedPipe
}

func handleDirectWindowFrame(raw []byte, window *relayWindow, cb Callbacks, total int64) error {
	frame, err := webproto.Parse(raw)
	if err != nil {
		return nil
	}
	switch frame.Kind {
	case webproto.FrameAck:
		ack, err := decodeAck(frame.Payload)
		if err != nil {
			return nil
		}
		before := window.ackedOffset()
		window.ack(ack.BytesReceived)
		after := window.ackedOffset()
		if after > before {
			cb.progress(Progress{Bytes: after, Total: total})
		}
	case webproto.FrameAbort:
		return decodeAbort(frame.Payload)
	}
	return nil
}

func awaitAckOrDirectFailure(ctx context.Context, frames <-chan derpbind.Packet, wantBytes int64, timeout time.Duration, directFailed <-chan error) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case pkt, ok := <-frames:
			if !ok {
				return io.ErrClosedPipe
			}
			done, err := ackPacketSatisfied(pkt, wantBytes)
			if err != nil || done {
				return err
			}
		case <-timer.C:
			return errAckTimeout
		case err := <-directFailed:
			return directFailureErr(err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func ackPacketSatisfied(pkt derpbind.Packet, wantBytes int64) (bool, error) {
	frame, err := webproto.Parse(pkt.Payload)
	if err != nil {
		return false, nil
	}
	switch frame.Kind {
	case webproto.FrameAck:
		return ackFrameSatisfied(frame, wantBytes)
	case webproto.FrameAbort:
		return false, decodeAbort(frame.Payload)
	default:
		return false, nil
	}
}

func ackFrameSatisfied(frame webproto.Frame, wantBytes int64) (bool, error) {
	ack, err := decodeAck(frame.Payload)
	if err != nil {
		return false, nil
	}
	return ack.BytesReceived >= wantBytes, nil
}

func sendFrameAwaitAck(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, kind webproto.FrameKind, seq uint64, payload []byte, wantBytes int64) error {
	for {
		if err := sendFrame(ctx, client, peerDERP, kind, seq, payload); err != nil {
			return err
		}
		if err := awaitAck(ctx, frames, wantBytes, frameRetryDelay); err != nil {
			if errors.Is(err, errAckTimeout) {
				continue
			}
			if err := abortIfContextDone(ctx, client, peerDERP); err != nil {
				return err
			}
			return err
		}
		return nil
	}
}

func sendFrame(ctx context.Context, client derpClient, peerDERP key.NodePublic, kind webproto.FrameKind, seq uint64, payload []byte) error {
	frame, err := webproto.Marshal(kind, seq, payload)
	if err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, frame)
}

func sendAck(ctx context.Context, client derpClient, peerDERP key.NodePublic, bytesReceived int64) error {
	payload, err := json.Marshal(webproto.Ack{BytesReceived: bytesReceived})
	if err != nil {
		return err
	}
	return sendFrame(ctx, client, peerDERP, webproto.FrameAck, 0, payload)
}

func sendDirectAck(ctx context.Context, direct DirectTransport, bytesReceived int64) error {
	payload, err := json.Marshal(webproto.Ack{BytesReceived: bytesReceived})
	if err != nil {
		return err
	}
	return sendDirectFrame(ctx, direct, webproto.FrameAck, 0, payload)
}

func decodeAck(payload []byte) (webproto.Ack, error) {
	var ack webproto.Ack
	err := json.Unmarshal(payload, &ack)
	return ack, err
}

func abortAndReturn(ctx context.Context, client derpClient, peerDERP key.NodePublic, reason string) error {
	_ = sendAbortBestEffort(ctx, client, peerDERP, reason)
	return errors.New(reason)
}

func notifyAbort(ctx context.Context, client derpClient, peerDERP key.NodePublic, err error) error {
	if err != nil {
		_ = sendAbortBestEffort(ctx, client, peerDERP, err.Error())
	}
	return err
}

func abortIfContextDone(ctx context.Context, client derpClient, peerDERP key.NodePublic) error {
	if err := ctx.Err(); err != nil {
		_ = sendAbortBestEffort(ctx, client, peerDERP, err.Error())
		return err
	}
	return nil
}

func sendAbortBestEffort(ctx context.Context, client derpClient, peerDERP key.NodePublic, reason string) error {
	if ctx.Err() == nil {
		return sendAbort(ctx, client, peerDERP, reason)
	}
	abortCtx, cancel := context.WithTimeout(context.Background(), claimRetryDelay)
	defer cancel()
	return sendAbort(abortCtx, client, peerDERP, reason)
}

func sendAbort(ctx context.Context, client derpClient, peerDERP key.NodePublic, reason string) error {
	payload, err := json.Marshal(webproto.Abort{Reason: reason})
	if err != nil {
		return err
	}
	return sendFrame(ctx, client, peerDERP, webproto.FrameAbort, 0, payload)
}

func decodeAbort(payload []byte) error {
	var abort webproto.Abort
	if err := json.Unmarshal(payload, &abort); err != nil {
		return err
	}
	if abort.Reason == "" {
		return errors.New("peer aborted")
	}
	return errors.New(abort.Reason)
}

func nextPacket(ctx context.Context, ch <-chan derpbind.Packet) (derpbind.Packet, error) {
	select {
	case pkt, ok := <-ch:
		if !ok {
			return derpbind.Packet{}, io.ErrClosedPipe
		}
		return pkt, nil
	case <-ctx.Done():
		return derpbind.Packet{}, ctx.Err()
	}
}

func nextRawFrame(ctx context.Context, ch <-chan []byte, direct DirectTransport, directActive bool) ([]byte, error) {
	var directFailed <-chan error
	if directActive && direct != nil {
		directFailed = direct.Failed()
	}
	select {
	case raw, ok := <-ch:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return raw, nil
	case err := <-directFailed:
		if err == nil {
			err = errors.New("direct path failed")
		}
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func mergeFrameSources(ctx context.Context, derpFrames <-chan derpbind.Packet, direct DirectTransport) (<-chan []byte, func()) {
	ctx, cancel := context.WithCancel(ctx)
	out := make(chan []byte, 32)
	go runFrameSourceMerge(ctx, out, derpFrames, direct)
	return out, cancel
}

func runFrameSourceMerge(ctx context.Context, out chan<- []byte, derpFrames <-chan derpbind.Packet, direct DirectTransport) {
	defer close(out)
	sources := mergedFrameSources{derp: derpFrames}
	if direct != nil {
		sources.direct = direct.ReceiveFrames()
	}
	for sources.active() {
		if !sources.forwardNext(ctx, out) {
			return
		}
	}
}

type mergedFrameSources struct {
	derp   <-chan derpbind.Packet
	direct <-chan []byte
}

func (s *mergedFrameSources) active() bool {
	return s.derp != nil || s.direct != nil
}

func (s *mergedFrameSources) forwardNext(ctx context.Context, out chan<- []byte) bool {
	select {
	case pkt, ok := <-s.derp:
		s.derp = keepIfOpen(s.derp, ok)
		return !ok || sendMergedFrame(ctx, out, pkt.Payload)
	case raw, ok := <-s.direct:
		s.direct = keepIfOpen(s.direct, ok)
		return !ok || sendMergedFrame(ctx, out, raw)
	case <-ctx.Done():
		return false
	}
}

func keepIfOpen[T any](ch <-chan T, ok bool) <-chan T {
	if ok {
		return ch
	}
	return nil
}

func sendMergedFrame(ctx context.Context, out chan<- []byte, raw []byte) bool {
	select {
	case out <- raw:
		return true
	case <-ctx.Done():
		return false
	}
}

func newToken(pub key.NodePublic, regionID int) (token.Token, error) {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return token.Token{}, err
	}
	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		return token.Token{}, err
	}
	var quicPublic [32]byte
	if _, err := rand.Read(quicPublic[:]); err != nil {
		return token.Token{}, err
	}
	return token.Token{
		Version:         token.SupportedVersion,
		SessionID:       sessionID,
		ExpiresUnix:     time.Now().Add(offerTokenTTL).Unix(),
		BootstrapRegion: uint16(regionID),
		DERPPublic:      derpPublicKeyRaw32(pub),
		QUICPublic:      quicPublic,
		BearerSecret:    bearerSecret,
		Capabilities:    token.CapabilityWebFile,
	}, nil
}

func newClaim(tok token.Token, pub key.NodePublic) (rendezvous.Claim, error) {
	var quicPublic [32]byte
	if _, err := rand.Read(quicPublic[:]); err != nil {
		return rendezvous.Claim{}, err
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(pub),
		QUICPublic:   quicPublic,
		Parallel:     defaultClaimPar,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	return claim, nil
}

func derpPublicKeyRaw32(pub key.NodePublic) [32]byte {
	var raw [32]byte
	copy(raw[:], pub.AppendTo(raw[:0]))
	return raw
}

func keyNodePublicFromRaw32(raw [32]byte) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(raw[:]))
}

func firstDERPNode(dm *tailcfg.DERPMap, regionID int) *tailcfg.DERPNode {
	if dm == nil {
		return nil
	}
	if node := derpNodeForRegion(dm, regionID); node != nil {
		return node
	}
	return firstDERPMapNode(dm)
}

func derpNodeForRegion(dm *tailcfg.DERPMap, regionID int) *tailcfg.DERPNode {
	if regionID == 0 {
		return nil
	}
	region := dm.Regions[regionID]
	if region == nil || len(region.Nodes) == 0 {
		return nil
	}
	return region.Nodes[0]
}

func firstDERPMapNode(dm *tailcfg.DERPMap) *tailcfg.DERPNode {
	for _, regionID := range dm.RegionIDs() {
		region := dm.Regions[regionID]
		if region != nil && len(region.Nodes) > 0 {
			return region.Nodes[0]
		}
	}
	return nil
}

func publicDERPMapURL() string {
	if override := os.Getenv("DERPHOLE_TEST_DERP_MAP_URL"); override != "" {
		return override
	}
	return derpbind.PublicDERPMapURL
}

func publicDERPServerURL(node *tailcfg.DERPNode) string {
	if override := os.Getenv("DERPHOLE_TEST_DERP_SERVER_URL"); override != "" {
		return override
	}
	if node == nil {
		return ""
	}
	host := node.HostName
	port := node.DERPPort
	if port != 0 && port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "https://" + host + "/derp"
}

func safeName(name string) string {
	if name == "" {
		return "derphole-download"
	}
	if len(name) > maxFilenameBytes {
		name = name[:maxFilenameBytes]
	}
	return name
}

func (cb Callbacks) status(status string) {
	if cb.Status != nil {
		cb.Status(status)
	}
}

func (cb Callbacks) progress(progress Progress) {
	if cb.Progress != nil {
		cb.Progress(progress)
	}
}

func (cb Callbacks) trace(trace string) {
	if cb.Trace != nil {
		cb.Trace(trace)
	}
}

var frameKindNames = map[webproto.FrameKind]string{
	webproto.FrameClaim:              "claim",
	webproto.FrameDecision:           "decision",
	webproto.FrameMeta:               "meta",
	webproto.FrameData:               "data",
	webproto.FrameDone:               "done",
	webproto.FrameAck:                "ack",
	webproto.FrameAbort:              "abort",
	webproto.FrameWebRTCOffer:        "webrtc-offer",
	webproto.FrameWebRTCAnswer:       "webrtc-answer",
	webproto.FrameWebRTCIceCandidate: "webrtc-candidate",
	webproto.FrameWebRTCIceComplete:  "webrtc-ice-complete",
	webproto.FrameDirectReady:        "direct-ready",
	webproto.FramePathSwitch:         "path-switch",
	webproto.FrameDirectFailed:       "direct-failed",
}

func frameKindName(kind webproto.FrameKind) string {
	if name, ok := frameKindNames[kind]; ok {
		return name
	}
	return "unknown"
}

func FormatError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
