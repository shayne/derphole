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

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/derphole/webproto"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/token"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	chunkBytes         = webproto.MaxPayloadBytes
	relayWindowBytes   = 8 << 20
	relayWindowFrames  = relayWindowBytes / chunkBytes
	claimRetryDelay    = 250 * time.Millisecond
	frameRetryDelay    = 2 * time.Second
	offerTokenTTL      = time.Hour
	defaultClaimPar    = 1
	maxFilenameBytes   = 255
	statusWaitingClaim = "waiting-for-claim"
	statusClaimed      = "claimed"
	statusProbing      = "probing-direct"
	statusRelay        = "connected-relay"
	statusDirect       = "connected-direct"
	statusComplete     = "complete"
)

type Progress struct {
	Bytes int64
	Total int64
}

type Callbacks struct {
	Status   func(string)
	Progress func(Progress)
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
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, "", err
	}
	node := firstDERPNode(dm, 0)
	if node == nil {
		return nil, "", errors.New("no DERP node available")
	}
	client, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return nil, "", err
	}

	tokValue, err := newToken(client.PublicKey(), node.RegionID)
	if err != nil {
		_ = client.Close()
		return nil, "", err
	}
	encoded, err := token.Encode(tokValue)
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
	if o == nil || o.client == nil {
		return errors.New("nil offer")
	}
	if src == nil {
		return errors.New("nil source")
	}
	cb.status(statusWaitingClaim)
	peerDERP, err := o.waitClaim(ctx)
	if err != nil {
		return err
	}
	cb.status(statusClaimed)
	cb.status(statusRelay)

	peerCh, unsubscribe := o.client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	directTransport := opts.Direct
	var direct *directState
	var signalPeer *derpSignalPeer
	if directTransport != nil {
		direct = &directState{}
		signalPeer = newDERPSignalPeer(ctx, o.client, peerDERP)
		defer signalPeer.close()
		defer directTransport.Close()
		if err := directTransport.Start(ctx, DirectRoleSender, signalPeer); err != nil {
			direct.noteFailureBeforeSwitch(err)
			directTransport = nil
		} else {
			cb.status(statusProbing)
		}
	}

	cb.status(statusRelay)
	meta := webproto.Meta{Name: safeName(src.Name()), Size: src.Size()}
	metaPayload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameMeta, 0, metaPayload, 0); err != nil {
		return err
	}

	offset, seq, directTransport, direct, err := o.sendDataWindowed(ctx, src, cb, peerDERP, peerCh, meta.Size, directTransport, direct)
	if err != nil {
		return err
	}

	path := chooseSendPath(TransferOptions{Direct: directTransport}, direct != nil && direct.active)
	if path == sendPathDirect {
		if err := sendDirectFrame(ctx, directTransport, webproto.FrameDone, seq, nil); err == nil {
			if err := awaitAckOrDirectFailure(ctx, peerCh, offset, 5*time.Minute, directTransport.Failed()); err != nil {
				return notifyAbort(ctx, o.client, peerDERP, err)
			}
		} else {
			if direct != nil && direct.active {
				return notifyAbort(ctx, o.client, peerDERP, err)
			}
			if direct != nil {
				direct.noteFailure(err)
				directTransport = nil
			}
			cb.status(statusRelay)
			if err := sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameDone, seq, nil, offset); err != nil {
				return err
			}
		}
	} else if err := sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameDone, seq, nil, offset); err != nil {
		return err
	}

	cb.progress(Progress{Bytes: offset, Total: meta.Size})
	cb.status(statusComplete)
	return nil
}

func (o *Offer) sendDataWindowed(ctx context.Context, src FileSource, cb Callbacks, peerDERP key.NodePublic, peerCh <-chan derpbind.Packet, total int64, directTransport DirectTransport, direct *directState) (int64, uint64, DirectTransport, *directState, error) {
	window := newRelayWindow(relayWindowConfig{MaxBytes: relayWindowBytes, MaxFrames: relayWindowFrames})
	var offset int64
	var seq uint64 = 1
	var eof bool

	for {
		var directErr error
		directTransport, directErr = pollSendDirectState(cb, direct, directTransport)
		if directErr != nil {
			return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, directErr)
		}

		for !eof && window.canSend(chunkBytes) {
			if direct != nil && direct.ready && !direct.active && !window.empty() {
				break
			}

			chunk, err := src.ReadChunk(ctx, offset, chunkBytes)
			if err != nil {
				if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
					return offset, seq, directTransport, direct, err
				}
				return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, err)
			}
			if len(chunk) == 0 {
				eof = true
				break
			}

			nextOffset := offset + int64(len(chunk))
			frame := relayFrame{Seq: seq, Offset: offset, NextOffset: nextOffset, Payload: chunk}
			window.push(frame)
			if direct != nil && direct.active && directTransport != nil {
				if err := sendDirectFrame(ctx, directTransport, webproto.FrameData, seq, chunk); err != nil {
					if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
						return offset, seq, directTransport, direct, err
					}
					return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, err)
				}
				window.ack(nextOffset)
			} else if err := sendRelayDataFrame(ctx, o.client, peerDERP, frame); err != nil {
				if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
					return offset, seq, directTransport, direct, err
				}
				return offset, seq, directTransport, direct, err
			} else {
				window.markSent(seq)
			}

			offset = nextOffset
			cb.progress(Progress{Bytes: offset, Total: total})
			seq++

			if direct != nil && direct.ready && !direct.active {
				break
			}
		}

		directTransport, directErr = pollSendDirectState(cb, direct, directTransport)
		if directErr != nil {
			return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, directErr)
		}

		if direct != nil && direct.ready && !direct.active && !window.empty() {
			if err := awaitRelayWindowAck(ctx, peerCh, window); err != nil {
				if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
					return offset, seq, directTransport, direct, err
				}
				return offset, seq, directTransport, direct, err
			}
			directTransport, directErr = pollSendDirectState(cb, direct, directTransport)
			if directErr != nil {
				return offset, seq, directTransport, direct, notifyAbort(ctx, o.client, peerDERP, directErr)
			}
		}

		if direct != nil && directTransport != nil && direct.ready && !direct.active && offset > 0 {
			switched, err := trySwitchDirectWithReplay(ctx, o.client, peerDERP, peerCh, directTransport, seq, window)
			if err != nil {
				if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
					return offset, seq, directTransport, direct, err
				}
				return offset, seq, directTransport, direct, err
			}
			if switched {
				direct.noteSwitched()
				cb.status(statusDirect)
			}
		}

		if eof && window.empty() {
			return offset, seq, directTransport, direct, nil
		}

		if window.empty() {
			continue
		}

		if err := awaitRelayWindowAck(ctx, peerCh, window); err != nil {
			if err := abortIfContextDone(ctx, o.client, peerDERP); err != nil {
				return offset, seq, directTransport, direct, err
			}
			return offset, seq, directTransport, direct, err
		}
	}
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
	tok, err := token.Decode(encodedToken, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities != token.CapabilityWebFile {
		return errors.New("token is not a derphole web file offer")
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	client, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	defer client.Close()

	peerDERP := keyNodePublicFromRaw32(tok.DERPPublic)
	frames, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	claim, err := newClaim(tok, client.PublicKey())
	if err != nil {
		return err
	}
	if err := sendClaimUntilDecision(ctx, client, peerDERP, frames, claim); err != nil {
		return err
	}

	directTransport := opts.Direct
	var signalPeer *derpSignalPeer
	if directTransport != nil {
		signalPeer = newDERPSignalPeer(ctx, client, peerDERP)
		defer signalPeer.close()
		defer directTransport.Close()
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
	var meta webproto.Meta
	var expectedSeq uint64 = 1
	var received int64
	var opened bool
	var directActive bool

	for {
		raw, err := nextRawFrame(ctx, frames, direct, directActive)
		if err != nil {
			if err := abortIfContextDone(ctx, client, peerDERP); err != nil {
				return err
			}
			if directActive {
				_ = sendAbortBestEffort(ctx, client, peerDERP, err.Error())
			}
			return err
		}
		frame, err := webproto.Parse(raw)
		if err != nil {
			continue
		}
		switch frame.Kind {
		case webproto.FrameMeta:
			if opened {
				_ = sendAck(ctx, client, peerDERP, received)
				continue
			}
			if err := json.Unmarshal(frame.Payload, &meta); err != nil {
				return abortAndReturn(ctx, client, peerDERP, "invalid metadata")
			}
			if err := sink.Open(ctx, meta); err != nil {
				return abortAndReturn(ctx, client, peerDERP, err.Error())
			}
			opened = true
			cb.progress(Progress{Bytes: 0, Total: meta.Size})
			if err := sendAck(ctx, client, peerDERP, 0); err != nil {
				return err
			}
		case webproto.FrameData:
			if !opened {
				return abortAndReturn(ctx, client, peerDERP, "data before metadata")
			}
			if frame.Seq < expectedSeq {
				_ = sendAck(ctx, client, peerDERP, received)
				continue
			}
			if frame.Seq > expectedSeq {
				return abortAndReturn(ctx, client, peerDERP, "missing data frame")
			}
			if err := sink.WriteChunk(ctx, frame.Payload); err != nil {
				return abortAndReturn(ctx, client, peerDERP, err.Error())
			}
			received += int64(len(frame.Payload))
			expectedSeq++
			cb.progress(Progress{Bytes: received, Total: meta.Size})
			if err := sendAck(ctx, client, peerDERP, received); err != nil {
				return err
			}
		case webproto.FrameDirectReady:
			var ready webproto.DirectReady
			if err := json.Unmarshal(frame.Payload, &ready); err != nil {
				return abortAndReturn(ctx, client, peerDERP, "invalid direct ready")
			}
			if ready.BytesReceived == received && ready.NextSeq == expectedSeq {
				payload, err := json.Marshal(webproto.PathSwitch{
					Path:          "webrtc",
					BytesReceived: received,
					NextSeq:       expectedSeq,
				})
				if err != nil {
					return err
				}
				if err := sendFrame(ctx, client, peerDERP, webproto.FramePathSwitch, expectedSeq, payload); err != nil {
					return err
				}
				directActive = true
				cb.status(statusDirect)
			}
		case webproto.FrameDone:
			if meta.Size >= 0 && received != meta.Size {
				return abortAndReturn(ctx, client, peerDERP, "received byte count does not match metadata")
			}
			if err := sendAck(ctx, client, peerDERP, received); err != nil {
				return err
			}
			if opened {
				if err := sink.Close(ctx); err != nil {
					return err
				}
			}
			cb.progress(Progress{Bytes: received, Total: meta.Size})
			cb.status(statusComplete)
			return nil
		case webproto.FrameAbort:
			return decodeAbort(frame.Payload)
		}
	}
}

func (o *Offer) waitClaim(ctx context.Context) (key.NodePublic, error) {
	claimCh, unsubscribe := o.client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return webproto.IsWebFrame(pkt.Payload)
	})
	defer unsubscribe()

	for {
		pkt, err := nextPacket(ctx, claimCh)
		if err != nil {
			return key.NodePublic{}, err
		}
		frame, err := webproto.Parse(pkt.Payload)
		if err != nil || frame.Kind != webproto.FrameClaim {
			continue
		}
		var claim rendezvous.Claim
		if err := json.Unmarshal(frame.Payload, &claim); err != nil {
			continue
		}
		decision, _ := o.gate.Accept(time.Now(), claim)
		peerDERP := keyNodePublicFromRaw32(claim.DERPPublic)
		payload, err := json.Marshal(decision)
		if err != nil {
			return key.NodePublic{}, err
		}
		if err := sendFrame(ctx, o.client, peerDERP, webproto.FrameDecision, 0, payload); err != nil {
			return key.NodePublic{}, err
		}
		if !decision.Accepted {
			continue
		}
		return peerDERP, nil
	}
}

func pollSendDirectState(cb Callbacks, direct *directState, transport DirectTransport) (DirectTransport, error) {
	if direct == nil || transport == nil {
		return transport, nil
	}
	if direct.active {
		select {
		case err := <-transport.Failed():
			if err == nil {
				err = errors.New("direct path failed")
			}
			direct.noteFailure(err)
			cb.status(statusRelay)
			return nil, err
		default:
			return transport, nil
		}
	}
	if direct.ready {
		select {
		case err := <-transport.Failed():
			direct.noteFailureBeforeSwitch(err)
			return nil, nil
		default:
			return transport, nil
		}
	}
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

func trySwitchDirectWithReplay(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, direct DirectTransport, nextSeq uint64, window *relayWindow) (bool, error) {
	if direct == nil || window == nil {
		return false, nil
	}
	switchOffset := window.ackedOffset()
	replay := window.replayFrom(switchOffset)
	switchSeq := nextSeq
	if len(replay) > 0 {
		switchSeq = replay[0].Seq
	}
	ready, err := marshalDirectReadyFrame(switchSeq, switchOffset)
	if err != nil {
		return false, err
	}
	if err := sendFrame(ctx, client, peerDERP, ready.Kind, ready.Seq, ready.Payload); err != nil {
		return false, err
	}
	timer := time.NewTimer(frameRetryDelay)
	defer timer.Stop()
	for {
		select {
		case pkt, ok := <-frames:
			if !ok {
				return false, io.ErrClosedPipe
			}
			frame, err := webproto.Parse(pkt.Payload)
			if err != nil {
				continue
			}
			switch frame.Kind {
			case webproto.FramePathSwitch:
				var sw webproto.PathSwitch
				if err := json.Unmarshal(frame.Payload, &sw); err != nil {
					continue
				}
				if sw.Path != "webrtc" || sw.BytesReceived != switchOffset || sw.NextSeq != switchSeq {
					return false, nil
				}
				for _, replayFrame := range replay {
					if err := sendDirectFrame(ctx, direct, webproto.FrameData, replayFrame.Seq, replayFrame.Payload); err != nil {
						return false, err
					}
					window.ack(replayFrame.NextOffset)
				}
				return true, nil
			case webproto.FrameAbort:
				return false, decodeAbort(frame.Payload)
			case webproto.FrameAck:
				ack, err := decodeAck(frame.Payload)
				if err == nil {
					window.ack(ack.BytesReceived)
				}
			}
		case <-timer.C:
			return false, nil
		case err := <-direct.Failed():
			if err == nil {
				err = errors.New("direct path failed")
			}
			return false, err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

func sendClaimUntilDecision(ctx context.Context, client derpClient, peerDERP key.NodePublic, frames <-chan derpbind.Packet, claim rendezvous.Claim) error {
	payload, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	send := func() error {
		return sendFrame(ctx, client, peerDERP, webproto.FrameClaim, 0, payload)
	}
	if err := send(); err != nil {
		return err
	}
	retry := time.NewTicker(claimRetryDelay)
	defer retry.Stop()
	for {
		select {
		case pkt, ok := <-frames:
			if !ok {
				return io.ErrClosedPipe
			}
			frame, err := webproto.Parse(pkt.Payload)
			if err != nil || frame.Kind != webproto.FrameDecision {
				continue
			}
			var decision rendezvous.Decision
			if err := json.Unmarshal(frame.Payload, &decision); err != nil {
				continue
			}
			if !decision.Accepted {
				if decision.Reject != nil && decision.Reject.Reason != "" {
					return errors.New(decision.Reject.Reason)
				}
				return errors.New("claim rejected")
			}
			return nil
		case <-retry.C:
			if err := send(); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

var errAckTimeout = errors.New("timed out waiting for receiver ack")

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

func awaitRelayWindowAck(ctx context.Context, frames <-chan derpbind.Packet, window *relayWindow) error {
	for {
		select {
		case pkt, ok := <-frames:
			if !ok {
				return io.ErrClosedPipe
			}
			frame, err := webproto.Parse(pkt.Payload)
			if err != nil {
				continue
			}
			switch frame.Kind {
			case webproto.FrameAck:
				ack, err := decodeAck(frame.Payload)
				if err != nil {
					continue
				}
				window.ack(ack.BytesReceived)
				return nil
			case webproto.FrameAbort:
				return decodeAbort(frame.Payload)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
			frame, err := webproto.Parse(pkt.Payload)
			if err != nil {
				continue
			}
			switch frame.Kind {
			case webproto.FrameAck:
				ack, err := decodeAck(frame.Payload)
				if err != nil {
					continue
				}
				if ack.BytesReceived >= wantBytes {
					return nil
				}
			case webproto.FrameAbort:
				return decodeAbort(frame.Payload)
			}
		case <-timer.C:
			return errAckTimeout
		case err := <-directFailed:
			if err == nil {
				err = errors.New("direct path failed")
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
	go func() {
		defer close(out)
		var directFrames <-chan []byte
		if direct != nil {
			directFrames = direct.ReceiveFrames()
		}
		for derpFrames != nil || directFrames != nil {
			select {
			case pkt, ok := <-derpFrames:
				if !ok {
					derpFrames = nil
					continue
				}
				select {
				case out <- pkt.Payload:
				case <-ctx.Done():
					return
				}
			case raw, ok := <-directFrames:
				if !ok {
					directFrames = nil
					continue
				}
				select {
				case out <- raw:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, cancel
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
		Candidates:   []string{"websocket-derp"},
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
	if dm == nil || len(dm.Regions) == 0 {
		return nil
	}
	if regionID != 0 {
		if region := dm.Regions[regionID]; region != nil && len(region.Nodes) > 0 {
			return region.Nodes[0]
		}
	}
	for _, regionID := range dm.RegionIDs() {
		region := dm.Regions[regionID]
		if region != nil && len(region.Nodes) > 0 {
			return region.Nodes[0]
		}
	}
	return nil
}

func publicDERPMapURL() string {
	if override := os.Getenv("DERPCAT_TEST_DERP_MAP_URL"); override != "" {
		return override
	}
	return derpbind.PublicDERPMapURL
}

func publicDERPServerURL(node *tailcfg.DERPNode) string {
	if override := os.Getenv("DERPCAT_TEST_DERP_SERVER_URL"); override != "" {
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

func FormatError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
