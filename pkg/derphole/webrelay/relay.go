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
	claimRetryDelay    = 250 * time.Millisecond
	frameRetryDelay    = 2 * time.Second
	offerTokenTTL      = time.Hour
	defaultClaimPar    = 1
	maxFilenameBytes   = 255
	statusWaitingClaim = "waiting-for-claim"
	statusClaimed      = "claimed"
	statusRelay        = "connected-relay"
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

type Offer struct {
	client *derpbind.Client
	token  token.Token
	gate   *rendezvous.Gate
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

func (o *Offer) Send(ctx context.Context, src FileSource, cb Callbacks) error {
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

	meta := webproto.Meta{Name: safeName(src.Name()), Size: src.Size()}
	metaPayload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameMeta, 0, metaPayload, 0); err != nil {
		return err
	}

	var offset int64
	var seq uint64 = 1
	for {
		chunk, err := src.ReadChunk(ctx, offset, chunkBytes)
		if err != nil {
			return notifyAbort(ctx, o.client, peerDERP, err)
		}
		if len(chunk) == 0 {
			break
		}
		offset += int64(len(chunk))
		if err := sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameData, seq, chunk, offset); err != nil {
			return err
		}
		cb.progress(Progress{Bytes: offset, Total: meta.Size})
		seq++
	}

	if err := sendFrameAwaitAck(ctx, o.client, peerDERP, peerCh, webproto.FrameDone, seq, nil, offset); err != nil {
		return err
	}
	cb.progress(Progress{Bytes: offset, Total: meta.Size})
	cb.status(statusComplete)
	return nil
}

func Receive(ctx context.Context, encodedToken string, sink FileSink, cb Callbacks) error {
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
	cb.status(statusRelay)
	return receiveFrames(ctx, client, peerDERP, frames, sink, cb)
}

func receiveFrames(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, frames <-chan derpbind.Packet, sink FileSink, cb Callbacks) error {
	var meta webproto.Meta
	var expectedSeq uint64 = 1
	var received int64
	var opened bool

	for {
		pkt, err := nextPacket(ctx, frames)
		if err != nil {
			return err
		}
		frame, err := webproto.Parse(pkt.Payload)
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

func sendClaimUntilDecision(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, frames <-chan derpbind.Packet, claim rendezvous.Claim) error {
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

func sendFrameAwaitAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, frames <-chan derpbind.Packet, kind webproto.FrameKind, seq uint64, payload []byte, wantBytes int64) error {
	for {
		if err := sendFrame(ctx, client, peerDERP, kind, seq, payload); err != nil {
			return err
		}
		timer := time.NewTimer(frameRetryDelay)
		for {
			select {
			case pkt, ok := <-frames:
				if !ok {
					timer.Stop()
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
						timer.Stop()
						return nil
					}
				case webproto.FrameAbort:
					timer.Stop()
					return decodeAbort(frame.Payload)
				}
			case <-timer.C:
				goto retry
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
	retry:
	}
}

func sendFrame(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, kind webproto.FrameKind, seq uint64, payload []byte) error {
	frame, err := webproto.Marshal(kind, seq, payload)
	if err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, frame)
}

func sendAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived int64) error {
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

func abortAndReturn(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, reason string) error {
	_ = sendAbort(ctx, client, peerDERP, reason)
	return errors.New(reason)
}

func notifyAbort(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, err error) error {
	if err != nil {
		_ = sendAbort(ctx, client, peerDERP, err.Error())
	}
	return err
}

func sendAbort(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, reason string) error {
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
