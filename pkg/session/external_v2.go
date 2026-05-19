// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"go4.org/mem"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const externalV2CopyBufferSize = 1 << 20

type externalV2SendRuntime struct {
	cfg          SendConfig
	tok          token.Token
	listenerDERP key.NodePublic
	dm           *tailcfg.DERPMap
	derp         *derpbind.Client
	probeConn    net.PacketConn
	pm           publicPortmap
	identity     quicpath.SessionIdentity
	auth         externalPeerControlAuth

	acceptCh            <-chan derpbind.Packet
	completeCh          <-chan derpbind.Packet
	unsubscribeAccept   func()
	unsubscribeComplete func()
}

type externalV2ListenRuntime struct {
	cfg     ListenConfig
	tok     string
	auth    externalPeerControlAuth
	session *relaySession

	claimCh           <-chan derpbind.Packet
	unsubscribeClaims func()
}

type externalV2AcceptedClaim struct {
	peerDERP key.NodePublic
	claim    externalV2Claim
}

func sendExternalViaV2(ctx context.Context, cfg SendConfig) error {
	rt, err := newExternalV2SendRuntime(ctx, sendConfigWithInferredExpectedBytes(cfg))
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run(ctx)
}

func newExternalV2SendRuntime(ctx context.Context, cfg SendConfig) (*externalV2SendRuntime, error) {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return nil, err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return nil, ErrUnknownSession
	}
	if err := validateExternalV2SendToken(tok); err != nil {
		return nil, err
	}
	rt := &externalV2SendRuntime{
		cfg:          cfg,
		tok:          tok,
		listenerDERP: key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:])),
		auth:         externalPeerControlAuthForToken(tok),
	}
	if rt.listenerDERP.IsZero() {
		return nil, ErrUnknownSession
	}
	if err := rt.openDERP(ctx); err != nil {
		rt.Close()
		return nil, err
	}
	if err := rt.openProbeConn(); err != nil {
		rt.Close()
		return nil, err
	}
	if rt.identity, err = quicpath.GenerateSessionIdentity(); err != nil {
		rt.Close()
		return nil, err
	}
	rt.subscribe()
	return rt, nil
}

func (rt *externalV2SendRuntime) openDERP(ctx context.Context) error {
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(rt.tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	client, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	rt.dm = dm
	rt.derp = client
	return nil
}

func (rt *externalV2SendRuntime) openProbeConn() error {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	rt.probeConn = conn
	rt.pm = newBoundPublicPortmap(conn, nil)
	return nil
}

func (rt *externalV2SendRuntime) subscribe() {
	rt.acceptCh, rt.unsubscribeAccept = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isV2AcceptPayload(pkt.Payload)
	})
	rt.completeCh, rt.unsubscribeComplete = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isV2CompletePayload(pkt.Payload)
	})
}

func (rt *externalV2SendRuntime) Close() {
	if rt.unsubscribeAccept != nil {
		rt.unsubscribeAccept()
	}
	if rt.unsubscribeComplete != nil {
		rt.unsubscribeComplete()
	}
	if rt.derp != nil {
		_ = rt.derp.Close()
	}
	if rt.pm != nil {
		_ = rt.pm.Close()
	}
	if rt.probeConn != nil {
		_ = rt.probeConn.Close()
	}
}

func (rt *externalV2SendRuntime) run(ctx context.Context) error {
	src, err := openSendSource(ctx, rt.cfg)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateWaiting)
	if err := rt.sendClaim(ctx); err != nil {
		return err
	}
	pathEmitter.Emit(StateClaimed)

	manager, cleanup, err := rt.acceptAndStartTransport(ctx, pathEmitter)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := rt.sendStream(ctx, manager, src); err != nil {
		return err
	}
	pathEmitter.Complete(manager)
	return nil
}

func (rt *externalV2SendRuntime) acceptAndStartTransport(ctx context.Context, pathEmitter *transportPathEmitter) (*transport.Manager, func(), error) {
	accept, err := rt.receiveAccept(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := validateExternalV2Accept(accept); err != nil {
		return nil, nil, err
	}
	transferCtx, cancel := context.WithCancel(ctx)
	manager, cleanup, err := startExternalTransportManager(transferCtx, rt.tok, rt.probeConn, rt.dm, rt.derp, rt.listenerDERP, nil, rt.pm, true)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	pathEmitter.Watch(transferCtx, manager)
	pathEmitter.Flush(manager)
	return manager, func() {
		cleanup()
		cancel()
	}, nil
}

func (rt *externalV2SendRuntime) sendStream(ctx context.Context, manager *transport.Manager, src io.Reader) error {
	client := dataplane.NewQUICClient(manager, rt.identity, rt.tok.QUICPublic)
	stream, err := client.Open(ctx)
	if err != nil {
		return err
	}
	if err := copyExternalV2SendStream(src, stream); err != nil {
		_ = client.CloseWithError(1, err.Error())
		return err
	}
	if err := stream.Close(); err != nil {
		_ = client.CloseWithError(1, err.Error())
		return err
	}
	complete, err := rt.receiveComplete(ctx)
	if err != nil {
		_ = client.CloseWithError(1, err.Error())
		return err
	}
	if err := client.CloseWithError(0, "complete"); err != nil {
		return err
	}
	if complete.BytesReceived < 0 {
		return fmt.Errorf("invalid v2 complete bytes %d", complete.BytesReceived)
	}
	return nil
}

func (rt *externalV2SendRuntime) sendClaim(ctx context.Context) error {
	claim := externalV2Claim{
		Protocol:     externalV2Protocol,
		QUICPublic:   rt.identity.Public,
		RelayCapable: true,
	}
	return sendAuthenticatedEnvelope(ctx, rt.derp, rt.listenerDERP, envelope{
		Type:    envelopeV2Claim,
		V2Claim: &claim,
	}, rt.auth)
}

func (rt *externalV2SendRuntime) receiveAccept(ctx context.Context) (externalV2Accept, error) {
	for {
		select {
		case pkt, ok := <-rt.acceptCh:
			if !ok {
				return externalV2Accept{}, ErrPeerDisconnected
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
			if err != nil {
				if ignoreAuthenticatedEnvelopeError(err, rt.auth) {
					continue
				}
				return externalV2Accept{}, err
			}
			if env.Type == envelopeV2Accept && env.V2Accept != nil {
				return *env.V2Accept, nil
			}
		case <-ctx.Done():
			return externalV2Accept{}, ctx.Err()
		}
	}
}

func (rt *externalV2SendRuntime) receiveComplete(ctx context.Context) (externalV2Complete, error) {
	for {
		select {
		case pkt, ok := <-rt.completeCh:
			if !ok {
				return externalV2Complete{}, ErrPeerDisconnected
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
			if err != nil {
				if ignoreAuthenticatedEnvelopeError(err, rt.auth) {
					continue
				}
				return externalV2Complete{}, err
			}
			if env.Type == envelopeV2Complete && env.V2Complete != nil {
				return *env.V2Complete, nil
			}
		case <-ctx.Done():
			return externalV2Complete{}, ctx.Err()
		}
	}
}

func listenExternalViaV2(ctx context.Context, cfg ListenConfig) (string, error) {
	rt, err := newExternalV2ListenRuntime(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	if err := rt.publishToken(ctx); err != nil {
		return rt.tok, err
	}
	return rt.run(ctx)
}

func newExternalV2ListenRuntime(ctx context.Context, cfg ListenConfig) (*externalV2ListenRuntime, error) {
	tok, session, err := issuePublicQUICSession(ctx, token.CapabilityStdio|token.CapabilityTransferV2)
	if err != nil {
		return nil, err
	}
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isV2ClaimPayload(pkt.Payload)
	})
	rt := &externalV2ListenRuntime{
		cfg:               cfg,
		tok:               tok,
		session:           session,
		auth:              externalPeerControlAuthForToken(session.token),
		claimCh:           claimCh,
		unsubscribeClaims: unsubscribeClaims,
	}
	emitStatus(cfg.Emitter, StateWaiting)
	return rt, nil
}

func (rt *externalV2ListenRuntime) Close() {
	if rt.unsubscribeClaims != nil {
		rt.unsubscribeClaims()
	}
	closePublicSessionTransport(rt.session)
	if rt.session != nil && rt.session.derp != nil {
		_ = rt.session.derp.Close()
	}
}

func (rt *externalV2ListenRuntime) publishToken(ctx context.Context) error {
	return emitListenToken(ctx, rt.cfg.TokenSink, rt.tok)
}

func (rt *externalV2ListenRuntime) run(ctx context.Context) (string, error) {
	for {
		accepted, ok, err := rt.nextClaim(ctx)
		if err != nil {
			return rt.tok, err
		}
		if !ok {
			continue
		}
		if err := rt.receive(ctx, accepted); err != nil {
			return rt.tok, err
		}
		return rt.tok, nil
	}
}

func (rt *externalV2ListenRuntime) nextClaim(ctx context.Context) (externalV2AcceptedClaim, bool, error) {
	for {
		select {
		case pkt, ok := <-rt.claimCh:
			if !ok {
				return externalV2AcceptedClaim{}, false, ErrPeerDisconnected
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
			if err != nil {
				if ignoreAuthenticatedEnvelopeError(err, rt.auth) {
					continue
				}
				return externalV2AcceptedClaim{}, false, err
			}
			if env.Type != envelopeV2Claim || env.V2Claim == nil {
				continue
			}
			if err := validateExternalV2Claim(*env.V2Claim); err != nil {
				return externalV2AcceptedClaim{}, false, err
			}
			return externalV2AcceptedClaim{peerDERP: pkt.From, claim: *env.V2Claim}, true, nil
		case <-ctx.Done():
			return externalV2AcceptedClaim{}, false, ctx.Err()
		}
	}
}

func (rt *externalV2ListenRuntime) receive(ctx context.Context, accepted externalV2AcceptedClaim) error {
	dst, err := openListenSink(ctx, rt.cfg)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()

	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	manager, cleanup, err := startExternalTransportManager(transferCtx, rt.session.token, rt.session.probeConn, rt.session.derpMap, rt.session.derp, accepted.peerDERP, nil, publicSessionPortmap(rt.session), true)
	if err != nil {
		return err
	}
	defer cleanup()

	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Watch(transferCtx, manager)
	pathEmitter.Flush(manager)

	server := dataplane.NewQUICServer(manager, rt.session.quicIdentity, accepted.claim.QUICPublic)
	var bytesReceived int64
	stream, err := server.AcceptWithReady(transferCtx, func() error {
		return rt.sendAccept(ctx, accepted.peerDERP)
	})
	if err != nil {
		return err
	}
	bytesReceived, err = copyExternalV2ReceiveStream(dst, stream)
	if err != nil {
		_ = server.CloseWithError(1, err.Error())
		return err
	}
	if err := stream.Close(); err != nil {
		_ = server.CloseWithError(1, err.Error())
		return err
	}
	if err := rt.sendComplete(ctx, accepted.peerDERP, bytesReceived); err != nil {
		_ = server.CloseWithError(1, err.Error())
		return err
	}
	if err := server.CloseWithError(0, "complete"); err != nil {
		return err
	}
	pathEmitter.Complete(manager)
	return nil
}

func (rt *externalV2ListenRuntime) sendAccept(ctx context.Context, peerDERP key.NodePublic) error {
	accept := externalV2Accept{
		Protocol:     externalV2Protocol,
		Accepted:     true,
		RelayCapable: true,
	}
	return sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{
		Type:     envelopeV2Accept,
		V2Accept: &accept,
	}, rt.auth)
}

func (rt *externalV2ListenRuntime) sendComplete(ctx context.Context, peerDERP key.NodePublic, bytesReceived int64) error {
	complete := externalV2Complete{
		Protocol:      externalV2Protocol,
		BytesReceived: bytesReceived,
	}
	return sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{
		Type:       envelopeV2Complete,
		V2Complete: &complete,
	}, rt.auth)
}

func copyExternalV2SendStream(src io.Reader, stream dataplane.Stream) error {
	writer := bufio.NewWriterSize(stream, externalV2CopyBufferSize)
	buf := make([]byte, externalV2CopyBufferSize)
	if _, err := io.CopyBuffer(writer, src, buf); err != nil {
		return err
	}
	return writer.Flush()
}

func copyExternalV2ReceiveStream(dst io.Writer, stream dataplane.Stream) (int64, error) {
	buf := make([]byte, externalV2CopyBufferSize)
	return io.CopyBuffer(dst, stream, buf)
}
