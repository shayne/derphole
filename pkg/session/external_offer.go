package session

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/quicpath"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/token"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func offerExternal(ctx context.Context, cfg OfferConfig) (string, error) {
	tok, session, err := issuePublicSessionWithCapabilities(ctx, token.CapabilityStdioOffer)
	if err != nil {
		return "", err
	}
	defer closePublicSessionTransport(session)
	defer session.derp.Close()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)

	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	if cfg.TokenSink != nil {
		select {
		case cfg.TokenSink <- tok:
		case <-ctx.Done():
			return tok, ctx.Err()
		}
	}

	for {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			if ctx.Err() != nil {
				return tok, ctx.Err()
			}
			return tok, err
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			continue
		}

		peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
		decision, _ := session.gate.Accept(time.Now(), *env.Claim)
		if !decision.Accepted {
			if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
				return tok, err
			}
			continue
		}
		if decision.Accept == nil {
			return tok, errors.New("accepted decision missing accept payload")
		}

		probeConn := session.probeConn
		probeConns := []net.PacketConn{session.probeConn}
		portmaps := []publicPortmap{publicSessionPortmap(session)}
		cleanupProbeConns := func() {}
		if !cfg.ForceRelay {
			probeConn, probeConns, portmaps, cleanupProbeConns, err = externalAcceptedDirectUDPSet(cfg.Emitter)
			if err != nil {
				return tok, err
			}
		}
		defer cleanupProbeConns()
		pm := portmaps[0]
		decision.Accept.Parallel = len(probeConns)
		if !cfg.ForceRelay {
			decision.Accept.Candidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, session.derpMap, portmaps))
		} else {
			decision.Accept.Candidates = nil
		}

		localCandidates := parseCandidateStrings(decision.Accept.Candidates)
		ackCh, unsubscribeAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isAckPayload(pkt.Payload)
		})
		defer unsubscribeAck()
		readyAckCh, unsubscribeReadyAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
		})
		defer unsubscribeReadyAck()
		startAckCh, unsubscribeStartAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPStartAckPayload(pkt.Payload)
		})
		defer unsubscribeStartAck()
		rateProbeCh, unsubscribeRateProbe := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPRateProbePayload(pkt.Payload)
		})
		defer unsubscribeRateProbe()

		transportCtx, transportCancel := context.WithCancel(ctx)
		defer transportCancel()
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, session.derpMap, session.derp, peerDERP, localCandidates, pm, cfg.ForceRelay)
		if err != nil {
			return tok, err
		}
		defer transportCleanup()
		pathEmitter.Emit(StateClaimed)
		pathEmitter.SuppressWatcherDirect()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)
		remoteCandidates := parseCandidateStrings(env.Claim.Candidates)
		punchCtx, punchCancel := context.WithCancel(transportCtx)
		defer punchCancel()
		if !cfg.ForceRelay {
			externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
		}

		src, err := openOfferSource(ctx, cfg)
		if err != nil {
			return tok, err
		}
		defer src.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}

		sendCfg := SendConfig{
			Emitter:        cfg.Emitter,
			StdioIn:        cfg.StdioIn,
			ForceRelay:     cfg.ForceRelay,
			UsePublicDERP:  cfg.UsePublicDERP,
			ParallelPolicy: cfg.ParallelPolicy,
		}
		var sendErr error
		if cfg.ForceRelay {
			sendErr = sendExternalRelayUDP(ctx, src, transportManager, session.token.SessionID, cfg.Emitter)
		} else {
			sendErr = sendExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixSendConfig{
				src:              src,
				tok:              session.token,
				decision:         decision,
				derpClient:       session.derp,
				listenerDERP:     peerDERP,
				transportCtx:     transportCtx,
				transportManager: transportManager,
				pathEmitter:      pathEmitter,
				punchCancel:      punchCancel,
				probeConn:        probeConn,
				probeConns:       probeConns,
				remoteCandidates: remoteCandidates,
				readyAckCh:       readyAckCh,
				startAckCh:       startAckCh,
				rateProbeCh:      rateProbeCh,
				cfg:              sendCfg,
			})
		}
		if sendErr != nil {
			return tok, sendErr
		}
		if err := waitForPeerAckWithTimeout(ctx, ackCh, externalDirectUDPAckWait); err != nil {
			return tok, err
		}
		pathEmitter.Complete(transportManager)
		return tok, nil
	}
}

func receiveExternal(ctx context.Context, cfg ReceiveConfig) error {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities&token.CapabilityStdioOffer == 0 {
		return ErrUnknownSession
	}

	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return ErrUnknownSession
	}

	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	defer derpClient.Close()

	var relayPrefixPackets <-chan derpbind.Packet
	var unsubscribeRelayPrefix func()
	if !cfg.ForceRelay {
		relayPrefixPackets, unsubscribeRelayPrefix = derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == listenerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
		})
		defer unsubscribeRelayPrefix()
	}

	probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConnsFn(nil, nil, externalDirectUDPParallelism, cfg.Emitter)
	if err != nil {
		return err
	}
	defer cleanupProbeConns()
	probeConn := probeConns[0]
	pm := portmaps[0]

	claimIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		return err
	}

	var localCandidates []string
	if !cfg.ForceRelay {
		localCandidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, dm, portmaps))
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   claimIdentity.Public,
		Parallel:     len(probeConns),
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim)
	if err != nil {
		return err
	}
	if !decision.Accepted {
		if decision.Reject != nil {
			return errors.New(decision.Reject.Reason)
		}
		return errors.New("claim rejected")
	}
	if decision.Accept == nil {
		return errors.New("accepted decision missing accept payload")
	}

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)

	readyCh, unsubscribeReady := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPReadyPayload(pkt.Payload)
	})
	defer unsubscribeReady()
	startCh, unsubscribeStart := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPStartPayload(pkt.Payload)
	})
	defer unsubscribeStart()

	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.SuppressWatcherDirect()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	remoteCandidates := parseCandidateStrings(decision.Accept.Candidates)
	punchCtx, punchCancel := context.WithCancel(transportCtx)
	defer punchCancel()
	if !cfg.ForceRelay {
		externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
	}

	dst, err := openReceiveSink(ctx, cfg)
	if err != nil {
		return err
	}
	defer dst.Close()

	var receiveErr error
	if cfg.ForceRelay {
		receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, tok.SessionID, cfg.Emitter)
	} else {
		listenCfg := ListenConfig{
			Emitter:       cfg.Emitter,
			StdioOut:      cfg.StdioOut,
			ForceRelay:    cfg.ForceRelay,
			UsePublicDERP: cfg.UsePublicDERP,
		}
		receiveErr = receiveExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixReceiveConfig{
			dst:              dst,
			tok:              tok,
			derpClient:       derpClient,
			peerDERP:         listenerDERP,
			transportManager: transportManager,
			pathEmitter:      pathEmitter,
			punchCancel:      punchCancel,
			probeConn:        probeConn,
			probeConns:       probeConns,
			remoteCandidates: remoteCandidates,
			decision:         decision,
			readyCh:          readyCh,
			startCh:          startCh,
			relayPackets:     relayPrefixPackets,
			cfg:              listenCfg,
		})
	}
	if receiveErr != nil {
		return receiveErr
	}
	if err := sendEnvelope(ctx, derpClient, listenerDERP, envelope{Type: envelopeAck}); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}
