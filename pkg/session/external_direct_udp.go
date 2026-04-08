package session

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/transport"
	wgtransport "github.com/shayne/derpcat/pkg/wg"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	externalDirectUDPTransportLabel     = "batched"
	externalDirectUDPParallelism        = 8
	externalDirectUDPChunkSize          = 1384 // 52-byte probe header + 16-byte GCM tag keeps UDP payload at 1452 bytes.
	externalDirectUDPRateMbps           = 2250
	externalDirectUDPWait               = 5 * time.Second
	externalDirectUDPPunchWait          = 1200 * time.Millisecond
	externalDirectUDPHandshakeWait      = 1500 * time.Millisecond
	externalDirectUDPStartWait          = 30 * time.Second
	externalDirectUDPAckWait            = 60 * time.Second
	externalDirectUDPBufferSize         = 4 << 20
	externalDirectUDPRepairPayloads     = true
	externalDirectUDPTailReplayBytes    = 0
	externalDirectUDPFECGroupSize       = 32
	externalDirectUDPStripedBlast       = false
	externalDirectUDPDiscardQueue       = 32
	externalDirectUDPRateProbeMinBytes  = 256 << 20
	externalDirectUDPRateProbeDuration  = 200 * time.Millisecond
	externalDirectUDPRateProbeGrace     = 300 * time.Millisecond
	externalDirectUDPRateProbeMinMbps   = 64
	externalDirectUDPRateProbeHighShare = 0.79
	externalDirectUDPRateProbeHighGain  = 1.40
)

var externalDirectUDPRateProbeMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'c', 'a', 't', '-', 'r', 'a', 't', 'e', '-', 'v', '1'}

var externalDirectUDPPreviewTransportCaps = probe.PreviewTransportCaps

var externalDirectUDPPacketAEADDomain = []byte("derpcat-direct-udp-packet-aead-v1")

func externalDirectUDPPacketAEAD(tok token.Token) (cipher.AEAD, error) {
	hash := sha256.New()
	_, _ = hash.Write(externalDirectUDPPacketAEADDomain)
	_, _ = hash.Write(tok.SessionID[:])
	_, _ = hash.Write(tok.BearerSecret[:])
	block, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sendExternalViaDirectUDP(ctx context.Context, cfg SendConfig) error {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return ErrUnknownSession
	}
	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer src.Close()

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

	probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConns(nil, nil, externalDirectUDPParallelism, cfg.Emitter)
	if err != nil {
		return err
	}
	defer cleanupProbeConns()
	probeConn := probeConns[0]
	pm := portmaps[0]

	_, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		return err
	}

	var localCandidates []string
	if !cfg.ForceRelay {
		localCandidates = externalDirectUDPCandidates(ctx, probeConns, dm, portmaps)
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("udp-local-candidates=" + strings.Join(localCandidates, ","))
		}
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   senderPublic,
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
	ackCh, unsubscribeAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	readyAckCh, unsubscribeReadyAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
	})
	defer unsubscribeReadyAck()
	startAckCh, unsubscribeStartAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPStartAckPayload(pkt.Payload)
	})
	defer unsubscribeStartAck()
	rateProbeCh, unsubscribeRateProbe := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPRateProbePayload(pkt.Payload)
	})
	defer unsubscribeRateProbe()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	remoteCandidates := parseCandidateStrings(decision.Accept.Candidates)
	punchCtx, punchCancel := context.WithCancel(transportCtx)
	defer punchCancel()
	if !cfg.ForceRelay {
		externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
	}

	var sendErr error
	if cfg.ForceRelay || len(remoteCandidates) == 0 {
		sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
	} else if peerAddr, err := waitExternalDirectUDPAddr(ctx, probeConn, transportManager); err == nil {
		if err := sendEnvelope(ctx, derpClient, listenerDERP, envelope{Type: envelopeDirectUDPReady}); err != nil {
			return err
		}
		readyAck, err := waitForDirectUDPReadyAck(ctx, readyAckCh)
		if err != nil {
			if externalDirectUDPWaitCanFallback(ctx, err) {
				sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
			} else {
				return err
			}
		} else {
			transportManager.StopDirectReads()
			pathEmitter.Emit(StateDirect)
			remoteAddrs := externalDirectUDPSelectRemoteAddrs(ctx, probeConns, remoteCandidates, peerAddr, cfg.Emitter)
			probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
			if len(probeConns) == 0 {
				return errors.New("direct UDP established without usable remote addresses")
			}
			activeRateMbps := externalDirectUDPRateMbpsForLanes(externalDirectUDPRateMbps, len(probeConns))
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("udp-blast=true")
				cfg.Emitter.Debug("udp-lanes=" + strconv.Itoa(len(probeConns)))
				cfg.Emitter.Debug("udp-rate-max-mbps=" + strconv.Itoa(activeRateMbps))
				cfg.Emitter.Debug("udp-repair-payloads=" + strconv.FormatBool(externalDirectUDPRepairPayloads))
				cfg.Emitter.Debug("udp-tail-replay-bytes=" + strconv.Itoa(externalDirectUDPTailReplayBytes))
				cfg.Emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPFECGroupSize))
				cfg.Emitter.Debug("udp-striped-blast=false")
				cfg.Emitter.Debug("udp-fast-discard=" + strconv.FormatBool(readyAck.FastDiscard))
				cfg.Emitter.Debug("udp-direct-addr=" + peerAddr.String())
				cfg.Emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
			}
			packetAEAD, err := externalDirectUDPPacketAEAD(tok)
			if err != nil {
				return err
			}
			sendCfg := probe.SendConfig{
				Blast:                    true,
				Transport:                externalDirectUDPTransportLabel,
				ChunkSize:                externalDirectUDPChunkSize,
				RateMbps:                 activeRateMbps,
				RunID:                    tok.SessionID,
				RepairPayloads:           externalDirectUDPRepairPayloads,
				TailReplayBytes:          externalDirectUDPTailReplayBytes,
				FECGroupSize:             externalDirectUDPFECGroupSize,
				StripedBlast:             externalDirectUDPStripedBlast && !readyAck.FastDiscard,
				PacketAEAD:               packetAEAD,
				AllowPartialParallel:     true,
				ParallelHandshakeTimeout: externalDirectUDPHandshakeWait,
			}
			var stats probe.TransferStats
			spool, spoolErr := externalDirectUDPSpoolDiscardLanes(ctx, externalDirectUDPBufferedReader(src), len(probeConns), sendCfg.ChunkSize)
			if spoolErr != nil {
				return spoolErr
			}
			defer spool.Close()
			rateProbeRates := externalDirectUDPRateProbeRates(activeRateMbps, spool.TotalBytes)
			if cfg.Emitter != nil && len(rateProbeRates) > 0 {
				cfg.Emitter.Debug("udp-rate-probe-rates=" + externalDirectUDPFormatInts(rateProbeRates))
			}
			emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, spool.TotalBytes)
			if err := sendEnvelope(ctx, derpClient, listenerDERP, envelope{
				Type: envelopeDirectUDPStart,
				DirectUDPStart: &directUDPStart{
					ExpectedBytes: spool.TotalBytes,
					SectionSizes:  append([]int64(nil), spool.Sizes...),
					SectionAddrs:  append([]string(nil), remoteAddrs...),
					ProbeRates:    append([]int(nil), rateProbeRates...),
				},
			}); err != nil {
				return err
			}
			if err := waitForDirectUDPStartAck(ctx, startAckCh); err != nil {
				return err
			}
			if len(rateProbeRates) > 0 {
				sentSamples, probeErr := externalDirectUDPSendRateProbes(ctx, probeConns, remoteAddrs, rateProbeRates)
				if probeErr != nil {
					if cfg.Emitter != nil {
						cfg.Emitter.Debug("udp-rate-probe-error=" + probeErr.Error())
					}
				} else {
					probeResult, resultErr := waitForDirectUDPRateProbeResult(ctx, rateProbeCh, len(rateProbeRates))
					if resultErr != nil {
						if cfg.Emitter != nil {
							cfg.Emitter.Debug("udp-rate-probe-result-error=" + resultErr.Error())
						}
					} else {
						activeRateMbps = externalDirectUDPSelectRateFromProbeSamples(activeRateMbps, sentSamples, probeResult.Samples)
						sendCfg.RateMbps = activeRateMbps
						if cfg.Emitter != nil {
							cfg.Emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(sentSamples, probeResult.Samples))
							cfg.Emitter.Debug("udp-rate-mbps=" + strconv.Itoa(activeRateMbps))
						}
					}
				}
			}
			if cfg.Emitter != nil && len(rateProbeRates) == 0 {
				cfg.Emitter.Debug("udp-rate-mbps=" + strconv.Itoa(activeRateMbps))
			}
			sectionSendCfg := sendCfg
			// Sectioned direct UDP derives stable per-lane run IDs so stale probe packets cannot enter the payload receiver.
			sectionSendCfg.RunID = tok.SessionID
			externalDirectUDPStopPunchingForBlast(punchCancel)
			stats, err = externalDirectUDPSendDiscardSpoolParallel(ctx, probeConns, remoteAddrs, spool, sectionSendCfg)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("udp-send-transport=" + stats.Transport.Summary())
				if stats.Lanes > 0 {
					cfg.Emitter.Debug("udp-send-active-lanes=" + strconv.Itoa(stats.Lanes))
				}
				cfg.Emitter.Debug("udp-send-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
				emitExternalDirectUDPStats(cfg.Emitter, "udp-send", stats.BytesSent, stats.StartedAt, stats.FirstByteAt, stats.CompletedAt)
			}
			sendErr = err
		}
	} else if externalDirectUDPWaitCanFallback(ctx, err) {
		sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
	} else {
		return err
	}
	if sendErr != nil {
		return sendErr
	}
	if err := waitForPeerAckWithTimeout(ctx, ackCh, externalDirectUDPAckWait); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}

func listenExternalViaDirectUDP(ctx context.Context, cfg ListenConfig) (string, error) {
	tok, session, err := issuePublicSession(ctx)
	if err != nil {
		return "", err
	}
	defer deleteRelayMailbox(tok, session)
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
		probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConns(session.probeConn, publicSessionPortmap(session), externalDirectUDPParallelism, cfg.Emitter)
		if err != nil {
			return tok, err
		}
		defer cleanupProbeConns()
		decision.Accept.Parallel = len(probeConns)
		if !cfg.ForceRelay {
			decision.Accept.Candidates = externalDirectUDPCandidates(ctx, probeConns, session.derpMap, portmaps)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("udp-local-candidates=" + strings.Join(decision.Accept.Candidates, ","))
			}
		}
		localCandidates := parseCandidateStrings(decision.Accept.Candidates)
		readyCh, unsubscribeReady := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPReadyPayload(pkt.Payload)
		})
		defer unsubscribeReady()
		startCh, unsubscribeStart := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPStartPayload(pkt.Payload)
		})
		defer unsubscribeStart()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("claim-accepted")
		}

		transportCtx, transportCancel := context.WithCancel(ctx)
		defer transportCancel()
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.probeConn, session.derpMap, session.derp, peerDERP, localCandidates, publicSessionPortmap(session), cfg.ForceRelay)
		if err != nil {
			return tok, err
		}
		defer transportCleanup()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)
		remoteCandidates := parseCandidateStrings(env.Claim.Candidates)
		punchCtx, punchCancel := context.WithCancel(transportCtx)
		defer punchCancel()
		if !cfg.ForceRelay {
			externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
		}

		dst, err := openListenSink(ctx, cfg)
		if err != nil {
			return tok, err
		}
		defer dst.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("decision-sent")
		}

		var receiveErr error
		if cfg.ForceRelay || len(remoteCandidates) == 0 {
			receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
		} else if _, err := waitExternalDirectUDPAddr(ctx, session.probeConn, transportManager); err == nil {
			peerAddr, _ := transportManager.DirectAddr()
			directReady := true
			if err := waitForDirectUDPReady(ctx, readyCh); err != nil {
				if externalDirectUDPWaitCanFallback(ctx, err) {
					directReady = false
					receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
				} else {
					return tok, err
				}
			}
			if receiveErr != nil {
				return tok, receiveErr
			}
			if directReady {
				remoteAddrs := externalDirectUDPParallelCandidateStrings(remoteCandidates, len(probeConns))
				probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
				if len(probeConns) == 0 {
					receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
				} else {
					transportManager.StopDirectReads()
					pathEmitter.Emit(StateDirect)
					receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
					fastDiscard := receiveDst == io.Discard
					if !fastDiscard {
						receiveDst, flushDst = externalDirectUDPSectionWriterForTarget(dst, receiveDst, flushDst)
					}
					if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{
						Type: envelopeDirectUDPReadyAck,
						DirectUDPReadyAck: &directUDPReadyAck{
							FastDiscard: fastDiscard,
						},
					}); err != nil {
						return tok, err
					}
					if cfg.Emitter != nil {
						cfg.Emitter.Debug("udp-blast=true")
						cfg.Emitter.Debug("udp-lanes=" + strconv.Itoa(len(probeConns)))
						cfg.Emitter.Debug("udp-require-complete=" + strconv.FormatBool(!fastDiscard))
						cfg.Emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPFECGroupSize))
						cfg.Emitter.Debug("udp-striped-blast=false")
						cfg.Emitter.Debug("udp-fast-discard=" + strconv.FormatBool(fastDiscard))
						if peerAddr != nil {
							cfg.Emitter.Debug("udp-direct-addr=" + peerAddr.String())
						}
						cfg.Emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
					}
					packetAEAD, err := externalDirectUDPPacketAEAD(session.token)
					if err != nil {
						return tok, err
					}
					receiveCfg := externalDirectUDPFastDiscardReceiveConfig()
					receiveCfg.PacketAEAD = packetAEAD
					var stats probe.TransferStats
					var start directUDPStart
					start, receiveErr = waitForDirectUDPStart(ctx, startCh)
					if receiveErr != nil {
						return tok, receiveErr
					}
					emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, start.ExpectedBytes)
					if receiveErr = sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDirectUDPStartAck}); receiveErr != nil {
						return tok, receiveErr
					}
					externalDirectUDPStopPunchingForBlast(punchCancel)
					if len(start.ProbeRates) > 0 {
						probeSamples, probeErr := externalDirectUDPReceiveRateProbes(ctx, probeConns, start.ProbeRates)
						if probeErr != nil {
							return tok, probeErr
						}
						if cfg.Emitter != nil {
							cfg.Emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(nil, probeSamples))
						}
						if receiveErr = sendEnvelope(ctx, session.derp, peerDERP, envelope{
							Type: envelopeDirectUDPRateProbe,
							DirectUDPRateProbe: &directUDPRateProbeResult{
								Samples: probeSamples,
							},
						}); receiveErr != nil {
							return tok, receiveErr
						}
					}
					if fastDiscard {
						stats, receiveErr = probe.ReceiveBlastParallelToWriter(ctx, probeConns, receiveDst, receiveCfg, start.ExpectedBytes)
					} else {
						receiveCfg.RequireComplete = true
						probeConns, receiveErr = externalDirectUDPOrderConnsForSections(probeConns, decision.Accept.Candidates, start.SectionAddrs)
						if receiveErr != nil {
							return tok, receiveErr
						}
						receiveCfg.ExpectedRunIDs = externalDirectUDPLaneRunIDs(session.token.SessionID, len(probeConns))
						stats, receiveErr = externalDirectUDPReceiveSectionSpoolParallel(ctx, probeConns, receiveDst, receiveCfg, start.ExpectedBytes, start.SectionSizes)
					}
					emitExternalDirectUDPReceiveResultDebug(cfg.Emitter, stats, receiveErr)
					if cfg.Emitter != nil {
						cfg.Emitter.Debug("udp-receive-transport=" + stats.Transport.Summary())
						if stats.Lanes > 0 {
							cfg.Emitter.Debug("udp-receive-active-lanes=" + strconv.Itoa(stats.Lanes))
						}
						cfg.Emitter.Debug("udp-receive-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
						emitExternalDirectUDPStats(cfg.Emitter, "udp-receive", stats.BytesReceived, stats.StartedAt, stats.FirstByteAt, stats.CompletedAt)
					}
					if receiveErr == nil {
						receiveErr = flushDst()
					}
				}
			}
		} else if externalDirectUDPWaitCanFallback(ctx, err) {
			receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
		} else {
			return tok, err
		}
		if receiveErr != nil {
			return tok, receiveErr
		}
		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeAck}); err != nil {
			return tok, err
		}
		pathEmitter.Complete(transportManager)
		return tok, nil
	}
}

func externalDirectUDPConns(_ net.PacketConn, _ publicPortmap, parallel int, emitter *telemetry.Emitter) ([]net.PacketConn, []publicPortmap, func(), error) {
	if parallel <= 0 {
		parallel = 1
	}
	conns := make([]net.PacketConn, 0, parallel)
	portmaps := make([]publicPortmap, 0, parallel)
	owned := make([]net.PacketConn, 0, parallel)
	ownedPMs := make([]publicPortmap, 0, parallel)
	network, address := "udp", ":0"
	if fakeTransportEnabled() {
		network, address = "udp4", "127.0.0.1:0"
	}
	for len(conns) < parallel {
		conn, err := net.ListenPacket(network, address)
		if err != nil {
			for _, ownedConn := range owned {
				_ = ownedConn.Close()
			}
			for _, pm := range ownedPMs {
				if pm != nil {
					_ = pm.Close()
				}
			}
			return nil, nil, nil, err
		}
		externalDirectUDPPreviewTransportCaps(conn, externalDirectUDPTransportLabel)
		pm := newBoundPublicPortmap(conn, emitter)
		conns = append(conns, conn)
		portmaps = append(portmaps, pm)
		owned = append(owned, conn)
		if pm != nil {
			ownedPMs = append(ownedPMs, pm)
		}
	}
	cleanup := func() {
		for _, pm := range ownedPMs {
			_ = pm.Close()
		}
		for _, conn := range owned {
			_ = conn.Close()
		}
	}
	return conns, portmaps, cleanup, nil
}

func externalDirectUDPCandidates(ctx context.Context, conns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap) []string {
	if len(conns) == 0 {
		return nil
	}
	sets := make([][]string, len(conns))
	for i, conn := range conns {
		var pm publicPortmap
		if i < len(portmaps) {
			pm = portmaps[i]
		}
		if fakeTransportEnabled() {
			sets[i] = publicInitialProbeCandidates(conn, pm)
			sets[i] = externalDirectUDPPreferLoopbackStrings(sets[i])
		} else {
			sets[i] = publicProbeCandidates(ctx, conn, dm, pm)
			sets[i] = externalDirectUDPPreferWANStrings(sets[i])
		}
	}
	sets = externalDirectUDPInferWANPerPort(sets)
	return externalDirectUDPFlattenCandidateSets(sets)
}

func externalDirectUDPFlattenCandidateSets(sets [][]string) []string {
	out := make([]string, 0, rendezvous.MaxClaimCandidates)
	seen := make(map[string]bool)
	add := func(candidate string) bool {
		if candidate == "" || seen[candidate] {
			return false
		}
		out = append(out, candidate)
		seen[candidate] = true
		return len(out) == rendezvous.MaxClaimCandidates
	}
	for depth := 0; ; depth++ {
		progressed := false
		for _, candidates := range sets {
			if depth >= len(candidates) {
				continue
			}
			progressed = true
			if add(candidates[depth]) {
				return out
			}
		}
		if !progressed {
			return out
		}
	}
}

func externalDirectUDPInferWANPerPort(sets [][]string) [][]string {
	var wan netip.Addr
	for _, candidates := range sets {
		for _, candidate := range candidates {
			addrPort, err := netip.ParseAddrPort(candidate)
			if err != nil {
				continue
			}
			if externalDirectUDPCandidateRank(candidate) == 0 {
				wan = addrPort.Addr()
				break
			}
		}
		if wan.IsValid() {
			break
		}
	}
	if !wan.IsValid() {
		return sets
	}
	out := make([][]string, len(sets))
	for i, candidates := range sets {
		out[i] = append([]string(nil), candidates...)
		hasWAN := false
		var port uint16
		for _, candidate := range candidates {
			addrPort, err := netip.ParseAddrPort(candidate)
			if err != nil {
				continue
			}
			if externalDirectUDPCandidateRank(candidate) == 0 {
				hasWAN = true
				break
			}
			if port == 0 && addrPort.Addr().IsPrivate() {
				port = addrPort.Port()
			}
		}
		if hasWAN || port == 0 {
			continue
		}
		inferred := netip.AddrPortFrom(wan, port).String()
		out[i] = append([]string{inferred}, out[i]...)
	}
	return out
}

func externalDirectUDPStartPunching(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr) {
	if len(remoteCandidates) == 0 {
		return
	}
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		go probe.PunchAddrs(ctx, conn, remoteCandidates, nil, 0)
	}
}

func externalDirectUDPSelectRemoteAddrs(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr, peer net.Addr, emitter *telemetry.Emitter) []string {
	fallback := externalDirectUDPParallelCandidateStringsForPeer(remoteCandidates, len(conns), peer)
	if fakeTransportEnabled() {
		return fallback
	}
	observedByConn := probe.ObservePunchAddrsByConn(ctx, conns, externalDirectUDPPunchWait)
	if emitter != nil {
		emitter.Debug("udp-remote-fallback-addrs=" + strings.Join(fallback, ","))
		emitter.Debug("udp-observed-addrs-by-conn=" + externalDirectUDPFormatObservedAddrsByConn(observedByConn))
	}
	selected := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, len(conns), peer)
	if emitter != nil {
		emitter.Debug("udp-selected-addrs=" + strings.Join(selected, ","))
	}
	final := externalDirectUDPFillMissingSelectedAddrs(selected, fallback)
	if emitter != nil {
		emitter.Debug("udp-final-addrs=" + strings.Join(final, ","))
	}
	return final
}

func externalDirectUDPFormatObservedAddrsByConn(observedByConn [][]net.Addr) string {
	parts := make([]string, 0, len(observedByConn))
	for i, observed := range observedByConn {
		parts = append(parts, strconv.Itoa(i)+"="+strings.Join(externalDirectUDPParallelCandidateStrings(observed, len(observed)), "|"))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPSelectRemoteAddrsByConn(observedByConn [][]net.Addr, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = len(observedByConn)
	}
	out := make([]string, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	selectCandidate := func(i int, candidate string) bool {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			return false
		}
		out[i] = candidate
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		return true
	}
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		for _, candidate := range externalDirectUDPParallelCandidateStringsForPeer(observedByConn[i], len(observedByConn[i]), peer) {
			if selectCandidate(i, candidate) {
				break
			}
		}
	}
	return out
}

func externalDirectUDPSelectedAddrCount(addrs []string) int {
	count := 0
	for _, addr := range addrs {
		if addr != "" {
			count++
		}
	}
	return count
}

func externalDirectUDPFillMissingSelectedAddrs(selected []string, fallback []string) []string {
	if externalDirectUDPSelectedAddrCount(selected) == len(selected) {
		return selected
	}
	if externalDirectUDPSelectedAddrCount(selected) == 0 {
		return externalDirectUDPDedupeAndFill(make([]string, len(selected)), fallback)
	}
	return externalDirectUDPDedupeAndFill(selected, fallback)
}

func externalDirectUDPParallelCandidateStrings(candidates []net.Addr, parallel int) []string {
	return externalDirectUDPParallelCandidateStringsForPeer(candidates, parallel, nil)
}

func externalDirectUDPParallelCandidateStringsForPeer(candidates []net.Addr, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = 1
	}
	ordered := probe.CandidateStringsInOrder(candidates)
	if fakeTransportEnabled() {
		ordered = externalDirectUDPPreferLoopbackStrings(ordered)
	} else {
		ordered = externalDirectUDPPreferPeerAddrStrings(ordered, peer)
	}
	out := make([]string, 0, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	for _, candidate := range ordered {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		if len(out) == parallel {
			return out
		}
	}
	for _, candidate := range ordered {
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) == parallel {
			return out
		}
	}
	return out
}

func externalDirectUDPPreferPeerAddrStrings(candidates []string, peer net.Addr) []string {
	out := externalDirectUDPPreferWANStrings(candidates)
	peerAddr, ok := externalDirectUDPAddrPort(peer)
	if !ok {
		return out
	}
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromotePeerCandidate(candidate, out[j], peerAddr.Addr()) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromotePeerCandidate(candidate string, existing string, peer netip.Addr) bool {
	candidatePeer := externalDirectUDPMatchesPeerAddr(candidate, peer)
	existingPeer := externalDirectUDPMatchesPeerAddr(existing, peer)
	if candidatePeer != existingPeer {
		return candidatePeer
	}
	return candidatePeer && externalDirectUDPShouldPromoteCandidate(candidate, existing)
}

func externalDirectUDPMatchesPeerAddr(candidate string, peer netip.Addr) bool {
	candidateAddr, err := netip.ParseAddrPort(candidate)
	return err == nil && candidateAddr.Addr() == peer
}

func externalDirectUDPAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil || !addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func externalDirectUDPPreferLoopbackStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromoteLoopbackCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromoteLoopbackCandidate(candidate string, existing string) bool {
	candidateLoopback := externalDirectUDPCandidateRank(candidate) == 5
	existingLoopback := externalDirectUDPCandidateRank(existing) == 5
	if candidateLoopback != existingLoopback {
		return candidateLoopback
	}
	if candidateLoopback {
		return externalDirectUDPShouldPromoteCandidate(candidate, existing)
	}
	return false
}

func externalDirectUDPPreferWANStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromoteCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromoteCandidate(candidate string, existing string) bool {
	candidateRank := externalDirectUDPCandidateRank(candidate)
	existingRank := externalDirectUDPCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return externalDirectUDPEndpointKey(candidate) == externalDirectUDPEndpointKey(existing) && externalDirectUDPBetterCandidate(candidate, existing)
}

func externalDirectUDPBetterCandidate(candidate string, existing string) bool {
	candidateRank := externalDirectUDPCandidateRank(candidate)
	existingRank := externalDirectUDPCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return candidate < existing
}

func externalDirectUDPCandidateRank(candidate string) int {
	addrPort, err := netip.ParseAddrPort(candidate)
	if err != nil {
		return 6
	}
	addr := addrPort.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		return 6
	}
	if addr.IsLoopback() {
		return 5
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return 4
	}
	if publicProbeTailscaleCGNATPrefix.Contains(addr) || publicProbeTailscaleULAPrefix.Contains(addr) {
		return 3
	}
	if addr.IsPrivate() {
		return 2
	}
	if addr.IsGlobalUnicast() {
		return 0
	}
	return 1
}

func externalDirectUDPEndpointKey(candidate string) string {
	_, port, err := net.SplitHostPort(candidate)
	if err != nil {
		return candidate
	}
	return port
}

func externalDirectUDPDedupeAndFill(selected []string, fallback []string) []string {
	out := append([]string(nil), selected...)
	seenEndpoint := make(map[string]int)
	for i, candidate := range out {
		if candidate == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(candidate)
		if existingIndex, ok := seenEndpoint[endpoint]; ok {
			if externalDirectUDPBetterCandidate(candidate, out[existingIndex]) {
				out[existingIndex] = ""
				seenEndpoint[endpoint] = i
				continue
			}
			out[i] = ""
			continue
		}
		seenEndpoint[endpoint] = i
	}
	for i, candidate := range out {
		if candidate != "" {
			continue
		}
		for _, replacement := range externalDirectUDPPreferWANStrings(fallback) {
			endpoint := externalDirectUDPEndpointKey(replacement)
			if replacement == "" {
				continue
			}
			if _, ok := seenEndpoint[endpoint]; ok {
				continue
			}
			out[i] = replacement
			seenEndpoint[endpoint] = i
			break
		}
	}
	return out
}

func externalDirectUDPPairs(conns []net.PacketConn, remoteAddrs []string) ([]net.PacketConn, []string) {
	limit := len(conns)
	if len(remoteAddrs) < limit {
		limit = len(remoteAddrs)
	}
	outConns := make([]net.PacketConn, 0, limit)
	outAddrs := make([]string, 0, limit)
	seenEndpoint := make(map[string]bool)
	for i := 0; i < limit; i++ {
		if conns[i] == nil || remoteAddrs[i] == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(remoteAddrs[i])
		if seenEndpoint[endpoint] {
			continue
		}
		seenEndpoint[endpoint] = true
		outConns = append(outConns, conns[i])
		outAddrs = append(outAddrs, remoteAddrs[i])
	}
	return outConns, outAddrs
}

func externalDirectUDPRateProbeRates(maxRateMbps int, totalBytes int64) []int {
	if maxRateMbps <= 0 || totalBytes < externalDirectUDPRateProbeMinBytes {
		return nil
	}
	bases := []int{150, 350, 700, 1200, maxRateMbps}
	out := make([]int, 0, len(bases))
	seen := make(map[int]bool)
	for _, rate := range bases {
		if rate < externalDirectUDPRateProbeMinMbps || rate > maxRateMbps || seen[rate] {
			continue
		}
		out = append(out, rate)
		seen[rate] = true
	}
	if len(out) == 0 {
		out = append(out, maxRateMbps)
	}
	return out
}

func externalDirectUDPSendRateProbes(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, rates []int) ([]directUDPRateProbeSample, error) {
	if len(rates) == 0 {
		return nil, nil
	}
	if len(conns) == 0 {
		return nil, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return nil, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	peers := make([]net.Addr, len(remoteAddrs))
	for i, addr := range remoteAddrs {
		peer, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		peers[i] = peer
	}
	samples := make([]directUDPRateProbeSample, len(rates))
	for i, rate := range rates {
		sent, err := externalDirectUDPSendRateProbe(ctx, conns, peers, i, rate)
		samples[i] = directUDPRateProbeSample{
			RateMbps:       rate,
			BytesSent:      sent,
			DurationMillis: externalDirectUDPRateProbeDuration.Milliseconds(),
		}
		if err != nil {
			return samples, err
		}
	}
	return samples, nil
}

func externalDirectUDPSendRateProbe(ctx context.Context, conns []net.PacketConn, peers []net.Addr, sampleIndex int, rateMbps int) (int64, error) {
	if rateMbps <= 0 {
		return 0, nil
	}
	laneRate := externalDirectUDPPerLaneRateMbps(rateMbps, len(conns))
	results := make(chan externalDirectUDPRateProbeSendResult, len(conns))
	startedAt := time.Now()
	deadline := startedAt.Add(externalDirectUDPRateProbeDuration)
	for i, conn := range conns {
		go func(conn net.PacketConn, peer net.Addr) {
			sent, err := externalDirectUDPSendRateProbeLane(ctx, conn, peer, sampleIndex, laneRate, startedAt, deadline)
			results <- externalDirectUDPRateProbeSendResult{bytes: sent, err: err}
		}(conn, peers[i])
	}
	var total int64
	var firstErr error
	for range conns {
		result := <-results
		total += result.bytes
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
	}
	return total, firstErr
}

type externalDirectUDPRateProbeSendResult struct {
	bytes int64
	err   error
}

func externalDirectUDPSendRateProbeLane(ctx context.Context, conn net.PacketConn, peer net.Addr, sampleIndex int, rateMbps int, startedAt time.Time, deadline time.Time) (int64, error) {
	packet := make([]byte, externalDirectUDPChunkSize)
	copy(packet, externalDirectUDPRateProbeMagic[:])
	binary.BigEndian.PutUint32(packet[16:20], uint32(sampleIndex))
	var sent int64
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		n, err := conn.WriteTo(packet, peer)
		if err != nil {
			return sent, err
		}
		sent += int64(n)
		if err := externalDirectUDPPace(ctx, startedAt, uint64(sent), rateMbps); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

func externalDirectUDPReceiveRateProbes(ctx context.Context, conns []net.PacketConn, rates []int) ([]directUDPRateProbeSample, error) {
	if len(rates) == 0 {
		return nil, nil
	}
	samples := make([]directUDPRateProbeSample, len(rates))
	for i, rate := range rates {
		samples[i] = directUDPRateProbeSample{
			RateMbps:       rate,
			DurationMillis: externalDirectUDPRateProbeDuration.Milliseconds(),
		}
	}
	if len(conns) == 0 {
		return samples, errors.New("no packet conns")
	}
	deadline := time.Now().Add(time.Duration(len(rates))*externalDirectUDPRateProbeDuration + externalDirectUDPRateProbeGrace)
	var mu sync.Mutex
	errCh := make(chan error, len(conns))
	var wg sync.WaitGroup
	for _, conn := range conns {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return samples, err
		}
		wg.Add(1)
		go func(conn net.PacketConn) {
			defer wg.Done()
			defer conn.SetReadDeadline(time.Time{})
			buf := make([]byte, externalDirectUDPChunkSize)
			for {
				n, _, err := conn.ReadFrom(buf)
				if err != nil {
					if externalDirectUDPIsNetTimeout(err) {
						return
					}
					if ctx.Err() != nil {
						errCh <- ctx.Err()
						return
					}
					errCh <- err
					return
				}
				index, ok := externalDirectUDPRateProbeIndex(buf[:n], len(samples))
				if !ok {
					continue
				}
				mu.Lock()
				samples[index].BytesReceived += int64(n)
				mu.Unlock()
			}
		}(conn)
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return samples, err
	default:
	}
	return samples, nil
}

func externalDirectUDPRateProbeIndex(packet []byte, samples int) (int, bool) {
	if len(packet) < 20 || samples <= 0 {
		return 0, false
	}
	if string(packet[:16]) != string(externalDirectUDPRateProbeMagic[:]) {
		return 0, false
	}
	index := int(binary.BigEndian.Uint32(packet[16:20]))
	if index < 0 || index >= samples {
		return 0, false
	}
	return index, true
}

func externalDirectUDPIsNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func externalDirectUDPSelectRateFromProbeSamples(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	if maxRateMbps <= 0 || len(sent) == 0 || len(received) == 0 {
		return maxRateMbps
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	type candidate struct {
		rate     int
		goodput  float64
		delivery float64
		score    float64
	}
	candidates := make([]candidate, 0, len(received))
	bestRate := 0
	bestGoodput := 0.0
	bestScore := 0.0
	bestDelivery := 0.0
	for _, sample := range received {
		durationMillis := sample.DurationMillis
		if durationMillis <= 0 {
			durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		}
		goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
		delivery := 0.0
		if sentSample, ok := sentByRate[sample.RateMbps]; ok && sentSample.BytesSent > 0 {
			delivery = float64(sample.BytesReceived) / float64(sentSample.BytesSent)
		}
		score := goodput
		if delivery > 0 && delivery < 0.90 {
			score *= delivery / 0.90
		}
		candidates = append(candidates, candidate{
			rate:     sample.RateMbps,
			goodput:  goodput,
			delivery: delivery,
			score:    score,
		})
		if score <= bestScore {
			continue
		}
		bestScore = score
		bestGoodput = goodput
		bestRate = sample.RateMbps
		bestDelivery = delivery
	}
	if bestRate <= 0 || bestGoodput <= 0 {
		return maxRateMbps
	}
	for i := 1; i < len(candidates); i++ {
		prev := candidates[i-1]
		current := candidates[i]
		efficiency := 0.0
		if current.rate > 0 {
			efficiency = current.goodput / float64(current.rate)
		}
		highThroughputKnee := current.goodput >= float64(maxRateMbps)*externalDirectUDPRateProbeHighShare && current.goodput >= prev.goodput*externalDirectUDPRateProbeHighGain
		if current.delivery >= 0.70 && current.goodput >= prev.goodput*0.75 && (efficiency >= 0.85 || highThroughputKnee) {
			continue
		}
		midProbeSoftLoss := current.rate < maxRateMbps && current.delivery >= 0.70 && current.goodput >= prev.goodput
		if midProbeSoftLoss {
			selected := prev.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		midProbeCollapseAfterCleanTier := current.rate < maxRateMbps && prev.delivery >= 0.90
		if midProbeCollapseAfterCleanTier {
			selected := prev.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		topProbeStillGaining := (i == len(candidates)-1 || current.rate == maxRateMbps) && current.delivery >= 0.98 && current.goodput >= prev.goodput*externalDirectUDPRateProbeHighGain
		if topProbeStillGaining {
			selected := int(current.goodput*1.15 + 0.5)
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		backoffIndex := i - 2
		if backoffIndex < 0 {
			backoffIndex = i - 1
		}
		selected := candidates[backoffIndex].rate
		if selected < externalDirectUDPRateProbeMinMbps {
			selected = externalDirectUDPRateProbeMinMbps
		}
		if selected > maxRateMbps {
			selected = maxRateMbps
		}
		return selected
	}
	selected := int(bestGoodput*1.15 + 0.5)
	if bestDelivery >= 0.90 {
		selected = bestRate
	}
	if selected < externalDirectUDPRateProbeMinMbps {
		selected = externalDirectUDPRateProbeMinMbps
	}
	if selected > maxRateMbps {
		selected = maxRateMbps
	}
	return selected
}

func externalDirectUDPSampleGoodputMbps(bytes int64, durationMillis int64) float64 {
	if bytes <= 0 || durationMillis <= 0 {
		return 0
	}
	return float64(bytes*8) / float64(durationMillis) / 1000
}

func externalDirectUDPFormatInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPFormatRateProbeSamples(sent []directUDPRateProbeSample, received []directUDPRateProbeSample) string {
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	parts := make([]string, 0, len(received))
	for _, sample := range received {
		durationMillis := sample.DurationMillis
		if durationMillis <= 0 {
			durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		}
		goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
		delivery := 0.0
		if sentSample, ok := sentByRate[sample.RateMbps]; ok && sentSample.BytesSent > 0 {
			delivery = float64(sample.BytesReceived) / float64(sentSample.BytesSent)
		}
		parts = append(parts, fmt.Sprintf("%d:rx=%d:goodput=%.2f:delivery=%.2f", sample.RateMbps, sample.BytesReceived, goodput, delivery))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPPace(ctx context.Context, startedAt time.Time, bytesSent uint64, rateMbps int) error {
	if rateMbps <= 0 || bytesSent == 0 {
		return nil
	}
	target := time.Duration((float64(bytesSent*8) / float64(rateMbps*1000*1000)) * float64(time.Second))
	sleepFor := time.Until(startedAt.Add(target))
	if sleepFor <= 0 {
		return nil
	}
	timer := time.NewTimer(sleepFor)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func externalDirectUDPOrderConnsForSections(conns []net.PacketConn, localCandidates []string, sectionAddrs []string) ([]net.PacketConn, error) {
	if len(sectionAddrs) == 0 {
		return conns, nil
	}
	endpointToConn := make(map[string]int)
	addEndpoint := func(endpoint string, index int) {
		if endpoint == "" || index < 0 || index >= len(conns) {
			return
		}
		if _, ok := endpointToConn[endpoint]; !ok {
			endpointToConn[endpoint] = index
		}
	}
	nextConn := 0
	for _, candidate := range localCandidates {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if endpoint == "" {
			continue
		}
		if _, ok := endpointToConn[endpoint]; ok {
			continue
		}
		addEndpoint(endpoint, nextConn)
		nextConn++
		if nextConn == len(conns) {
			break
		}
	}
	for i, conn := range conns {
		if conn == nil || conn.LocalAddr() == nil {
			continue
		}
		addEndpoint(externalDirectUDPEndpointKey(conn.LocalAddr().String()), i)
	}

	ordered := make([]net.PacketConn, 0, len(sectionAddrs))
	seen := make(map[int]bool)
	for _, addr := range sectionAddrs {
		endpoint := externalDirectUDPEndpointKey(addr)
		index, ok := endpointToConn[endpoint]
		if !ok {
			return nil, fmt.Errorf("direct UDP section address %q does not match a local lane", addr)
		}
		if seen[index] {
			return nil, fmt.Errorf("direct UDP section address %q duplicates local lane %d", addr, index)
		}
		seen[index] = true
		ordered = append(ordered, conns[index])
	}
	return ordered, nil
}

func externalDirectUDPFastDiscardReceiveConfig() probe.ReceiveConfig {
	return probe.ReceiveConfig{
		Blast:        true,
		Transport:    externalDirectUDPTransportLabel,
		FECGroupSize: externalDirectUDPFECGroupSize,
	}
}

func waitExternalDirectUDPAddr(ctx context.Context, conn net.PacketConn, manager *transport.Manager) (net.Addr, error) {
	if manager == nil {
		return nil, errors.New("nil transport manager")
	}
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if addr, active := manager.DirectAddr(); active && addr != nil {
			return addr, nil
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		}
	}
}

func externalDirectUDPWaitCanFallback(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded)
}

func emitExternalDirectUDPStats(emitter *telemetry.Emitter, prefix string, bytes int64, startedAt time.Time, firstByteAt time.Time, completedAt time.Time) {
	if emitter == nil || bytes <= 0 || startedAt.IsZero() || completedAt.IsZero() || !completedAt.After(startedAt) {
		return
	}
	duration := completedAt.Sub(startedAt)
	emitter.Debug(prefix + "-duration-ms=" + strconv.FormatInt(duration.Milliseconds(), 10))
	mbps := float64(bytes*8) / duration.Seconds() / 1_000_000
	emitter.Debug(prefix + "-goodput-mbps=" + strconv.FormatFloat(mbps, 'f', 2, 64))
	if firstByteAt.IsZero() || firstByteAt.Before(startedAt) || !completedAt.After(firstByteAt) {
		return
	}
	firstByteDelay := firstByteAt.Sub(startedAt)
	dataDuration := completedAt.Sub(firstByteAt)
	dataMbps := float64(bytes*8) / dataDuration.Seconds() / 1_000_000
	emitter.Debug(prefix + "-first-byte-ms=" + strconv.FormatInt(firstByteDelay.Milliseconds(), 10))
	emitter.Debug(prefix + "-data-duration-ms=" + strconv.FormatInt(dataDuration.Milliseconds(), 10))
	emitter.Debug(prefix + "-data-goodput-mbps=" + strconv.FormatFloat(dataMbps, 'f', 2, 64))
}

func emitExternalDirectUDPReceiveStartDebug(emitter *telemetry.Emitter, expectedBytes int64) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-fast-discard-expected-bytes=" + strconv.FormatInt(expectedBytes, 10))
}

func emitExternalDirectUDPReceiveResultDebug(emitter *telemetry.Emitter, stats probe.TransferStats, err error) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-receive-bytes=" + strconv.FormatInt(stats.BytesReceived, 10))
	if err != nil {
		emitter.Debug("udp-receive-error=" + err.Error())
	}
}

func waitForDirectUDPReady(ctx context.Context, readyCh <-chan derpbind.Packet) error {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()
	_, err := receiveSubscribedPacket(waitCtx, readyCh)
	return err
}

func waitForDirectUDPReadyAck(ctx context.Context, readyAckCh <-chan derpbind.Packet) (directUDPReadyAck, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, readyAckCh)
	if err != nil {
		return directUDPReadyAck{}, err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPReadyAck {
		return directUDPReadyAck{}, errors.New("unexpected direct UDP ready ack")
	}
	if env.DirectUDPReadyAck == nil {
		return directUDPReadyAck{}, nil
	}
	return *env.DirectUDPReadyAck, nil
}

func waitForDirectUDPStart(ctx context.Context, startCh <-chan derpbind.Packet) (directUDPStart, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, startCh)
	if err != nil {
		return directUDPStart{}, err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPStart {
		return directUDPStart{}, errors.New("unexpected direct UDP start")
	}
	if env.DirectUDPStart == nil {
		return directUDPStart{}, nil
	}
	return *env.DirectUDPStart, nil
}

func waitForDirectUDPStartAck(ctx context.Context, startAckCh <-chan derpbind.Packet) error {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, startAckCh)
	if err != nil {
		return err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPStartAck {
		return errors.New("unexpected direct UDP start ack")
	}
	return nil
}

func waitForDirectUDPRateProbeResult(ctx context.Context, rateProbeCh <-chan derpbind.Packet, samples int) (directUDPRateProbeResult, error) {
	wait := externalDirectUDPStartWait
	if samples > 0 {
		wait = time.Duration(samples)*externalDirectUDPRateProbeDuration + 5*time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, rateProbeCh)
	if err != nil {
		return directUDPRateProbeResult{}, err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPRateProbe {
		return directUDPRateProbeResult{}, errors.New("unexpected direct UDP rate probe result")
	}
	if env.DirectUDPRateProbe == nil {
		return directUDPRateProbeResult{}, nil
	}
	return *env.DirectUDPRateProbe, nil
}

func isDirectUDPReadyPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPReady
}

func isDirectUDPStartPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPStart
}

func isDirectUDPStartAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPStartAck
}

func isDirectUDPRateProbePayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPRateProbe
}

type externalDirectUDPDiscardSendResult struct {
	stats probe.TransferStats
	err   error
}

type externalDirectUDPReceiveResult struct {
	stats probe.TransferStats
	err   error
}

type externalDirectUDPDiscardSpool struct {
	File       *os.File
	Path       string
	Offsets    []int64
	Sizes      []int64
	TotalBytes int64
}

func (s *externalDirectUDPDiscardSpool) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.File != nil {
		if err := s.File.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.Path != "" {
		if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func externalDirectUDPSpoolDiscardLanes(ctx context.Context, src io.Reader, lanes int, chunkSize int) (*externalDirectUDPDiscardSpool, error) {
	if lanes <= 0 {
		return nil, errors.New("no discard spool lanes")
	}
	if src == nil {
		return nil, errors.New("nil source reader")
	}
	if chunkSize <= 0 {
		chunkSize = externalDirectUDPChunkSize
	}
	file, err := os.CreateTemp("", "derpcat-discard-spool-*")
	if err != nil {
		return nil, err
	}
	spool := &externalDirectUDPDiscardSpool{
		File:    file,
		Path:    file.Name(),
		Offsets: make([]int64, lanes),
		Sizes:   make([]int64, lanes),
	}
	buf := make([]byte, chunkSize*128)
	for {
		if err := ctx.Err(); err != nil {
			_ = spool.Close()
			return nil, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			written, err := spool.File.Write(buf[:n])
			if err != nil {
				_ = spool.Close()
				return nil, err
			}
			if written != n {
				_ = spool.Close()
				return nil, io.ErrShortWrite
			}
			spool.TotalBytes += int64(written)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = spool.Close()
			return nil, readErr
		}
		if n == 0 {
			select {
			case <-ctx.Done():
				_ = spool.Close()
				return nil, ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}
	base := spool.TotalBytes / int64(lanes)
	extra := spool.TotalBytes % int64(lanes)
	var offset int64
	for i := range spool.Sizes {
		size := base
		if int64(i) < extra {
			size++
		}
		spool.Offsets[i] = offset
		spool.Sizes[i] = size
		offset += size
	}
	return spool, nil
}

func externalDirectUDPSendDiscardSpoolParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, spool *externalDirectUDPDiscardSpool, cfg probe.SendConfig) (probe.TransferStats, error) {
	if spool == nil {
		return probe.TransferStats{}, errors.New("nil discard spool")
	}
	if len(conns) == 0 {
		return probe.TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return probe.TransferStats{}, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if spool.File == nil {
		return probe.TransferStats{}, errors.New("nil discard spool file")
	}
	if len(spool.Sizes) < len(conns) || len(spool.Offsets) < len(conns) {
		return probe.TransferStats{}, fmt.Errorf("discard spool lane count %d is less than packet conn count %d", len(spool.Sizes), len(conns))
	}
	cfg.StripedBlast = false
	cfg.Parallel = 1
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = externalDirectUDPChunkSize
	}
	laneRate := externalDirectUDPPerLaneRateMbps(cfg.RateMbps, len(conns))
	startedAt := time.Now()
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		laneCfg := cfg
		laneCfg.RunID = externalDirectUDPDiscardLaneRunID(cfg.RunID, i)
		laneCfg.RateMbps = laneRate
		src := io.NewSectionReader(spool.File, spool.Offsets[i], spool.Sizes[i])
		go func(conn net.PacketConn, remoteAddr string, src io.Reader, laneCfg probe.SendConfig) {
			stats, err := probe.Send(ctx, conn, remoteAddr, src, laneCfg)
			results <- externalDirectUDPDiscardSendResult{stats: stats, err: err}
		}(conn, remoteAddrs[i], src, laneCfg)
	}
	stats := probe.TransferStats{StartedAt: startedAt, Lanes: len(conns)}
	var sendErr error
	for range conns {
		result := <-results
		if result.err != nil && sendErr == nil {
			sendErr = result.err
		}
		externalDirectUDPMergeSendStats(&stats, result.stats)
	}
	stats.CompletedAt = time.Now()
	if sendErr != nil {
		return probe.TransferStats{}, sendErr
	}
	if stats.FirstByteAt.IsZero() && stats.BytesSent > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
}

type externalDirectUDPOffsetWriter struct {
	file   *os.File
	offset int64
}

func (w *externalDirectUDPOffsetWriter) Write(p []byte) (int, error) {
	if w == nil || w.file == nil {
		return 0, errors.New("nil offset writer")
	}
	n, err := w.file.WriteAt(p, w.offset)
	w.offset += int64(n)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func externalDirectUDPReceiveSectionSpoolParallel(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg probe.ReceiveConfig, totalBytes int64, sectionSizes []int64) (probe.TransferStats, error) {
	if len(conns) == 0 {
		return probe.TransferStats{}, errors.New("no packet conns")
	}
	if totalBytes < 0 {
		return probe.TransferStats{}, errors.New("negative expected bytes")
	}
	sizes, offsets, err := externalDirectUDPReceiveSectionLayout(totalBytes, len(conns), sectionSizes)
	if err != nil {
		return probe.TransferStats{}, err
	}
	conns = conns[:len(sizes)]
	if dst == nil {
		dst = io.Discard
	}
	file, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(dst, totalBytes)
	if err != nil {
		return probe.TransferStats{}, err
	}
	defer cleanup()

	receiveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan externalDirectUDPReceiveResult, len(conns))
	startedAt := time.Now()
	for i, conn := range conns {
		laneCfg := cfg
		if len(laneCfg.ExpectedRunIDs) == len(conns) {
			laneCfg.ExpectedRunID = laneCfg.ExpectedRunIDs[i]
			laneCfg.ExpectedRunIDs = nil
		} else if len(laneCfg.ExpectedRunIDs) == 0 {
			laneCfg.ExpectedRunID = [16]byte{}
		}
		laneCfg.RequireComplete = true
		writer := &externalDirectUDPOffsetWriter{file: file, offset: offsets[i]}
		go func(conn net.PacketConn, writer io.Writer, expected int64, laneCfg probe.ReceiveConfig) {
			stats, err := probe.ReceiveBlastParallelToWriter(receiveCtx, []net.PacketConn{conn}, writer, laneCfg, expected)
			if err != nil {
				cancel()
			}
			results <- externalDirectUDPReceiveResult{stats: stats, err: err}
		}(conn, writer, sizes[i], laneCfg)
	}

	stats := probe.TransferStats{StartedAt: startedAt, Lanes: len(conns)}
	var receiveErr error
	for range conns {
		result := <-results
		if result.err != nil && receiveErr == nil {
			receiveErr = result.err
		}
		externalDirectUDPMergeReceiveStats(&stats, result.stats)
	}
	if receiveErr != nil {
		stats.CompletedAt = time.Now()
		if stats.FirstByteAt.IsZero() && stats.BytesReceived > 0 {
			stats.FirstByteAt = startedAt
		}
		return stats, receiveErr
	}
	if err := externalDirectUDPFinishSectionTarget(file, copyToDst, dst, totalBytes); err != nil {
		stats.CompletedAt = time.Now()
		return stats, err
	}
	stats.CompletedAt = time.Now()
	if stats.FirstByteAt.IsZero() && stats.BytesReceived > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
}

func externalDirectUDPReceiveSectionTarget(dst io.Writer, totalBytes int64) (*os.File, bool, func(), error) {
	if file := externalDirectUDPRegularFileWriter(dst); file != nil {
		if totalBytes > 0 {
			if err := file.Truncate(totalBytes); err != nil {
				return nil, false, nil, err
			}
		}
		return file, false, func() {}, nil
	}
	file, err := os.CreateTemp("", "derpcat-receive-spool-*")
	if err != nil {
		return nil, false, nil, err
	}
	path := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	return file, true, cleanup, nil
}

func externalDirectUDPSectionWriterForTarget(dst io.Writer, buffered io.Writer, flush func() error) (io.Writer, func() error) {
	if file := externalDirectUDPRegularFileWriter(dst); file != nil {
		return file, func() error { return nil }
	}
	if buffered == nil {
		buffered = dst
	}
	if flush == nil {
		flush = func() error { return nil }
	}
	return buffered, flush
}

func externalDirectUDPRegularFileWriter(dst io.Writer) *os.File {
	file := externalDirectUDPFileWriter(dst)
	if file == nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return file
}

func externalDirectUDPFileWriter(dst io.Writer) *os.File {
	switch writer := dst.(type) {
	case *os.File:
		return writer
	case nopWriteCloser:
		return externalDirectUDPFileWriter(writer.Writer)
	case *nopWriteCloser:
		if writer == nil {
			return nil
		}
		return externalDirectUDPFileWriter(writer.Writer)
	default:
		return nil
	}
}

func externalDirectUDPFinishSectionTarget(file *os.File, copyToDst bool, dst io.Writer, totalBytes int64) error {
	if file == nil || totalBytes <= 0 {
		return nil
	}
	if !copyToDst {
		_, err := file.Seek(totalBytes, io.SeekStart)
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	written, err := io.CopyN(dst, file, totalBytes)
	if err != nil {
		return err
	}
	if written != totalBytes {
		return io.ErrShortWrite
	}
	return nil
}

func externalDirectUDPReceiveSectionLayout(totalBytes int64, connCount int, sectionSizes []int64) ([]int64, []int64, error) {
	if connCount <= 0 {
		return nil, nil, errors.New("no packet conns")
	}
	if len(sectionSizes) == 0 {
		sizes, offsets := externalDirectUDPSectionSizes(totalBytes, connCount)
		return sizes, offsets, nil
	}
	if len(sectionSizes) > connCount {
		return nil, nil, fmt.Errorf("direct UDP start section count %d exceeds receiver lane count %d", len(sectionSizes), connCount)
	}
	sizes := append([]int64(nil), sectionSizes...)
	offsets := make([]int64, len(sizes))
	var offset int64
	for i, size := range sizes {
		if size < 0 {
			return nil, nil, fmt.Errorf("negative direct UDP section size at lane %d", i)
		}
		offsets[i] = offset
		offset += size
	}
	if offset != totalBytes {
		return nil, nil, fmt.Errorf("direct UDP section sizes total %d bytes, want %d", offset, totalBytes)
	}
	return sizes, offsets, nil
}

func externalDirectUDPSectionSizes(totalBytes int64, lanes int) ([]int64, []int64) {
	if lanes <= 0 {
		return nil, nil
	}
	sizes := make([]int64, lanes)
	offsets := make([]int64, lanes)
	base := totalBytes / int64(lanes)
	extra := totalBytes % int64(lanes)
	var offset int64
	for i := range sizes {
		size := base
		if int64(i) < extra {
			size++
		}
		offsets[i] = offset
		sizes[i] = size
		offset += size
	}
	return sizes, offsets
}

func externalDirectUDPSendDiscardParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, src io.Reader, cfg probe.SendConfig) (probe.TransferStats, error) {
	if len(conns) == 0 {
		return probe.TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return probe.TransferStats{}, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if src == nil {
		return probe.TransferStats{}, errors.New("nil source reader")
	}
	cfg.StripedBlast = false
	cfg.Parallel = 1
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = externalDirectUDPChunkSize
	}
	if len(conns) == 1 {
		cfg.RunID = externalDirectUDPLaneRunID(cfg.RunID, 0)
		return probe.Send(ctx, conns[0], remoteAddrs[0], src, cfg)
	}

	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	startedAt := time.Now()
	laneRate := externalDirectUDPPerLaneRateMbps(cfg.RateMbps, len(conns))
	writers := make([]*io.PipeWriter, len(conns))
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		reader, writer := io.Pipe()
		writers[i] = writer
		remoteAddr := remoteAddrs[i]
		laneCfg := cfg
		laneCfg.RunID = externalDirectUDPLaneRunID(cfg.RunID, i)
		laneCfg.RateMbps = laneRate
		go func(conn net.PacketConn, remoteAddr string, reader *io.PipeReader, laneCfg probe.SendConfig) {
			defer reader.Close()
			stats, err := probe.Send(sendCtx, conn, remoteAddr, reader, laneCfg)
			if err != nil {
				cancel()
			}
			results <- externalDirectUDPDiscardSendResult{stats: stats, err: err}
		}(conn, remoteAddr, reader, laneCfg)
	}

	dispatchErr := externalDirectUDPDistributeDiscardStream(sendCtx, src, writers, cfg.ChunkSize)
	for _, writer := range writers {
		if dispatchErr != nil {
			_ = writer.CloseWithError(dispatchErr)
			continue
		}
		_ = writer.Close()
	}

	stats := probe.TransferStats{StartedAt: startedAt, Lanes: len(conns)}
	var sendErr error
	for range conns {
		result := <-results
		if result.err != nil && sendErr == nil {
			sendErr = result.err
		}
		externalDirectUDPMergeSendStats(&stats, result.stats)
	}
	stats.CompletedAt = time.Now()
	if dispatchErr != nil {
		return probe.TransferStats{}, dispatchErr
	}
	if sendErr != nil {
		return probe.TransferStats{}, sendErr
	}
	if stats.FirstByteAt.IsZero() && stats.BytesSent > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
}

func externalDirectUDPLaneRunIDs(base [16]byte, lanes int) [][16]byte {
	if lanes <= 0 {
		return nil
	}
	out := make([][16]byte, lanes)
	for i := range out {
		out[i] = externalDirectUDPLaneRunID(base, i)
	}
	return out
}

func externalDirectUDPDiscardLaneRunID(base [16]byte, lane int) [16]byte {
	if base == ([16]byte{}) {
		return base
	}
	return externalDirectUDPLaneRunID(base, lane)
}

func externalDirectUDPStopPunchingForBlast(cancel context.CancelFunc) {
	// The blast keeps NAT mappings warm. Extra keepalive punches on the data sockets can backlog receivers.
	cancel()
}

func externalDirectUDPLaneRunID(base [16]byte, lane int) [16]byte {
	runID := base
	if lane < 0 {
		lane = 0
	}
	lane++
	runID[14] ^= byte(lane >> 8)
	runID[15] ^= byte(lane)
	return runID
}

func externalDirectUDPDistributeDiscardStream(ctx context.Context, src io.Reader, writers []*io.PipeWriter, chunkSize int) error {
	if len(writers) == 0 {
		return errors.New("no pipe writers")
	}
	if chunkSize <= 0 {
		chunkSize = externalDirectUDPChunkSize
	}
	distCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var writerErrMu sync.Mutex
	var writerErr error
	setWriterErr := func(err error) {
		if err == nil {
			return
		}
		writerErrMu.Lock()
		if writerErr == nil {
			writerErr = err
		}
		writerErrMu.Unlock()
		cancel()
	}
	currentWriterErr := func() error {
		writerErrMu.Lock()
		defer writerErrMu.Unlock()
		return writerErr
	}
	closeWritersWithError := func(err error) {
		for _, writer := range writers {
			if writer != nil {
				_ = writer.CloseWithError(err)
			}
		}
	}
	queues := make([]chan []byte, len(writers))
	writerDone := make(chan error, len(writers))
	for i, writer := range writers {
		queue := make(chan []byte, externalDirectUDPDiscardQueue)
		queues[i] = queue
		go func(writer *io.PipeWriter, queue <-chan []byte) {
			for chunk := range queue {
				if len(chunk) == 0 {
					continue
				}
				if _, err := writer.Write(chunk); err != nil {
					setWriterErr(err)
					writerDone <- err
					return
				}
			}
			writerDone <- nil
		}(writer, queue)
	}
	var closeQueuesOnce sync.Once
	closeQueues := func() {
		closeQueuesOnce.Do(func() {
			for _, queue := range queues {
				close(queue)
			}
		})
	}
	waitWriters := func() error {
		var firstErr error
		for range writers {
			if err := <-writerDone; err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return firstErr
		}
		return currentWriterErr()
	}
	fail := func(err error) error {
		closeWritersWithError(err)
		closeQueues()
		if writerWaitErr := waitWriters(); writerWaitErr != nil && err == nil {
			return writerWaitErr
		}
		return err
	}

	buf := make([]byte, chunkSize*128)
	lane := 0
	for {
		if err := distCtx.Err(); err != nil {
			if writerErr := currentWriterErr(); writerErr != nil {
				return fail(writerErr)
			}
			return fail(err)
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			select {
			case queues[lane] <- chunk:
				lane = (lane + 1) % len(writers)
			case <-distCtx.Done():
				if writerErr := currentWriterErr(); writerErr != nil {
					return fail(writerErr)
				}
				return fail(distCtx.Err())
			}
		}
		if errors.Is(readErr, io.EOF) {
			closeQueues()
			return waitWriters()
		}
		if readErr != nil {
			return fail(readErr)
		}
		if n == 0 {
			select {
			case <-distCtx.Done():
				if writerErr := currentWriterErr(); writerErr != nil {
					return fail(writerErr)
				}
				return fail(distCtx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
}

func externalDirectUDPPerLaneRateMbps(totalRateMbps int, lanes int) int {
	if totalRateMbps <= 0 || lanes <= 1 {
		return totalRateMbps
	}
	rate := totalRateMbps / lanes
	if rate < 1 {
		return 1
	}
	return rate
}

func externalDirectUDPRateMbpsForLanes(maxRateMbps int, lanes int) int {
	if maxRateMbps <= 0 || lanes >= externalDirectUDPParallelism {
		return maxRateMbps
	}
	if lanes <= 0 {
		return 0
	}
	return externalDirectUDPPerLaneRateMbps(maxRateMbps, externalDirectUDPParallelism) * lanes
}

func externalDirectUDPMergeSendStats(dst *probe.TransferStats, src probe.TransferStats) {
	dst.BytesSent += src.BytesSent
	dst.PacketsSent += src.PacketsSent
	dst.PacketsAcked += src.PacketsAcked
	dst.Retransmits += src.Retransmits
	if !src.FirstByteAt.IsZero() && (dst.FirstByteAt.IsZero() || src.FirstByteAt.Before(dst.FirstByteAt)) {
		dst.FirstByteAt = src.FirstByteAt
	}
	if dst.Transport.Kind == "" {
		dst.Transport = src.Transport
	}
}

func externalDirectUDPMergeReceiveStats(dst *probe.TransferStats, src probe.TransferStats) {
	dst.BytesReceived += src.BytesReceived
	dst.PacketsSent += src.PacketsSent
	dst.PacketsAcked += src.PacketsAcked
	dst.Retransmits += src.Retransmits
	if !src.FirstByteAt.IsZero() && (dst.FirstByteAt.IsZero() || src.FirstByteAt.Before(dst.FirstByteAt)) {
		dst.FirstByteAt = src.FirstByteAt
	}
	if dst.Transport.Kind == "" {
		dst.Transport = src.Transport
	}
}

func sendExternalRelayUDP(ctx context.Context, src io.Reader, manager *transport.Manager, runID [16]byte, emitter *telemetry.Emitter) error {
	if emitter != nil {
		emitter.Debug("udp-relay=true")
	}
	peerConn := manager.PeerDatagramConn(ctx)
	packetConn := newExternalPeerDatagramPacketConn(ctx, peerConn)
	defer packetConn.Close()
	_, err := probe.Send(ctx, packetConn, packetConn.remoteAddr.String(), externalDirectUDPBufferedReader(src), probe.SendConfig{
		Raw:        true,
		Transport:  "legacy",
		ChunkSize:  externalDirectUDPChunkSize,
		WindowSize: 4096,
		RunID:      runID,
	})
	return err
}

func receiveExternalRelayUDP(ctx context.Context, dst io.Writer, manager *transport.Manager, runID [16]byte, emitter *telemetry.Emitter) error {
	if emitter != nil {
		emitter.Debug("udp-relay=true")
	}
	peerConn := manager.PeerDatagramConn(ctx)
	packetConn := newExternalPeerDatagramPacketConn(ctx, peerConn)
	defer packetConn.Close()
	receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
	_, err := probe.ReceiveToWriter(ctx, packetConn, "", receiveDst, probe.ReceiveConfig{
		Raw:           true,
		ExpectedRunID: runID,
	})
	if err == nil {
		err = flushDst()
	}
	return err
}

func externalDirectUDPBufferedReader(src io.Reader) io.Reader {
	if src == nil {
		return nil
	}
	if _, ok := src.(*bufio.Reader); ok {
		return src
	}
	return bufio.NewReaderSize(src, externalDirectUDPBufferSize)
}

func externalDirectUDPBufferedWriter(dst io.Writer) (io.Writer, func() error) {
	if dst == nil {
		return io.Discard, func() error { return nil }
	}
	if externalDirectUDPWriterIsNullDevice(dst) {
		return io.Discard, func() error { return nil }
	}
	if buffered, ok := dst.(*bufio.Writer); ok {
		return buffered, buffered.Flush
	}
	buffered := bufio.NewWriterSize(dst, externalDirectUDPBufferSize)
	return buffered, buffered.Flush
}

func externalDirectUDPWriterIsNullDevice(dst io.Writer) bool {
	switch writer := dst.(type) {
	case nopWriteCloser:
		return externalDirectUDPWriterIsNullDevice(writer.Writer)
	case *nopWriteCloser:
		if writer == nil {
			return false
		}
		return externalDirectUDPWriterIsNullDevice(writer.Writer)
	case *os.File:
		return externalDirectUDPFileIsNullDevice(writer)
	default:
		return false
	}
}

func externalDirectUDPFileIsNullDevice(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return false
	}
	defer devNull.Close()
	nullInfo, err := devNull.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(info, nullInfo)
}

type externalPeerDatagramPacketConn struct {
	ctx        context.Context
	peer       transport.PeerDatagramConn
	remoteAddr net.Addr

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newExternalPeerDatagramPacketConn(ctx context.Context, peer transport.PeerDatagramConn) *externalPeerDatagramPacketConn {
	remoteAddr := peer.RemoteAddr()
	if remoteAddr == nil {
		remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	}
	return &externalPeerDatagramPacketConn{
		ctx:        ctx,
		peer:       peer,
		remoteAddr: remoteAddr,
	}
}

func (c *externalPeerDatagramPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	readCtx := c.ctx
	deadline := c.currentReadDeadline()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithDeadline(readCtx, deadline)
		defer cancel()
	}
	payload, _, err := c.peer.RecvDatagram(readCtx)
	if err != nil {
		return 0, nil, err
	}
	defer c.peer.ReleaseDatagram(payload)
	return copy(b, payload), c.remoteAddr, nil
}

func (c *externalPeerDatagramPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if deadline := c.currentWriteDeadline(); !deadline.IsZero() && time.Now().After(deadline) {
		return 0, context.DeadlineExceeded
	}
	if err := c.peer.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *externalPeerDatagramPacketConn) Close() error {
	return c.peer.Close()
}

func (c *externalPeerDatagramPacketConn) LocalAddr() net.Addr {
	return c.peer.LocalAddr()
}

func (c *externalPeerDatagramPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *externalPeerDatagramPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *externalPeerDatagramPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func (c *externalPeerDatagramPacketConn) currentReadDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline
}

func (c *externalPeerDatagramPacketConn) currentWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline
}
