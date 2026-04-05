package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derpcat/pkg/quicpath"
	"github.com/shayne/derpcat/pkg/telemetry"
	"tailscale.com/tailcfg"
)

type externalNativeQUICConnResult struct {
	conn   *quic.Conn
	dialed bool
	err    error
}

type externalNativeQUICStreamResult struct {
	index  int
	stream *quic.Stream
	err    error
}

type externalNativeQUICStripeConnResult struct {
	index      int
	peerAddr   net.Addr
	transport  *quic.Transport
	conn       *quic.Conn
	openStream bool
	err        error
}

var errExternalNativeQUICNoMatchingStripeCandidate = errors.New("no matching native QUIC stripe candidate")

const externalNativeQUICDuplicateConnWait = 250 * time.Millisecond
const externalNativeQUICStreamOpenByte = byte(1)

var externalNativeQUICStripeProbeCandidates = publicProbeCandidates
var externalNativeQUICStripeCanUseLocalAddrCandidate = externalNativeQUICStripeCanUseLocalAddrCandidateDefault

type externalNativeQUICStripedSession struct {
	setupFallback bool
	packetConns   []net.PacketConn
	transports    []*quic.Transport
	conns         []*quic.Conn
	openStreams   []bool
	portmaps      []publicPortmap
	primaryStream *quic.Stream
}

type externalNativeQUICStripeSetup struct {
	CandidateSets [][]string `json:"candidate_sets"`
}

type externalNativeQUICStripeSetupResult struct {
	Ready bool `json:"ready"`
}

func (s *externalNativeQUICStripedSession) Close() {
	if s == nil {
		return
	}
	closeExternalNativeQUICConns(s.conns)
	for _, transport := range s.transports {
		_ = transport.Close()
	}
	for _, pm := range s.portmaps {
		_ = pm.Close()
	}
	for _, packetConn := range s.packetConns {
		_ = packetConn.Close()
	}
}

func (s *externalNativeQUICStripedSession) OpenStreams(ctx context.Context) ([]io.WriteCloser, error) {
	streams, err := s.OpenReadWriteStreams(ctx)
	if err != nil {
		return nil, err
	}
	writers := make([]io.WriteCloser, 0, len(streams))
	for _, stream := range streams {
		writers = append(writers, stream)
	}
	return writers, nil
}

func (s *externalNativeQUICStripedSession) OpenReadWriteStreams(ctx context.Context) ([]io.ReadWriteCloser, error) {
	streams, err := s.OpenQUICStreams(ctx)
	if err != nil {
		return nil, err
	}
	rwStreams := make([]io.ReadWriteCloser, 0, len(streams))
	for _, stream := range streams {
		rwStreams = append(rwStreams, stream)
	}
	return rwStreams, nil
}

func (s *externalNativeQUICStripedSession) OpenQUICStreams(ctx context.Context) ([]*quic.Stream, error) {
	if s.primaryStream != nil {
		externalTransferTracef("native-quic-open-streams-primary-reuse")
		return []*quic.Stream{s.primaryStream}, nil
	}
	externalTransferTracef("native-quic-open-streams-start conns=%d", len(s.conns))
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	results := make(chan externalNativeQUICStreamResult, len(s.conns))
	for i, conn := range s.conns {
		i := i
		conn := conn
		openStream := externalNativeQUICStreamRole(s.openStreams, i)
		go func() {
			externalTransferTracef("native-quic-open-stream-start index=%d", i)
			stream, err := openExternalNativeQUICStreamForConn(streamCtx, conn, openStream)
			results <- externalNativeQUICStreamResult{
				index:  i,
				stream: stream,
				err:    err,
			}
		}()
	}

	streams := make([]*quic.Stream, len(s.conns))
	var firstErr error
	for range s.conns {
		result := <-results
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
				streamCancel()
			}
			continue
		}
		streams[result.index] = result.stream
		externalTransferTracef("native-quic-open-stream-complete index=%d", result.index)
	}
	if firstErr != nil {
		for _, stream := range streams {
			if stream != nil {
				_ = stream.Close()
			}
		}
		return nil, firstErr
	}
	externalTransferTracef("native-quic-open-streams-complete conns=%d", len(streams))
	return streams, nil
}

func dialExternalNativeQUICStripedConns(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	dm *tailcfg.DERPMap,
	emitter *telemetry.Emitter,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	connCount int,
) (*externalNativeQUICStripedSession, error) {
	connCount = externalNativeQUICConnCountForPeer(peerAddr, connCount)
	externalTransferTracef("native-quic-dial-striped-start peer=%v conns=%d", peerAddr, connCount)
	if connCount < 1 {
		return nil, errors.New("native QUIC connection count must be positive")
	}
	if connCount > 1 && externalNativeQUICStripeShouldReusePrimaryPacketConn(peerAddr) {
		transport, conns, openStreams, err := dialOrAcceptExternalNativeQUICConnsWithStreamRole(
			ctx,
			packetConn,
			peerAddr,
			clientTLS,
			serverTLS,
			connCount,
			true,
		)
		if err != nil {
			return nil, err
		}
		if emitter != nil {
			emitter.Debug(fmt.Sprintf("native-quic-stripes=%d", len(conns)))
		}
		return &externalNativeQUICStripedSession{
			packetConns: []net.PacketConn{packetConn},
			transports:  []*quic.Transport{transport},
			conns:       conns,
			openStreams: externalNativeQUICStreamRoles(len(conns), openStreams),
		}, nil
	}

	primaryTransport, primaryConn, openPrimaryStream, err := dialOrAcceptExternalNativeQUICConnWithRole(
		ctx,
		packetConn,
		peerAddr,
		clientTLS,
		serverTLS,
		true,
	)
	if err != nil {
		return nil, err
	}
	externalTransferTracef("native-quic-dial-primary-ready")
	session := &externalNativeQUICStripedSession{
		packetConns: []net.PacketConn{packetConn},
		transports:  []*quic.Transport{primaryTransport},
		conns:       []*quic.Conn{primaryConn},
		openStreams: []bool{openPrimaryStream},
	}
	if connCount == 1 {
		if emitter != nil {
			emitter.Debug("native-quic-primary-only")
		}
		return session, nil
	}

	controlOpenCtx, controlOpenCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	controlStream, err := openExternalNativeQUICStreamForConn(controlOpenCtx, primaryConn, openPrimaryStream)
	controlOpenCancel()
	if err != nil {
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=open-control-stream")
		}
		session.setupFallback = true
		return session, nil
	}
	externalTransferTracef("native-quic-dial-control-open")
	cancelControlStreamDeadline := cancelExternalNativeQUICControlStreamDeadlineOnContextDone(ctx, controlStream)
	defer cancelControlStreamDeadline()
	keepControlStream := false
	defer func() {
		if keepControlStream {
			return
		}
		_ = controlStream.SetDeadline(time.Time{})
		_ = controlStream.Close()
	}()

	localPacketConns, localPortmaps, localCandidateSets, err := openExternalNativeQUICStripePacketConns(ctx, peerAddr, dm, emitter, connCount-1)
	if err != nil {
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=open-stripe-sockets")
		}
		session.setupFallback = true
		return session, nil
	}
	externalTransferTracef("native-quic-dial-stripe-candidates-ready stripes=%d", len(localPacketConns))
	if err := ctx.Err(); err != nil {
		closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
		session.setupFallback = true
		session.primaryStream = controlStream
		keepControlStream = true
		return session, err
	}

	_ = controlStream.SetDeadline(time.Now().Add(externalNativeQUICWait))
	if err := json.NewEncoder(controlStream).Encode(externalNativeQUICStripeSetup{CandidateSets: localCandidateSets}); err != nil {
		closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=encode-stripe-setup")
		}
		session.setupFallback = true
		session.primaryStream = controlStream
		keepControlStream = true
		return session, nil
	}
	var peerSetup externalNativeQUICStripeSetup
	externalTransferTracef("native-quic-dial-peer-stripe-setup-wait")
	if err := json.NewDecoder(controlStream).Decode(&peerSetup); err != nil {
		closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=decode-stripe-setup")
		}
		session.setupFallback = true
		session.primaryStream = controlStream
		keepControlStream = true
		return session, nil
	}
	externalTransferTracef("native-quic-dial-peer-stripe-setup-received stripes=%d", len(peerSetup.CandidateSets))
	stripeCount := min(len(localPacketConns), len(peerSetup.CandidateSets))
	if stripeCount < len(localPacketConns) {
		closeExternalNativeQUICStripePacketConns(localPacketConns[stripeCount:], localPortmaps[stripeCount:])
		localPacketConns = localPacketConns[:stripeCount]
		localPortmaps = localPortmaps[:stripeCount]
	}
	if stripeCount == 0 {
		closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=stripe-setup-size")
		}
		session.setupFallback = true
		session.primaryStream = controlStream
		keepControlStream = true
		return session, nil
	}
	_ = controlStream.SetDeadline(time.Time{})

	extraSetupCtx, extraSetupCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer extraSetupCancel()

	extraTransports, extraConns, extraOpenStreams, stripeReady := openExternalNativeQUICStripeConns(
		extraSetupCtx,
		peerAddr,
		localPacketConns,
		peerSetup.CandidateSets,
		clientTLS,
		serverTLS,
		true,
		"native-quic-dial-stripe-ready",
		"native-quic-primary-fallback=dial-stripe-conn err=",
		emitter,
	)
	_ = controlStream.SetDeadline(time.Now().Add(externalNativeQUICWait))
	if err := json.NewEncoder(controlStream).Encode(externalNativeQUICStripeSetupResult{Ready: stripeReady}); err != nil {
		closeExternalNativeQUICConns(extraConns)
		for _, transport := range extraTransports {
			_ = transport.Close()
		}
		closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=encode-stripe-ready")
		}
		session.setupFallback = true
		session.primaryStream = controlStream
		keepControlStream = true
		return session, nil
	}
	var peerReady externalNativeQUICStripeSetupResult
	if err := json.NewDecoder(controlStream).Decode(&peerReady); err != nil || !stripeReady || !peerReady.Ready {
		closeExternalNativeQUICConns(extraConns)
		for _, transport := range extraTransports {
			_ = transport.Close()
		}
		closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
		if emitter != nil {
			emitter.Debug("native-quic-primary-fallback=final")
		}
		session.setupFallback = true
		session.primaryStream = controlStream
		keepControlStream = true
		return session, nil
	}
	externalTransferTracef("native-quic-dial-striped-ready conns=%d", len(session.conns)+len(extraConns))

	session.packetConns = append(session.packetConns, localPacketConns...)
	session.portmaps = append(session.portmaps, localPortmaps...)
	session.transports = append(session.transports, extraTransports...)
	session.conns = append(session.conns, extraConns...)
	session.openStreams = append(session.openStreams, extraOpenStreams...)
	if emitter != nil {
		emitter.Debug(fmt.Sprintf("native-quic-stripes=%d", len(session.conns)))
	}

	return session, nil
}

func acceptExternalNativeQUICStripedConns(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	dm *tailcfg.DERPMap,
	emitter *telemetry.Emitter,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	connCount int,
) (*externalNativeQUICStripedSession, []*quic.Stream, error) {
	connCount = externalNativeQUICConnCountForPeer(peerAddr, connCount)
	externalTransferTracef("native-quic-accept-striped-start peer=%v conns=%d", peerAddr, connCount)
	if connCount < 1 {
		return nil, nil, errors.New("native QUIC connection count must be positive")
	}
	if connCount > 1 && externalNativeQUICStripeShouldReusePrimaryPacketConn(peerAddr) {
		transport, conns, openStreams, err := dialOrAcceptExternalNativeQUICConnsWithStreamRole(
			ctx,
			packetConn,
			peerAddr,
			clientTLS,
			serverTLS,
			connCount,
			false,
		)
		if err != nil {
			return nil, nil, err
		}
		session := &externalNativeQUICStripedSession{
			packetConns: []net.PacketConn{packetConn},
			transports:  []*quic.Transport{transport},
			conns:       conns,
			openStreams: externalNativeQUICStreamRoles(len(conns), openStreams),
		}
		if emitter != nil {
			emitter.Debug(fmt.Sprintf("native-quic-stripes=%d", len(conns)))
		}
		streams, err := session.OpenQUICStreams(ctx)
		if err != nil {
			session.Close()
			return nil, nil, err
		}
		return session, streams, nil
	}

	transport, conn, openPrimaryStream, err := dialOrAcceptExternalNativeQUICConnWithRole(
		ctx,
		packetConn,
		peerAddr,
		clientTLS,
		serverTLS,
		false,
	)
	if err != nil {
		return nil, nil, err
	}
	session := &externalNativeQUICStripedSession{
		packetConns: []net.PacketConn{packetConn},
		transports:  []*quic.Transport{transport},
		conns:       []*quic.Conn{conn},
		openStreams: []bool{openPrimaryStream},
	}
	externalTransferTracef("native-quic-accept-primary-ready")
	if connCount > 1 {
		controlAcceptCtx, controlAcceptCancel := context.WithTimeout(ctx, externalNativeQUICWait)
		controlStream, err := openExternalNativeQUICStreamForConn(controlAcceptCtx, conn, openPrimaryStream)
		controlAcceptCancel()
		if err != nil {
			stream, streamErr := openExternalNativeQUICStreamForConn(ctx, conn, openPrimaryStream)
			if streamErr != nil {
				session.Close()
				return nil, nil, streamErr
			}
			session.setupFallback = true
			return session, []*quic.Stream{stream}, nil
		}
		externalTransferTracef("native-quic-accept-control-open")
		cancelControlStreamDeadline := cancelExternalNativeQUICControlStreamDeadlineOnContextDone(ctx, controlStream)
		defer cancelControlStreamDeadline()
		keepControlStream := false
		defer func() {
			if keepControlStream {
				return
			}
			_ = controlStream.SetDeadline(time.Time{})
			_ = controlStream.Close()
		}()
		_ = controlStream.SetDeadline(time.Now().Add(externalNativeQUICWait))

		var peerSetup externalNativeQUICStripeSetup
		if err := json.NewDecoder(controlStream).Decode(&peerSetup); err != nil {
			if emitter != nil {
				emitter.Debug("native-quic-primary-fallback=decode-stripe-setup")
			}
			session.setupFallback = true
			keepControlStream = true
			return session, []*quic.Stream{controlStream}, nil
		}
		externalTransferTracef("native-quic-accept-peer-stripe-setup-received stripes=%d", len(peerSetup.CandidateSets))
		stripeCount := min(connCount-1, len(peerSetup.CandidateSets))
		if stripeCount == 0 {
			if emitter != nil {
				emitter.Debug("native-quic-primary-fallback=stripe-setup-size")
			}
			session.setupFallback = true
			keepControlStream = true
			return session, []*quic.Stream{controlStream}, nil
		}

		_ = controlStream.SetDeadline(time.Time{})

		localPacketConns, localPortmaps, localCandidateSets, err := openExternalNativeQUICStripePacketConns(ctx, peerAddr, dm, emitter, connCount-1)
		if err != nil {
			if emitter != nil {
				emitter.Debug("native-quic-primary-fallback=open-stripe-sockets")
			}
			stream, streamErr := conn.AcceptStream(ctx)
			if streamErr != nil {
				session.Close()
				return nil, nil, streamErr
			}
			session.setupFallback = true
			return session, []*quic.Stream{stream}, nil
		}
		externalTransferTracef("native-quic-accept-stripe-candidates-ready stripes=%d", len(localPacketConns))
		if err := ctx.Err(); err != nil {
			closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
			session.setupFallback = true
			keepControlStream = true
			return session, []*quic.Stream{controlStream}, err
		}
		if stripeCount < len(localPacketConns) {
			closeExternalNativeQUICStripePacketConns(localPacketConns[stripeCount:], localPortmaps[stripeCount:])
			localPacketConns = localPacketConns[:stripeCount]
			localPortmaps = localPortmaps[:stripeCount]
			localCandidateSets = localCandidateSets[:stripeCount]
		}

		_ = controlStream.SetDeadline(time.Now().Add(externalNativeQUICWait))
		if err := json.NewEncoder(controlStream).Encode(externalNativeQUICStripeSetup{CandidateSets: localCandidateSets}); err != nil {
			closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
			if emitter != nil {
				emitter.Debug("native-quic-primary-fallback=encode-stripe-setup")
			}
			session.setupFallback = true
			keepControlStream = true
			return session, []*quic.Stream{controlStream}, nil
		}
		_ = controlStream.SetDeadline(time.Time{})

		extraSetupCtx, extraSetupCancel := context.WithTimeout(ctx, externalNativeQUICWait)
		defer extraSetupCancel()

		extraTransports, extraConns, extraOpenStreams, stripeReady := openExternalNativeQUICStripeConns(
			extraSetupCtx,
			peerAddr,
			localPacketConns,
			peerSetup.CandidateSets,
			clientTLS,
			serverTLS,
			false,
			"native-quic-accept-stripe-ready",
			"native-quic-primary-fallback=dial-stripe-conn err=",
			emitter,
		)
		_ = controlStream.SetDeadline(time.Now().Add(externalNativeQUICWait))
		var peerReady externalNativeQUICStripeSetupResult
		if err := json.NewDecoder(controlStream).Decode(&peerReady); err != nil {
			stripeReady = false
		}
		if err := json.NewEncoder(controlStream).Encode(externalNativeQUICStripeSetupResult{Ready: stripeReady}); err != nil || !stripeReady || !peerReady.Ready {
			closeExternalNativeQUICConns(extraConns)
			for _, transport := range extraTransports {
				_ = transport.Close()
			}
			closeExternalNativeQUICStripePacketConns(localPacketConns, localPortmaps)
			if emitter != nil {
				emitter.Debug("native-quic-primary-fallback")
			}
			session.setupFallback = true
			keepControlStream = true
			return session, []*quic.Stream{controlStream}, nil
		}

		session.packetConns = append(session.packetConns, localPacketConns...)
		session.portmaps = append(session.portmaps, localPortmaps...)
		session.transports = append(session.transports, extraTransports...)
		session.conns = append(session.conns, extraConns...)
		session.openStreams = append(session.openStreams, extraOpenStreams...)
		externalTransferTracef("native-quic-accept-striped-ready conns=%d", len(session.conns))
		if emitter != nil {
			emitter.Debug(fmt.Sprintf("native-quic-stripes=%d", len(session.conns)))
		}
	}

	streams, err := session.OpenQUICStreams(ctx)
	if err != nil {
		session.Close()
		return nil, nil, err
	}
	return session, streams, nil
}

func openExternalNativeQUICStripePacketConns(
	ctx context.Context,
	peerAddr net.Addr,
	dm *tailcfg.DERPMap,
	emitter *telemetry.Emitter,
	count int,
) ([]net.PacketConn, []publicPortmap, [][]string, error) {
	start := time.Now()
	packetConns := make([]net.PacketConn, 0, count)
	portmaps := make([]publicPortmap, 0, count)
	candidateSets := make([][]string, 0, count)
	bindAddr := externalNativeQUICStripeLocalBindAddr(peerAddr)
	for range count {
		packetConn, err := net.ListenPacket(bindAddr.Network(), bindAddr.String())
		if err != nil {
			closeExternalNativeQUICStripePacketConns(packetConns, portmaps)
			return nil, nil, nil, err
		}
		pm := newBoundPublicPortmap(packetConn, emitter)
		packetConns = append(packetConns, packetConn)
		portmaps = append(portmaps, pm)
		candidateSets = append(candidateSets, nil)
	}
	var wg sync.WaitGroup
	wg.Add(len(packetConns))
	for i := range packetConns {
		go func() {
			defer wg.Done()
			if externalNativeQUICStripeCanUseLocalAddrCandidate(packetConns[i].LocalAddr(), peerAddr) {
				candidateSets[i] = []string{packetConns[i].LocalAddr().String()}
				return
			}
			candidateSets[i] = externalNativeQUICStripeProbeCandidates(ctx, packetConns[i], dm, portmaps[i])
		}()
	}
	wg.Wait()
	for _, packetConn := range packetConns {
		if err := packetConn.SetDeadline(time.Time{}); err != nil {
			closeExternalNativeQUICStripePacketConns(packetConns, portmaps)
			return nil, nil, nil, err
		}
	}
	if emitter != nil {
		emitter.Debug("native-quic-stripe-candidates=" + time.Since(start).String())
	}
	return packetConns, portmaps, candidateSets, nil
}

func openExternalNativeQUICStripeConns(
	ctx context.Context,
	peerAddr net.Addr,
	localPacketConns []net.PacketConn,
	peerCandidateSets [][]string,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	preferDial bool,
	traceFormat string,
	fallbackPrefix string,
	emitter *telemetry.Emitter,
) ([]*quic.Transport, []*quic.Conn, []bool, bool) {
	setupCtx, setupCancel := context.WithCancel(ctx)
	defer setupCancel()

	results := make(chan externalNativeQUICStripeConnResult, len(localPacketConns))
	for i, localPacketConn := range localPacketConns {
		i := i
		localPacketConn := localPacketConn
		go func() {
			result := externalNativeQUICStripeConnResult{index: i}
			stripePeerAddr, err := selectExternalNativeQUICPeerAddr(peerAddr, peerCandidateSets[i])
			if err != nil {
				result.err = err
				results <- result
				return
			}
			result.peerAddr = stripePeerAddr
			result.transport, result.conn, result.openStream, result.err = dialOrAcceptExternalNativeQUICConnWithRole(
				setupCtx,
				localPacketConn,
				stripePeerAddr,
				clientTLS,
				serverTLS,
				preferDial,
			)
			results <- result
		}()
	}

	transports := make([]*quic.Transport, len(localPacketConns))
	conns := make([]*quic.Conn, len(localPacketConns))
	openStreams := make([]bool, len(localPacketConns))
	stripeReady := true
	for range localPacketConns {
		result := <-results
		externalTransferTracef(traceFormat+" index=%d peer=%v err=%v", result.index, result.peerAddr, result.err)
		if emitter != nil && result.peerAddr != nil {
			emitter.Debug("native-quic-stripe-local=" + localPacketConns[result.index].LocalAddr().String() + " peer=" + result.peerAddr.String())
		}
		if result.err != nil {
			if stripeReady {
				stripeReady = false
				setupCancel()
				if emitter != nil {
					if result.peerAddr == nil {
						emitter.Debug("native-quic-primary-fallback=select-stripe-peer err=" + result.err.Error())
					} else {
						emitter.Debug(fallbackPrefix + result.err.Error())
					}
				}
			}
			continue
		}
		transports[result.index] = result.transport
		conns[result.index] = result.conn
		openStreams[result.index] = result.openStream
	}
	if stripeReady {
		return transports, conns, openStreams, true
	}
	closeExternalNativeQUICConns(conns)
	for _, transport := range transports {
		if transport != nil {
			_ = transport.Close()
		}
	}
	return nil, nil, nil, false
}

func externalNativeQUICStripeLocalBindAddr(peerAddr net.Addr) net.Addr {
	fallbackAddr := &net.UDPAddr{Port: 0}
	peerUDPAddr, ok := peerAddr.(*net.UDPAddr)
	if !ok || peerUDPAddr == nil || len(peerUDPAddr.IP) == 0 || peerUDPAddr.IP.IsUnspecified() {
		return fallbackAddr
	}
	routeProbe, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: peerUDPAddr.IP, Port: peerUDPAddr.Port})
	if err != nil {
		return fallbackAddr
	}
	defer routeProbe.Close()

	localUDPAddr, ok := routeProbe.LocalAddr().(*net.UDPAddr)
	if !ok || localUDPAddr == nil || len(localUDPAddr.IP) == 0 || localUDPAddr.IP.IsUnspecified() {
		return fallbackAddr
	}
	return &net.UDPAddr{IP: append(net.IP(nil), localUDPAddr.IP...), Port: 0}
}

func externalNativeQUICStripeCanUseLocalAddrCandidateDefault(localAddr, peerAddr net.Addr) bool {
	localUDPAddr, ok := localAddr.(*net.UDPAddr)
	if !ok || localUDPAddr == nil {
		return false
	}
	peerUDPAddr, ok := peerAddr.(*net.UDPAddr)
	if !ok || peerUDPAddr == nil {
		return false
	}
	localIP, ok := netip.AddrFromSlice(localUDPAddr.IP)
	if !ok {
		return false
	}
	peerIP, ok := netip.AddrFromSlice(peerUDPAddr.IP)
	if !ok {
		return false
	}
	localIP = localIP.Unmap()
	peerIP = peerIP.Unmap()
	if !localIP.Is4() || !peerIP.Is4() {
		return false
	}
	return externalNativeQUICStripeSameRouteLocalPrefix(localIP, peerIP)
}

func externalNativeQUICStripeShouldReusePrimaryPacketConn(peerAddr net.Addr) bool {
	return externalNativeQUICStripeCanUseLocalAddrCandidate(
		externalNativeQUICStripeLocalBindAddr(peerAddr),
		peerAddr,
	)
}

func externalNativeQUICConnCountForPeer(peerAddr net.Addr, connCount int) int {
	if connCount <= 1 {
		return connCount
	}
	if externalNativeTCPAddrIsPublic(peerAddr) {
		return connCount
	}
	peerUDPAddr, ok := peerAddr.(*net.UDPAddr)
	if !ok || peerUDPAddr == nil {
		return 1
	}
	peerIP, ok := netip.AddrFromSlice(peerUDPAddr.IP)
	if !ok {
		return 1
	}
	localUDPAddr, ok := externalNativeQUICStripeLocalBindAddr(peerAddr).(*net.UDPAddr)
	if !ok || localUDPAddr == nil {
		return 1
	}
	localIP, ok := netip.AddrFromSlice(localUDPAddr.IP)
	if !ok {
		return 1
	}
	if externalNativeQUICStripeSameRouteLocalPrefix(localIP.Unmap(), peerIP.Unmap()) {
		return connCount
	}
	return 1
}

func externalNativeQUICStripeSameRouteLocalPrefix(localIP, peerIP netip.Addr) bool {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
	} {
		if prefix.Contains(localIP) && prefix.Contains(peerIP) {
			return true
		}
	}
	return false
}

func closeExternalNativeQUICStripePacketConns(packetConns []net.PacketConn, portmaps []publicPortmap) {
	for _, pm := range portmaps {
		_ = pm.Close()
	}
	for _, packetConn := range packetConns {
		_ = packetConn.Close()
	}
}

func selectExternalNativeQUICPeerAddr(primaryPeerAddr net.Addr, candidates []string) (net.Addr, error) {
	parsed := parseCandidateStrings(candidates)
	if len(parsed) == 0 {
		if primaryPeerAddr != nil {
			return cloneSessionAddr(primaryPeerAddr), nil
		}
		return nil, errors.New("no native QUIC peer candidates")
	}
	primaryUDPAddr, ok := primaryPeerAddr.(*net.UDPAddr)
	if !ok || primaryUDPAddr == nil {
		return cloneSessionAddr(parsed[0]), nil
	}
	primaryIP, ok := netip.AddrFromSlice(primaryUDPAddr.IP)
	if !ok {
		return cloneSessionAddr(parsed[0]), nil
	}
	primaryIP = primaryIP.Unmap()
	for _, candidate := range parsed {
		candidateUDPAddr, ok := candidate.(*net.UDPAddr)
		if !ok || candidateUDPAddr == nil {
			continue
		}
		candidateIP, ok := netip.AddrFromSlice(candidateUDPAddr.IP)
		if !ok {
			continue
		}
		if candidateIP.Unmap() == primaryIP {
			return cloneSessionAddr(candidate), nil
		}
	}
	return nil, errExternalNativeQUICNoMatchingStripeCandidate
}

func dialOrAcceptExternalNativeQUICConn(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
) (*quic.Transport, *quic.Conn, error) {
	transport, conn, _, err := dialOrAcceptExternalNativeQUICConnWithRole(ctx, packetConn, peerAddr, clientTLS, serverTLS, true)
	if err != nil {
		return nil, nil, err
	}
	return transport, conn, nil
}

func dialOrAcceptExternalNativeQUICConnWithRole(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	preferDial bool,
) (*quic.Transport, *quic.Conn, bool, error) {
	transport, conns, openStreams, err := dialOrAcceptExternalNativeQUICConnsWithStreamRole(
		ctx,
		packetConn,
		peerAddr,
		clientTLS,
		serverTLS,
		1,
		preferDial,
	)
	if err != nil {
		return nil, nil, false, err
	}
	return transport, conns[0], openStreams, nil
}

func dialOrAcceptExternalNativeQUICConns(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	connCount int,
) (*quic.Transport, []*quic.Conn, error) {
	return dialOrAcceptExternalNativeQUICConnsWithRole(ctx, packetConn, peerAddr, clientTLS, serverTLS, connCount, true)
}

func acceptExternalNativeQUICConnStrict(
	ctx context.Context,
	packetConn net.PacketConn,
	serverTLS *tls.Config,
) (*quic.Transport, *quic.Conn, error) {
	transport, conns, err := acceptExternalNativeQUICConnsStrict(ctx, packetConn, serverTLS, 1)
	if err != nil {
		return nil, nil, err
	}
	return transport, conns[0], nil
}

func acceptExternalNativeQUICConnsStrict(
	ctx context.Context,
	packetConn net.PacketConn,
	serverTLS *tls.Config,
	connCount int,
) (*quic.Transport, []*quic.Conn, error) {
	if connCount < 1 {
		return nil, nil, errors.New("native QUIC connection count must be positive")
	}
	transport, listener, err := startExternalNativeQUICTransport(packetConn, serverTLS)
	if err != nil {
		return nil, nil, err
	}

	acceptCtx, cancel := context.WithTimeout(ctx, externalNativeQUICConnectWait)
	defer cancel()

	conns := make([]*quic.Conn, 0, connCount)
	for len(conns) < connCount {
		conn, err := listener.Accept(acceptCtx)
		if err != nil {
			closeExternalNativeQUICConns(conns)
			_ = listener.Close()
			_ = transport.Close()
			return nil, nil, err
		}
		conns = append(conns, conn)
	}

	_ = listener.Close()
	return transport, conns, nil
}

func dialOrAcceptExternalNativeQUICConnsWithRole(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	connCount int,
	preferDial bool,
) (*quic.Transport, []*quic.Conn, error) {
	transport, conns, _, err := dialOrAcceptExternalNativeQUICConnsWithStreamRole(ctx, packetConn, peerAddr, clientTLS, serverTLS, connCount, preferDial)
	return transport, conns, err
}

func dialOrAcceptExternalNativeQUICConnsWithStreamRole(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	connCount int,
	preferDial bool,
) (*quic.Transport, []*quic.Conn, bool, error) {
	if connCount < 1 {
		return nil, nil, false, errors.New("native QUIC connection count must be positive")
	}
	transport, listener, err := startExternalNativeQUICTransport(packetConn, serverTLS)
	if err != nil {
		return nil, nil, false, err
	}

	connectCtx, cancel := context.WithTimeout(ctx, externalNativeQUICConnectWait)
	firstConn, dialRemainder, err := dialOrAcceptExternalNativeQUICConnOnTransport(
		connectCtx,
		transport,
		listener,
		peerAddr,
		clientTLS,
		preferDial,
	)
	if err != nil {
		cancel()
		_ = listener.Close()
		_ = transport.Close()
		return nil, nil, false, err
	}

	conns := []*quic.Conn{firstConn}
	for len(conns) < connCount {
		var nextConn *quic.Conn
		if dialRemainder {
			nextConn, err = transport.Dial(connectCtx, peerAddr, clientTLS, quicpath.DefaultQUICConfig())
		} else {
			nextConn, err = listener.Accept(connectCtx)
		}
		if err != nil {
			cancel()
			_ = listener.Close()
			closeExternalNativeQUICConns(conns)
			_ = transport.Close()
			return nil, nil, false, err
		}
		conns = append(conns, nextConn)
	}

	cancel()
	_ = listener.Close()
	// Stream-open ownership is a protocol role, not a side-effect of which
	// first connection happened to win the accept-vs-dial race.
	return transport, conns, preferDial, nil
}

func dialOrAcceptExternalNativeQUICConnOnTransport(
	ctx context.Context,
	transport *quic.Transport,
	listener *quic.Listener,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	preferDial bool,
) (*quic.Conn, bool, error) {
	connectCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan externalNativeQUICConnResult, 2)
	pendingResults := 1
	if peerAddr != nil {
		pendingResults++
		go func() {
			if !preferDial {
				delayTimer := time.NewTimer(externalNativeQUICDuplicateConnWait)
				defer delayTimer.Stop()
				select {
				case <-delayTimer.C:
				case <-connectCtx.Done():
					results <- externalNativeQUICConnResult{dialed: true, err: connectCtx.Err()}
					return
				}
			}
			conn, err := transport.Dial(connectCtx, peerAddr, clientTLS, quicpath.DefaultQUICConfig())
			results <- externalNativeQUICConnResult{conn: conn, dialed: true, err: err}
		}()
	}
	go func() {
		conn, err := listener.Accept(connectCtx)
		results <- externalNativeQUICConnResult{conn: conn, err: err}
	}()

	var firstErr error
	var firstConn *quic.Conn
	var firstDialed bool
	for i := 0; i < pendingResults; i++ {
		if firstConn != nil {
			if firstDialed == preferDial {
				cancel()
				return firstConn, firstDialed, nil
			}
			select {
			case result := <-results:
				if result.err == nil {
					cancel()
					if result.dialed == preferDial {
						_ = firstConn.CloseWithError(0, "")
						return result.conn, preferDial, nil
					}
					_ = result.conn.CloseWithError(0, "")
					return firstConn, firstDialed, nil
				}
			case <-time.After(externalNativeQUICDuplicateConnWait):
			case <-ctx.Done():
			}
			cancel()
			return firstConn, firstDialed, nil
		}

		result := <-results
		if result.err == nil {
			firstConn = result.conn
			firstDialed = result.dialed
			continue
		}
		if firstErr == nil {
			firstErr = result.err
		}
	}
	if firstConn != nil {
		cancel()
		return firstConn, firstDialed, nil
	}

	cancel()
	if firstErr == nil {
		firstErr = errors.New("native QUIC connection unavailable")
	}
	return nil, false, firstErr
}

func openExternalNativeQUICStreamForConn(ctx context.Context, conn *quic.Conn, openStream bool) (*quic.Stream, error) {
	if openStream {
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		cancelDeadline := cancelExternalNativeQUICCarrierDeadlineOnContextDone(ctx, stream)
		defer cancelDeadline()
		if _, err := stream.Write([]byte{externalNativeQUICStreamOpenByte}); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, nil
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	cancelDeadline := cancelExternalNativeQUICCarrierDeadlineOnContextDone(ctx, stream)
	defer cancelDeadline()
	var opened [1]byte
	if _, err := io.ReadFull(stream, opened[:]); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if opened[0] != externalNativeQUICStreamOpenByte {
		_ = stream.Close()
		return nil, fmt.Errorf("native QUIC stream open byte = %d, want %d", opened[0], externalNativeQUICStreamOpenByte)
	}
	return stream, nil
}

func externalNativeQUICStreamRole(openStreams []bool, index int) bool {
	if index >= 0 && index < len(openStreams) {
		return openStreams[index]
	}
	return true
}

func externalNativeQUICStreamRoles(count int, openStream bool) []bool {
	roles := make([]bool, count)
	for i := range roles {
		roles[i] = openStream
	}
	return roles
}

func acceptExternalNativeQUICStream(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
) (*quic.Transport, *quic.Conn, *quic.Stream, error) {
	transport, conns, streams, err := acceptExternalNativeQUICStreams(ctx, packetConn, peerAddr, clientTLS, serverTLS, 1)
	if err != nil {
		return nil, nil, nil, err
	}
	return transport, conns[0], streams[0], nil
}

func acceptExternalNativeQUICStreams(
	ctx context.Context,
	packetConn net.PacketConn,
	peerAddr net.Addr,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	streamCount int,
) (*quic.Transport, []*quic.Conn, []*quic.Stream, error) {
	transport, conns, err := dialOrAcceptExternalNativeQUICConnsWithRole(ctx, packetConn, peerAddr, clientTLS, serverTLS, streamCount, false)
	if err != nil {
		return nil, nil, nil, err
	}

	streams := make([]*quic.Stream, 0, len(conns))
	for _, conn := range conns {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			closeExternalNativeQUICStreams(streams)
			closeExternalNativeQUICConns(conns)
			_ = transport.Close()
			return nil, nil, nil, err
		}
		streams = append(streams, stream)
	}
	return transport, conns, streams, nil
}

func closeExternalNativeQUICConns(conns []*quic.Conn) {
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		_ = conn.CloseWithError(0, "")
	}
}

func closeExternalNativeQUICStreams(streams []*quic.Stream) {
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		_ = stream.Close()
	}
}

func startExternalNativeQUICTransport(packetConn net.PacketConn, serverTLS *tls.Config) (*quic.Transport, *quic.Listener, error) {
	transport := &quic.Transport{Conn: packetConn}
	listener, err := transport.Listen(serverTLS, quicpath.DefaultQUICConfig())
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	return transport, listener, nil
}

func cancelExternalNativeQUICControlStreamDeadlineOnContextDone(ctx context.Context, stream *quic.Stream) func() {
	return cancelExternalNativeQUICCarrierDeadlineOnContextDone(ctx, stream)
}

func cancelExternalNativeQUICCarrierDeadlineOnContextDone(ctx context.Context, carrier interface{ SetDeadline(time.Time) error }) func() {
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		externalTransferTracef("native-quic-carrier-deadline-cancel-fired carrier=%T", carrier)
		_ = carrier.SetDeadline(time.Now())
		close(callbackDone)
	})
	return func() {
		if stop() {
			close(callbackDone)
		}
		<-callbackDone
		_ = carrier.SetDeadline(time.Time{})
	}
}
