// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore U1000 Retired public QUIC transport helpers pending deletion after the WG cutover settles.
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
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/telemetry"
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
	mu            sync.Mutex
	setupFallback bool
	packetConns   []net.PacketConn
	transports    []*quic.Transport
	conns         []*quic.Conn
	openStreams   []bool
	portmaps      []publicPortmap
	primaryStream *quic.Stream
	peerAddr      net.Addr
	derpMap       *tailcfg.DERPMap
	emitter       *telemetry.Emitter
	clientTLS     *tls.Config
	serverTLS     *tls.Config
	preferDial    bool
}

type externalNativeQUICGrowthPlan struct {
	target        int
	packetConns   []net.PacketConn
	portmaps      []publicPortmap
	candidateSets [][]string
}

type externalNativeQUICGrowthResult struct {
	plan        *externalNativeQUICGrowthPlan
	transports  []*quic.Transport
	conns       []*quic.Conn
	openStreams []bool
	streams     []io.ReadWriteCloser
}

type externalNativeQUICStripeSockets struct {
	packetConns   []net.PacketConn
	portmaps      []publicPortmap
	candidateSets [][]string
}

type externalNativeQUICControlStream struct {
	stream         *quic.Stream
	keep           bool
	cancelDeadline func()
}

func newExternalNativeQUICControlStream(ctx context.Context, stream *quic.Stream) *externalNativeQUICControlStream {
	return &externalNativeQUICControlStream{
		stream:         stream,
		cancelDeadline: cancelExternalNativeQUICControlStreamDeadlineOnContextDone(ctx, stream),
	}
}

func (c *externalNativeQUICControlStream) Close() {
	if c == nil {
		return
	}
	c.cancelDeadline()
	if c.keep {
		return
	}
	_ = c.stream.SetDeadline(time.Time{})
	_ = c.stream.Close()
}

func (c *externalNativeQUICControlStream) KeepAsPrimary(session *externalNativeQUICStripedSession) {
	if c == nil {
		return
	}
	session.primaryStream = c.stream
	c.keep = true
}

func (c *externalNativeQUICControlStream) Keep() {
	if c != nil {
		c.keep = true
	}
}

func (c *externalNativeQUICControlStream) SetWaitDeadline() {
	_ = c.stream.SetDeadline(time.Now().Add(externalNativeQUICWait))
}

func (c *externalNativeQUICControlStream) ClearDeadline() {
	_ = c.stream.SetDeadline(time.Time{})
}

func closeExternalNativeQUICGrowthPlan(plan *externalNativeQUICGrowthPlan) {
	if plan == nil {
		return
	}
	closeExternalNativeQUICStripePacketConns(plan.packetConns, plan.portmaps)
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

func (s *externalNativeQUICStripedSession) StripeCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *externalNativeQUICStripedSession) PrepareGrowth(ctx context.Context, target int) (*externalNativeQUICGrowthPlan, error) {
	if s == nil {
		return nil, errors.New("nil native QUIC session")
	}
	s.mu.Lock()
	current := len(s.conns)
	peerAddr := cloneSessionAddr(s.peerAddr)
	dm := s.derpMap
	emitter := s.emitter
	s.mu.Unlock()
	if target <= current {
		return nil, nil
	}
	extraCount := target - current
	packetConns, portmaps, candidateSets, err := openExternalNativeQUICStripePacketConns(ctx, peerAddr, dm, emitter, extraCount)
	if err != nil {
		return nil, err
	}
	return &externalNativeQUICGrowthPlan{
		target:        target,
		packetConns:   packetConns,
		portmaps:      portmaps,
		candidateSets: candidateSets,
	}, nil
}

func (s *externalNativeQUICStripedSession) OpenGrowth(ctx context.Context, plan *externalNativeQUICGrowthPlan, peerCandidateSets [][]string) (*externalNativeQUICGrowthResult, error) {
	if s == nil {
		return nil, errors.New("nil native QUIC session")
	}
	if plan == nil {
		return nil, nil
	}
	s.mu.Lock()
	peerAddr := cloneSessionAddr(s.peerAddr)
	clientTLS := s.clientTLS
	serverTLS := s.serverTLS
	preferDial := s.preferDial
	emitter := s.emitter
	s.mu.Unlock()
	transports, conns, openStreams, ready := openExternalNativeQUICStripeConns(
		ctx,
		peerAddr,
		plan.packetConns,
		peerCandidateSets,
		clientTLS,
		serverTLS,
		preferDial,
		"native-quic-grow-ready",
		"native-quic-grow-fallback err=",
		emitter,
	)
	if !ready {
		return nil, errors.New("native QUIC growth setup failed")
	}
	streams, err := openExternalNativeQUICGrowthStreams(ctx, conns, openStreams)
	if err != nil {
		closeExternalNativeQUICGrowthResources(conns, transports)
		return nil, err
	}
	return &externalNativeQUICGrowthResult{
		plan:        plan,
		transports:  transports,
		conns:       conns,
		openStreams: openStreams,
		streams:     streams,
	}, nil
}

func openExternalNativeQUICGrowthStreams(ctx context.Context, conns []*quic.Conn, openStreams []bool) ([]io.ReadWriteCloser, error) {
	growthSession := &externalNativeQUICStripedSession{
		conns:       conns,
		openStreams: openStreams,
	}
	return growthSession.OpenReadWriteStreams(ctx)
}

func closeExternalNativeQUICGrowthResources(conns []*quic.Conn, transports []*quic.Transport) {
	closeExternalNativeQUICConns(conns)
	closeExternalNativeQUICTransports(transports)
}

func (s *externalNativeQUICStripedSession) CommitGrowth(growth *externalNativeQUICGrowthResult) int {
	if s == nil || growth == nil {
		return s.StripeCount()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packetConns = append(s.packetConns, growth.plan.packetConns...)
	s.portmaps = append(s.portmaps, growth.plan.portmaps...)
	s.transports = append(s.transports, growth.transports...)
	s.conns = append(s.conns, growth.conns...)
	s.openStreams = append(s.openStreams, growth.openStreams...)
	return len(s.conns)
}

func closeExternalNativeQUICGrowthResult(growth *externalNativeQUICGrowthResult) {
	if growth == nil {
		return
	}
	closeExternalNativeQUICReadWriteStreams(growth.streams)
	closeExternalNativeQUICGrowthResources(growth.conns, growth.transports)
	closeExternalNativeQUICGrowthPlan(growth.plan)
}

func closeExternalNativeQUICReadWriteStreams(streams []io.ReadWriteCloser) {
	for _, stream := range streams {
		if stream != nil {
			_ = stream.Close()
		}
	}
}

func closeExternalNativeQUICTransports(transports []*quic.Transport) {
	for _, transport := range transports {
		if transport != nil {
			_ = transport.Close()
		}
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
	if err := validateExternalNativeQUICConnCount(connCount); err != nil {
		return nil, err
	}
	if connCount > 1 && externalNativeQUICStripeShouldReusePrimaryPacketConn(peerAddr) {
		return dialExternalNativeQUICReusedStripeSession(ctx, packetConn, peerAddr, dm, emitter, clientTLS, serverTLS, connCount)
	}

	session, err := dialExternalNativeQUICPrimaryStripeSession(ctx, packetConn, peerAddr, dm, emitter, clientTLS, serverTLS)
	if err != nil {
		return nil, err
	}
	if connCount == 1 {
		emitExternalNativeQUICDebug(emitter, "native-quic-primary-only")
		return session, nil
	}
	return session, dialExternalNativeQUICAddStripes(ctx, session, peerAddr, clientTLS, serverTLS, connCount)
}

func validateExternalNativeQUICConnCount(connCount int) error {
	if connCount < 1 {
		return errors.New("native QUIC connection count must be positive")
	}
	return nil
}

func dialExternalNativeQUICReusedStripeSession(ctx context.Context, packetConn net.PacketConn, peerAddr net.Addr, dm *tailcfg.DERPMap, emitter *telemetry.Emitter, clientTLS *tls.Config, serverTLS *tls.Config, connCount int) (*externalNativeQUICStripedSession, error) {
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
	emitExternalNativeQUICStripeCount(emitter, len(conns))
	return newExternalNativeQUICStripedSession(
		[]net.PacketConn{packetConn},
		nil,
		[]*quic.Transport{transport},
		conns,
		externalNativeQUICStreamRoles(len(conns), openStreams),
		peerAddr,
		dm,
		emitter,
		clientTLS,
		serverTLS,
		true,
	), nil
}

func dialExternalNativeQUICPrimaryStripeSession(ctx context.Context, packetConn net.PacketConn, peerAddr net.Addr, dm *tailcfg.DERPMap, emitter *telemetry.Emitter, clientTLS *tls.Config, serverTLS *tls.Config) (*externalNativeQUICStripedSession, error) {
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
	return newExternalNativeQUICStripedSession(
		[]net.PacketConn{packetConn},
		nil,
		[]*quic.Transport{primaryTransport},
		[]*quic.Conn{primaryConn},
		[]bool{openPrimaryStream},
		peerAddr,
		dm,
		emitter,
		clientTLS,
		serverTLS,
		true,
	), nil
}

func newExternalNativeQUICStripedSession(
	packetConns []net.PacketConn,
	portmaps []publicPortmap,
	transports []*quic.Transport,
	conns []*quic.Conn,
	openStreams []bool,
	peerAddr net.Addr,
	dm *tailcfg.DERPMap,
	emitter *telemetry.Emitter,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	preferDial bool,
) *externalNativeQUICStripedSession {
	return &externalNativeQUICStripedSession{
		packetConns: packetConns,
		portmaps:    portmaps,
		transports:  transports,
		conns:       conns,
		openStreams: openStreams,
		peerAddr:    cloneSessionAddr(peerAddr),
		derpMap:     dm,
		emitter:     emitter,
		clientTLS:   clientTLS,
		serverTLS:   serverTLS,
		preferDial:  preferDial,
	}
}

func dialExternalNativeQUICAddStripes(ctx context.Context, session *externalNativeQUICStripedSession, peerAddr net.Addr, clientTLS *tls.Config, serverTLS *tls.Config, connCount int) error {
	controlOpenCtx, controlOpenCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	controlStream, err := openExternalNativeQUICStreamForConn(controlOpenCtx, session.conns[0], session.openStreams[0])
	controlOpenCancel()
	if err != nil {
		externalNativeQUICFallback(session, nil, "native-quic-primary-fallback=open-control-stream")
		return nil
	}
	externalTransferTracef("native-quic-dial-control-open")
	control := newExternalNativeQUICControlStream(ctx, controlStream)
	defer control.Close()

	sockets, ok, err := openExternalNativeQUICDialStripeSockets(ctx, session, control, peerAddr, connCount-1)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	sockets, peerCandidateSets, ok := exchangeExternalNativeQUICDialStripeSetup(session, control, sockets)
	if !ok {
		return nil
	}

	extraSetupCtx, extraSetupCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer extraSetupCancel()

	extraTransports, extraConns, extraOpenStreams, stripeReady := openExternalNativeQUICStripeConns(
		extraSetupCtx,
		peerAddr,
		sockets.packetConns,
		peerCandidateSets,
		clientTLS,
		serverTLS,
		true,
		"native-quic-dial-stripe-ready",
		"native-quic-primary-fallback=dial-stripe-conn err=",
		session.emitter,
	)
	if !completeExternalNativeQUICDialStripeReady(session, control, sockets, extraTransports, extraConns, stripeReady) {
		return nil
	}
	externalTransferTracef("native-quic-dial-striped-ready conns=%d", len(session.conns)+len(extraConns))

	session.packetConns = append(session.packetConns, sockets.packetConns...)
	session.portmaps = append(session.portmaps, sockets.portmaps...)
	session.transports = append(session.transports, extraTransports...)
	session.conns = append(session.conns, extraConns...)
	session.openStreams = append(session.openStreams, extraOpenStreams...)
	emitExternalNativeQUICStripeCount(session.emitter, len(session.conns))

	return nil
}

func emitExternalNativeQUICDebug(emitter *telemetry.Emitter, msg string) {
	if emitter != nil && msg != "" {
		emitter.Debug(msg)
	}
}

func emitExternalNativeQUICStripeCount(emitter *telemetry.Emitter, count int) {
	emitExternalNativeQUICDebug(emitter, fmt.Sprintf("native-quic-stripes=%d", count))
}

func externalNativeQUICFallback(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, debug string) {
	emitExternalNativeQUICDebug(session.emitter, debug)
	session.setupFallback = true
	if control != nil {
		control.KeepAsPrimary(session)
	}
}

func openExternalNativeQUICDialStripeSockets(ctx context.Context, session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, peerAddr net.Addr, count int) (externalNativeQUICStripeSockets, bool, error) {
	packetConns, portmaps, candidateSets, err := openExternalNativeQUICStripePacketConns(ctx, peerAddr, session.derpMap, session.emitter, count)
	sockets := externalNativeQUICStripeSockets{
		packetConns:   packetConns,
		portmaps:      portmaps,
		candidateSets: candidateSets,
	}
	if err != nil {
		externalNativeQUICFallback(session, nil, "native-quic-primary-fallback=open-stripe-sockets")
		return sockets, false, nil
	}
	externalTransferTracef("native-quic-dial-stripe-candidates-ready stripes=%d", len(packetConns))
	if err := ctx.Err(); err != nil {
		closeExternalNativeQUICStripePacketConns(packetConns, portmaps)
		externalNativeQUICFallback(session, control, "")
		return sockets, false, err
	}
	return sockets, true, nil
}

func exchangeExternalNativeQUICDialStripeSetup(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, sockets externalNativeQUICStripeSockets) (externalNativeQUICStripeSockets, [][]string, bool) {
	control.SetWaitDeadline()
	if err := json.NewEncoder(control.stream).Encode(externalNativeQUICStripeSetup{CandidateSets: sockets.candidateSets}); err != nil {
		closeExternalNativeQUICStripePacketConns(sockets.packetConns, sockets.portmaps)
		externalNativeQUICFallback(session, control, "native-quic-primary-fallback=encode-stripe-setup")
		return sockets, nil, false
	}
	peerCandidateSets, ok := receiveExternalNativeQUICDialPeerStripeSetup(session, control, sockets)
	if !ok {
		return sockets, nil, false
	}
	sockets, ok = trimExternalNativeQUICDialStripeSockets(session, control, sockets, peerCandidateSets)
	if !ok {
		return sockets, nil, false
	}
	control.ClearDeadline()
	return sockets, peerCandidateSets, true
}

func receiveExternalNativeQUICDialPeerStripeSetup(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, sockets externalNativeQUICStripeSockets) ([][]string, bool) {
	var peerSetup externalNativeQUICStripeSetup
	externalTransferTracef("native-quic-dial-peer-stripe-setup-wait")
	if err := json.NewDecoder(control.stream).Decode(&peerSetup); err != nil {
		closeExternalNativeQUICStripePacketConns(sockets.packetConns, sockets.portmaps)
		externalNativeQUICFallback(session, control, "native-quic-primary-fallback=decode-stripe-setup")
		return nil, false
	}
	externalTransferTracef("native-quic-dial-peer-stripe-setup-received stripes=%d", len(peerSetup.CandidateSets))
	return peerSetup.CandidateSets, true
}

func trimExternalNativeQUICDialStripeSockets(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, sockets externalNativeQUICStripeSockets, peerCandidateSets [][]string) (externalNativeQUICStripeSockets, bool) {
	stripeCount := min(len(sockets.packetConns), len(peerCandidateSets))
	if stripeCount < len(sockets.packetConns) {
		closeExternalNativeQUICStripePacketConns(sockets.packetConns[stripeCount:], sockets.portmaps[stripeCount:])
		sockets.packetConns = sockets.packetConns[:stripeCount]
		sockets.portmaps = sockets.portmaps[:stripeCount]
	}
	if stripeCount == 0 {
		closeExternalNativeQUICStripePacketConns(sockets.packetConns, sockets.portmaps)
		externalNativeQUICFallback(session, control, "native-quic-primary-fallback=stripe-setup-size")
		return sockets, false
	}
	return sockets, true
}

func completeExternalNativeQUICDialStripeReady(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, sockets externalNativeQUICStripeSockets, extraTransports []*quic.Transport, extraConns []*quic.Conn, stripeReady bool) bool {
	control.SetWaitDeadline()
	if err := json.NewEncoder(control.stream).Encode(externalNativeQUICStripeSetupResult{Ready: stripeReady}); err != nil {
		cleanupExternalNativeQUICDialStripeFallback(sockets, extraTransports, extraConns)
		externalNativeQUICFallback(session, control, "native-quic-primary-fallback=encode-stripe-ready")
		return false
	}
	var peerReady externalNativeQUICStripeSetupResult
	if err := json.NewDecoder(control.stream).Decode(&peerReady); err != nil || !stripeReady || !peerReady.Ready {
		cleanupExternalNativeQUICDialStripeFallback(sockets, extraTransports, extraConns)
		externalNativeQUICFallback(session, control, "native-quic-primary-fallback=final")
		return false
	}
	return true
}

func cleanupExternalNativeQUICDialStripeFallback(sockets externalNativeQUICStripeSockets, extraTransports []*quic.Transport, extraConns []*quic.Conn) {
	closeExternalNativeQUICConns(extraConns)
	for _, transport := range extraTransports {
		_ = transport.Close()
	}
	closeExternalNativeQUICStripePacketConns(sockets.packetConns, sockets.portmaps)
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
	if err := validateExternalNativeQUICConnCount(connCount); err != nil {
		return nil, nil, err
	}
	if connCount > 1 && externalNativeQUICStripeShouldReusePrimaryPacketConn(peerAddr) {
		return acceptExternalNativeQUICReusedStripeSession(ctx, packetConn, peerAddr, dm, emitter, clientTLS, serverTLS, connCount)
	}

	session, err := acceptExternalNativeQUICPrimaryStripeSession(ctx, packetConn, peerAddr, dm, emitter, clientTLS, serverTLS)
	if err != nil {
		return nil, nil, err
	}
	externalTransferTracef("native-quic-accept-primary-ready")
	if connCount > 1 {
		streams, handled, err := acceptExternalNativeQUICAddStripes(ctx, session, peerAddr, clientTLS, serverTLS, connCount)
		if err != nil {
			if streams != nil {
				return session, streams, err
			}
			return nil, nil, err
		}
		if handled {
			return session, streams, nil
		}
	}

	return openExternalNativeQUICSessionStreams(ctx, session)
}

func acceptExternalNativeQUICReusedStripeSession(ctx context.Context, packetConn net.PacketConn, peerAddr net.Addr, dm *tailcfg.DERPMap, emitter *telemetry.Emitter, clientTLS *tls.Config, serverTLS *tls.Config, connCount int) (*externalNativeQUICStripedSession, []*quic.Stream, error) {
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
	session := newExternalNativeQUICStripedSession(
		[]net.PacketConn{packetConn},
		nil,
		[]*quic.Transport{transport},
		conns,
		externalNativeQUICStreamRoles(len(conns), openStreams),
		peerAddr,
		dm,
		emitter,
		clientTLS,
		serverTLS,
		false,
	)
	emitExternalNativeQUICStripeCount(emitter, len(conns))
	return openExternalNativeQUICSessionStreams(ctx, session)
}

func acceptExternalNativeQUICPrimaryStripeSession(ctx context.Context, packetConn net.PacketConn, peerAddr net.Addr, dm *tailcfg.DERPMap, emitter *telemetry.Emitter, clientTLS *tls.Config, serverTLS *tls.Config) (*externalNativeQUICStripedSession, error) {
	transport, conn, openPrimaryStream, err := dialOrAcceptExternalNativeQUICConnWithRole(
		ctx,
		packetConn,
		peerAddr,
		clientTLS,
		serverTLS,
		false,
	)
	if err != nil {
		return nil, err
	}
	return newExternalNativeQUICStripedSession(
		[]net.PacketConn{packetConn},
		nil,
		[]*quic.Transport{transport},
		[]*quic.Conn{conn},
		[]bool{openPrimaryStream},
		peerAddr,
		dm,
		emitter,
		clientTLS,
		serverTLS,
		false,
	), nil
}

func openExternalNativeQUICSessionStreams(ctx context.Context, session *externalNativeQUICStripedSession) (*externalNativeQUICStripedSession, []*quic.Stream, error) {
	streams, err := session.OpenQUICStreams(ctx)
	if err != nil {
		session.Close()
		return nil, nil, err
	}
	return session, streams, nil
}

func acceptExternalNativeQUICAddStripes(ctx context.Context, session *externalNativeQUICStripedSession, peerAddr net.Addr, clientTLS *tls.Config, serverTLS *tls.Config, connCount int) ([]*quic.Stream, bool, error) {
	control, streams, handled, err := openExternalNativeQUICAcceptControl(ctx, session)
	if handled || err != nil {
		return streams, handled, err
	}
	defer control.Close()

	peerCandidateSets, stripeCount, streams, handled := receiveExternalNativeQUICAcceptPeerStripeSetup(session, control, connCount)
	if handled {
		return streams, true, nil
	}

	sockets, streams, handled, err := openExternalNativeQUICAcceptStripeSockets(ctx, session, control, peerAddr, connCount-1)
	if handled || err != nil {
		return streams, handled, err
	}
	sockets = trimExternalNativeQUICAcceptStripeSockets(sockets, stripeCount)
	if !sendExternalNativeQUICAcceptStripeSetup(session, control, sockets) {
		return []*quic.Stream{control.stream}, true, nil
	}

	extraSetupCtx, extraSetupCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer extraSetupCancel()
	extraTransports, extraConns, extraOpenStreams, stripeReady := openExternalNativeQUICStripeConns(
		extraSetupCtx,
		peerAddr,
		sockets.packetConns,
		peerCandidateSets,
		clientTLS,
		serverTLS,
		false,
		"native-quic-accept-stripe-ready",
		"native-quic-primary-fallback=dial-stripe-conn err=",
		session.emitter,
	)
	if !completeExternalNativeQUICAcceptStripeReady(session, control, sockets, extraTransports, extraConns, stripeReady) {
		return []*quic.Stream{control.stream}, true, nil
	}
	attachExternalNativeQUICAcceptedStripes(session, sockets, extraTransports, extraConns, extraOpenStreams)
	return nil, false, nil
}

func openExternalNativeQUICAcceptControl(ctx context.Context, session *externalNativeQUICStripedSession) (*externalNativeQUICControlStream, []*quic.Stream, bool, error) {
	controlAcceptCtx, controlAcceptCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	controlStream, err := openExternalNativeQUICStreamForConn(controlAcceptCtx, session.conns[0], session.openStreams[0])
	controlAcceptCancel()
	if err == nil {
		externalTransferTracef("native-quic-accept-control-open")
		return newExternalNativeQUICControlStream(ctx, controlStream), nil, false, nil
	}
	stream, streamErr := openExternalNativeQUICStreamForConn(ctx, session.conns[0], session.openStreams[0])
	if streamErr != nil {
		session.Close()
		return nil, nil, false, streamErr
	}
	session.setupFallback = true
	return nil, []*quic.Stream{stream}, true, nil
}

func receiveExternalNativeQUICAcceptPeerStripeSetup(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, connCount int) ([][]string, int, []*quic.Stream, bool) {
	control.SetWaitDeadline()
	var peerSetup externalNativeQUICStripeSetup
	if err := json.NewDecoder(control.stream).Decode(&peerSetup); err != nil {
		emitExternalNativeQUICDebug(session.emitter, "native-quic-primary-fallback=decode-stripe-setup")
		session.setupFallback = true
		control.Keep()
		return nil, 0, []*quic.Stream{control.stream}, true
	}
	externalTransferTracef("native-quic-accept-peer-stripe-setup-received stripes=%d", len(peerSetup.CandidateSets))
	stripeCount := min(connCount-1, len(peerSetup.CandidateSets))
	if stripeCount == 0 {
		emitExternalNativeQUICDebug(session.emitter, "native-quic-primary-fallback=stripe-setup-size")
		session.setupFallback = true
		control.Keep()
		return nil, 0, []*quic.Stream{control.stream}, true
	}
	control.ClearDeadline()
	return peerSetup.CandidateSets, stripeCount, nil, false
}

func openExternalNativeQUICAcceptStripeSockets(ctx context.Context, session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, peerAddr net.Addr, count int) (externalNativeQUICStripeSockets, []*quic.Stream, bool, error) {
	packetConns, portmaps, candidateSets, err := openExternalNativeQUICStripePacketConns(ctx, peerAddr, session.derpMap, session.emitter, count)
	sockets := externalNativeQUICStripeSockets{
		packetConns:   packetConns,
		portmaps:      portmaps,
		candidateSets: candidateSets,
	}
	if err != nil {
		streams, handled, streamErr := acceptExternalNativeQUICFallbackStream(ctx, session, "native-quic-primary-fallback=open-stripe-sockets")
		return sockets, streams, handled, streamErr
	}
	externalTransferTracef("native-quic-accept-stripe-candidates-ready stripes=%d", len(packetConns))
	if err := ctx.Err(); err != nil {
		closeExternalNativeQUICStripePacketConns(packetConns, portmaps)
		session.setupFallback = true
		control.Keep()
		return sockets, []*quic.Stream{control.stream}, true, err
	}
	return sockets, nil, false, nil
}

func acceptExternalNativeQUICFallbackStream(ctx context.Context, session *externalNativeQUICStripedSession, debug string) ([]*quic.Stream, bool, error) {
	emitExternalNativeQUICDebug(session.emitter, debug)
	stream, streamErr := session.conns[0].AcceptStream(ctx)
	if streamErr != nil {
		session.Close()
		return nil, false, streamErr
	}
	session.setupFallback = true
	return []*quic.Stream{stream}, true, nil
}

func trimExternalNativeQUICAcceptStripeSockets(sockets externalNativeQUICStripeSockets, stripeCount int) externalNativeQUICStripeSockets {
	if stripeCount < len(sockets.packetConns) {
		closeExternalNativeQUICStripePacketConns(sockets.packetConns[stripeCount:], sockets.portmaps[stripeCount:])
		sockets.packetConns = sockets.packetConns[:stripeCount]
		sockets.portmaps = sockets.portmaps[:stripeCount]
		sockets.candidateSets = sockets.candidateSets[:stripeCount]
	}
	return sockets
}

func sendExternalNativeQUICAcceptStripeSetup(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, sockets externalNativeQUICStripeSockets) bool {
	control.SetWaitDeadline()
	if err := json.NewEncoder(control.stream).Encode(externalNativeQUICStripeSetup{CandidateSets: sockets.candidateSets}); err != nil {
		closeExternalNativeQUICStripePacketConns(sockets.packetConns, sockets.portmaps)
		emitExternalNativeQUICDebug(session.emitter, "native-quic-primary-fallback=encode-stripe-setup")
		session.setupFallback = true
		control.Keep()
		return false
	}
	control.ClearDeadline()
	return true
}

func completeExternalNativeQUICAcceptStripeReady(session *externalNativeQUICStripedSession, control *externalNativeQUICControlStream, sockets externalNativeQUICStripeSockets, extraTransports []*quic.Transport, extraConns []*quic.Conn, stripeReady bool) bool {
	control.SetWaitDeadline()
	var peerReady externalNativeQUICStripeSetupResult
	if err := json.NewDecoder(control.stream).Decode(&peerReady); err != nil {
		stripeReady = false
	}
	if err := json.NewEncoder(control.stream).Encode(externalNativeQUICStripeSetupResult{Ready: stripeReady}); err != nil || !stripeReady || !peerReady.Ready {
		cleanupExternalNativeQUICDialStripeFallback(sockets, extraTransports, extraConns)
		emitExternalNativeQUICDebug(session.emitter, "native-quic-primary-fallback")
		session.setupFallback = true
		control.Keep()
		return false
	}
	return true
}

func attachExternalNativeQUICAcceptedStripes(session *externalNativeQUICStripedSession, sockets externalNativeQUICStripeSockets, extraTransports []*quic.Transport, extraConns []*quic.Conn, extraOpenStreams []bool) {
	session.packetConns = append(session.packetConns, sockets.packetConns...)
	session.portmaps = append(session.portmaps, sockets.portmaps...)
	session.transports = append(session.transports, extraTransports...)
	session.conns = append(session.conns, extraConns...)
	session.openStreams = append(session.openStreams, extraOpenStreams...)
	externalTransferTracef("native-quic-accept-striped-ready conns=%d", len(session.conns))
	emitExternalNativeQUICStripeCount(session.emitter, len(session.conns))
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
	startExternalNativeQUICStripeOpeners(
		setupCtx,
		peerAddr,
		localPacketConns,
		peerCandidateSets,
		clientTLS,
		serverTLS,
		preferDial,
		results,
	)

	transports := make([]*quic.Transport, len(localPacketConns))
	conns := make([]*quic.Conn, len(localPacketConns))
	openStreams := make([]bool, len(localPacketConns))
	stripeReady := collectExternalNativeQUICStripeOpenResults(
		setupCancel,
		results,
		localPacketConns,
		transports,
		conns,
		openStreams,
		traceFormat,
		fallbackPrefix,
		emitter,
	)
	if stripeReady {
		return transports, conns, openStreams, true
	}
	closeExternalNativeQUICStripeOpenResults(transports, conns)
	return nil, nil, nil, false
}

func startExternalNativeQUICStripeOpeners(
	ctx context.Context,
	peerAddr net.Addr,
	localPacketConns []net.PacketConn,
	peerCandidateSets [][]string,
	clientTLS *tls.Config,
	serverTLS *tls.Config,
	preferDial bool,
	results chan<- externalNativeQUICStripeConnResult,
) {
	for i, localPacketConn := range localPacketConns {
		i := i
		localPacketConn := localPacketConn
		go func() {
			results <- openExternalNativeQUICStripeConn(ctx, peerAddr, localPacketConn, peerCandidateSets[i], clientTLS, serverTLS, preferDial, i)
		}()
	}
}

func openExternalNativeQUICStripeConn(ctx context.Context, peerAddr net.Addr, localPacketConn net.PacketConn, peerCandidates []string, clientTLS *tls.Config, serverTLS *tls.Config, preferDial bool, index int) externalNativeQUICStripeConnResult {
	result := externalNativeQUICStripeConnResult{index: index}
	stripePeerAddr, err := selectExternalNativeQUICPeerAddr(peerAddr, peerCandidates)
	if err != nil {
		result.err = err
		return result
	}
	result.peerAddr = stripePeerAddr
	result.transport, result.conn, result.openStream, result.err = dialOrAcceptExternalNativeQUICConnWithRole(
		ctx,
		localPacketConn,
		stripePeerAddr,
		clientTLS,
		serverTLS,
		preferDial,
	)
	return result
}

func collectExternalNativeQUICStripeOpenResults(
	cancel context.CancelFunc,
	results <-chan externalNativeQUICStripeConnResult,
	localPacketConns []net.PacketConn,
	transports []*quic.Transport,
	conns []*quic.Conn,
	openStreams []bool,
	traceFormat string,
	fallbackPrefix string,
	emitter *telemetry.Emitter,
) bool {
	stripeReady := true
	for range localPacketConns {
		result := <-results
		externalNativeQUICTraceStripeOpenResult(result, localPacketConns, traceFormat, emitter)
		if result.err != nil {
			if stripeReady {
				stripeReady = false
				cancel()
				externalNativeQUICEmitStripeOpenFallback(result, fallbackPrefix, emitter)
			}
			continue
		}
		transports[result.index] = result.transport
		conns[result.index] = result.conn
		openStreams[result.index] = result.openStream
	}
	return stripeReady
}

func externalNativeQUICTraceStripeOpenResult(result externalNativeQUICStripeConnResult, localPacketConns []net.PacketConn, traceFormat string, emitter *telemetry.Emitter) {
	externalTransferTracef(traceFormat+" index=%d peer=%v err=%v", result.index, result.peerAddr, result.err)
	if emitter != nil && result.peerAddr != nil {
		emitter.Debug("native-quic-stripe-local=" + localPacketConns[result.index].LocalAddr().String() + " peer=" + result.peerAddr.String())
	}
}

func externalNativeQUICEmitStripeOpenFallback(result externalNativeQUICStripeConnResult, fallbackPrefix string, emitter *telemetry.Emitter) {
	if emitter == nil {
		return
	}
	if result.peerAddr == nil {
		emitter.Debug("native-quic-primary-fallback=select-stripe-peer err=" + result.err.Error())
		return
	}
	emitter.Debug(fallbackPrefix + result.err.Error())
}

func closeExternalNativeQUICStripeOpenResults(transports []*quic.Transport, conns []*quic.Conn) {
	closeExternalNativeQUICConns(conns)
	for _, transport := range transports {
		if transport != nil {
			_ = transport.Close()
		}
	}
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
	defer func() { _ = routeProbe.Close() }()

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
		return selectExternalNativeQUICPrimaryPeerAddr(primaryPeerAddr)
	}
	primaryIP, ok := externalNativeQUICPrimaryPeerIP(primaryPeerAddr)
	if !ok {
		return cloneSessionAddr(parsed[0]), nil
	}
	return selectExternalNativeQUICMatchingPeerAddr(primaryIP, parsed)
}

func selectExternalNativeQUICPrimaryPeerAddr(primaryPeerAddr net.Addr) (net.Addr, error) {
	if primaryPeerAddr != nil {
		return cloneSessionAddr(primaryPeerAddr), nil
	}
	return nil, errors.New("no native QUIC peer candidates")
}

func externalNativeQUICPrimaryPeerIP(primaryPeerAddr net.Addr) (netip.Addr, bool) {
	primaryUDPAddr, ok := primaryPeerAddr.(*net.UDPAddr)
	if !ok || primaryUDPAddr == nil {
		return netip.Addr{}, false
	}
	primaryIP, ok := netip.AddrFromSlice(primaryUDPAddr.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return primaryIP.Unmap(), true
}

func selectExternalNativeQUICMatchingPeerAddr(primaryIP netip.Addr, parsed []net.Addr) (net.Addr, error) {
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
	pendingResults := startExternalNativeQUICConnRace(connectCtx, transport, listener, peerAddr, clientTLS, preferDial, results)
	return receiveExternalNativeQUICConnRace(ctx, connectCtx, cancel, results, pendingResults, preferDial)
}

func startExternalNativeQUICConnRace(ctx context.Context, transport *quic.Transport, listener *quic.Listener, peerAddr net.Addr, clientTLS *tls.Config, preferDial bool, results chan<- externalNativeQUICConnResult) int {
	pendingResults := 1
	if peerAddr != nil {
		pendingResults++
		startExternalNativeQUICDialRace(ctx, transport, peerAddr, clientTLS, preferDial, results)
	}
	startExternalNativeQUICAcceptRace(ctx, listener, results)
	return pendingResults
}

func startExternalNativeQUICDialRace(ctx context.Context, transport *quic.Transport, peerAddr net.Addr, clientTLS *tls.Config, preferDial bool, results chan<- externalNativeQUICConnResult) {
	go func() {
		if err := waitExternalNativeQUICDialRace(ctx, preferDial); err != nil {
			results <- externalNativeQUICConnResult{dialed: true, err: err}
			return
		}
		conn, err := transport.Dial(ctx, peerAddr, clientTLS, quicpath.DefaultQUICConfig())
		results <- externalNativeQUICConnResult{conn: conn, dialed: true, err: err}
	}()
}

func waitExternalNativeQUICDialRace(ctx context.Context, preferDial bool) error {
	if preferDial {
		return nil
	}
	delayTimer := time.NewTimer(externalNativeQUICDuplicateConnWait)
	defer delayTimer.Stop()
	select {
	case <-delayTimer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func startExternalNativeQUICAcceptRace(ctx context.Context, listener *quic.Listener, results chan<- externalNativeQUICConnResult) {
	go func() {
		conn, err := listener.Accept(ctx)
		results <- externalNativeQUICConnResult{conn: conn, err: err}
	}()
}

func receiveExternalNativeQUICConnRace(ctx context.Context, connectCtx context.Context, cancel context.CancelFunc, results <-chan externalNativeQUICConnResult, pendingResults int, preferDial bool) (*quic.Conn, bool, error) {
	var firstErr error
	var firstConn *quic.Conn
	var firstDialed bool
	for i := 0; i < pendingResults; i++ {
		if firstConn != nil {
			return finishExternalNativeQUICConnRace(ctx, cancel, results, firstConn, firstDialed, preferDial)
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

func finishExternalNativeQUICConnRace(ctx context.Context, cancel context.CancelFunc, results <-chan externalNativeQUICConnResult, firstConn *quic.Conn, firstDialed bool, preferDial bool) (*quic.Conn, bool, error) {
	if firstDialed == preferDial {
		cancel()
		return firstConn, firstDialed, nil
	}
	select {
	case result := <-results:
		if result.err == nil {
			return selectExternalNativeQUICConnRaceWinner(cancel, firstConn, firstDialed, result, preferDial)
		}
	case <-time.After(externalNativeQUICDuplicateConnWait):
	case <-ctx.Done():
	}
	cancel()
	return firstConn, firstDialed, nil
}

func selectExternalNativeQUICConnRaceWinner(cancel context.CancelFunc, firstConn *quic.Conn, firstDialed bool, result externalNativeQUICConnResult, preferDial bool) (*quic.Conn, bool, error) {
	cancel()
	if result.dialed == preferDial {
		_ = firstConn.CloseWithError(0, "")
		return result.conn, preferDial, nil
	}
	_ = result.conn.CloseWithError(0, "")
	return firstConn, firstDialed, nil
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
