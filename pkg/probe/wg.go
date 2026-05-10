// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wgtransport "github.com/shayne/derphole/pkg/wg"
)

const defaultWireGuardProbePort = 7000

var wireGuardDrainAck = []byte("ok")

type WireGuardConfig struct {
	Transport      string
	PrivateKeyHex  string
	PeerPublicHex  string
	LocalAddr      string
	PeerAddr       string
	DirectEndpoint string
	PeerCandidates []net.Addr
	Port           uint16
	Streams        int
	SizeBytes      int64
	Reverse        bool
}

type wireGuardPlan struct {
	listenerPrivHex string
	listenerPubHex  string
	senderPrivHex   string
	senderPubHex    string
	listenerAddr    netip.Addr
	senderAddr      netip.Addr
	port            int
}

func newWireGuardPlan() (wireGuardPlan, error) {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return wireGuardPlan{}, err
	}
	listenerPriv, listenerPub, err := wgtransport.GenerateKeypair()
	if err != nil {
		return wireGuardPlan{}, err
	}
	senderPriv, senderPub, err := wgtransport.GenerateKeypair()
	if err != nil {
		return wireGuardPlan{}, err
	}
	listenerAddr, senderAddr := deriveProbeIPv4Addrs(sessionID)
	port, err := allocateWireGuardProbePort()
	if err != nil {
		return wireGuardPlan{}, err
	}
	return wireGuardPlan{
		listenerPrivHex: hex.EncodeToString(listenerPriv[:]),
		listenerPubHex:  hex.EncodeToString(listenerPub[:]),
		senderPrivHex:   hex.EncodeToString(senderPriv[:]),
		senderPubHex:    hex.EncodeToString(senderPub[:]),
		listenerAddr:    listenerAddr,
		senderAddr:      senderAddr,
		port:            port,
	}, nil
}

func allocateWireGuardProbePort() (int, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("allocate wireguard probe port: %w", err)
	}
	const minPort = 20000
	const portSpan = 40000
	port := minPort + int(uint16(raw[0])<<8|uint16(raw[1]))%portSpan
	if port == defaultWireGuardProbePort {
		port++
	}
	return port, nil
}

func deriveProbeIPv4Addrs(_ [16]byte) (netip.Addr, netip.Addr) {
	listener := netip.MustParseAddr("192.168.4.29")
	sender := netip.MustParseAddr("192.168.4.28")
	return listener, sender
}

func SendWireGuard(ctx context.Context, conn net.PacketConn, src io.Reader, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer func() { _ = node.Close() }()

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	if len(cfg.PeerCandidates) > 0 {
		go PunchAddrs(punchCtx, conn, cfg.PeerCandidates, nil, defaultPunchInterval)
	}

	stats := TransferStats{
		StartedAt: time.Now(),
		Transport: PreviewTransportCaps(conn, cfg.Transport),
	}
	if wireGuardStreamCount(cfg) > 1 {
		return sendWireGuardParallel(ctx, &stats, func(ctx context.Context) (net.Conn, error) {
			return node.DialTCP(ctx, netip.AddrPortFrom(resolved.peerAddr, resolved.port))
		}, cfg)
	}
	return sendWireGuardSingle(ctx, &stats, src, func(ctx context.Context) (net.Conn, error) {
		return node.DialTCP(ctx, netip.AddrPortFrom(resolved.peerAddr, resolved.port))
	})
}

func ReceiveWireGuardToWriter(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer func() { _ = node.Close() }()

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	if len(cfg.PeerCandidates) > 0 {
		go PunchAddrs(punchCtx, conn, cfg.PeerCandidates, nil, defaultPunchInterval)
	}

	stats := TransferStats{
		StartedAt: time.Now(),
		Transport: PreviewTransportCaps(conn, cfg.Transport),
	}
	ln, err := node.ListenTCP(resolved.port)
	if err != nil {
		return TransferStats{}, err
	}
	defer func() { _ = ln.Close() }()
	if wireGuardStreamCount(cfg) > 1 {
		return receiveWireGuardParallel(ctx, &stats, ln, dst, cfg)
	}
	return receiveWireGuardSingle(ctx, &stats, dst, cfg, func(ctx context.Context) (net.Conn, error) {
		return acceptConn(ctx, ln)
	})
}

func wireGuardStreamCount(cfg WireGuardConfig) int {
	if cfg.Streams < 1 {
		return 1
	}
	return cfg.Streams
}

func wireGuardParallelShares(total int64, streams int) ([]int64, error) {
	if streams < 1 {
		streams = 1
	}
	if total < 0 {
		return nil, fmt.Errorf("negative size bytes %d", total)
	}
	shares := make([]int64, streams)
	base := total / int64(streams)
	remainder := total % int64(streams)
	for i := range shares {
		shares[i] = base
		if remainder > 0 {
			shares[i]++
			remainder--
		}
	}
	return shares, nil
}

type zeroReader struct {
	remaining int64
}

func probeWGTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_WG_TRACE")) != ""
}

func probeWGTracef(format string, args ...any) {
	if !probeWGTraceEnabled() {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "probe-wg: "+format+"\n", args...)
}

func (r *zeroReader) Read(p []byte) (int, error) {
	if r == nil || r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	r.remaining -= int64(n)
	return n, nil
}

func sendWireGuardSingle(ctx context.Context, stats *TransferStats, src io.Reader, dial func(context.Context) (net.Conn, error)) (TransferStats, error) {
	probeWGTracef("send single dial start")
	tcpConn, err := dial(ctx)
	if err != nil {
		probeWGTracef("send single dial error=%v", err)
		return TransferStats{}, err
	}
	probeWGTracef("send single dial ok local=%v remote=%v", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	defer func() { _ = tcpConn.Close() }()

	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if err := writeWireGuardSingleChunk(stats, tcpConn, buf[:n]); err != nil {
				return TransferStats{}, err
			}
		}
		if readErr == io.EOF {
			return finishWireGuardSingleSend(ctx, stats, tcpConn)
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func writeWireGuardSingleChunk(stats *TransferStats, conn net.Conn, chunk []byte) error {
	written, err := conn.Write(chunk)
	if written > 0 {
		if stats.FirstByteAt.IsZero() {
			stats.FirstByteAt = time.Now()
		}
		stats.BytesSent += int64(written)
		stats.observePeakGoodput(time.Now(), stats.BytesSent)
	}
	if err != nil {
		return err
	}
	if written != len(chunk) {
		return io.ErrShortWrite
	}
	return nil
}

func finishWireGuardSingleSend(ctx context.Context, stats *TransferStats, conn net.Conn) (TransferStats, error) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			probeWGTracef("send single closewrite error=%v sent=%d", err, stats.BytesSent)
			return TransferStats{}, err
		}
	}
	if err := waitForWireGuardAck(ctx, conn); err != nil {
		probeWGTracef("send single ack error=%v sent=%d", err, stats.BytesSent)
		return TransferStats{}, err
	}
	probeWGTracef("send single done sent=%d", stats.BytesSent)
	stats.markComplete(time.Now())
	return *stats, nil
}

func receiveWireGuardSingle(ctx context.Context, stats *TransferStats, dst io.Writer, cfg WireGuardConfig, accept func(context.Context) (net.Conn, error)) (TransferStats, error) {
	probeWGTracef("recv single accept start")
	tcpConn, err := accept(ctx)
	if err != nil {
		probeWGTracef("recv single accept error=%v", err)
		return TransferStats{}, err
	}
	probeWGTracef("recv single accept ok local=%v remote=%v", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	defer func() { _ = tcpConn.Close() }()

	buf := make([]byte, 128<<10)
	ackSent := false
	for {
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := tcpConn.Read(buf)
		if n > 0 {
			var err error
			ackSent, err = receiveWireGuardSingleChunk(stats, dst, tcpConn, buf[:n], cfg, ackSent)
			if err != nil {
				return TransferStats{}, err
			}
		}
		if readErr == io.EOF {
			return finishWireGuardSingleReceive(stats, tcpConn, cfg, ackSent)
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func receiveWireGuardSingleChunk(stats *TransferStats, dst io.Writer, conn net.Conn, chunk []byte, cfg WireGuardConfig, ackSent bool) (bool, error) {
	if stats.FirstByteAt.IsZero() {
		stats.FirstByteAt = time.Now()
	}
	written, err := dst.Write(chunk)
	if written > 0 {
		stats.BytesReceived += int64(written)
		stats.observePeakGoodput(time.Now(), stats.BytesReceived)
	}
	if err != nil {
		return ackSent, err
	}
	if written != len(chunk) {
		return ackSent, io.ErrShortWrite
	}
	if ackSent || cfg.SizeBytes <= 0 || stats.BytesReceived < cfg.SizeBytes {
		return ackSent, nil
	}
	if err := writeWireGuardDrainAck(conn); err != nil {
		probeWGTracef("recv single target ack write error=%v received=%d", err, stats.BytesReceived)
		return ackSent, err
	}
	probeWGTracef("recv single reached target received=%d", stats.BytesReceived)
	return true, nil
}

func finishWireGuardSingleReceive(stats *TransferStats, conn net.Conn, cfg WireGuardConfig, ackSent bool) (TransferStats, error) {
	if cfg.SizeBytes > 0 && stats.BytesReceived < cfg.SizeBytes {
		return TransferStats{}, io.ErrUnexpectedEOF
	}
	if !ackSent {
		if err := writeWireGuardDrainAck(conn); err != nil {
			probeWGTracef("recv single ack write error=%v received=%d", err, stats.BytesReceived)
			return TransferStats{}, err
		}
	}
	probeWGTracef("recv single done received=%d", stats.BytesReceived)
	stats.markComplete(time.Now())
	return *stats, nil
}

func sendWireGuardParallel(ctx context.Context, stats *TransferStats, dial func(context.Context) (net.Conn, error), cfg WireGuardConfig) (TransferStats, error) {
	if cfg.SizeBytes <= 0 {
		return TransferStats{}, fmt.Errorf("parallel wireguard send requires positive size bytes")
	}
	shares, err := wireGuardParallelShares(cfg.SizeBytes, wireGuardStreamCount(cfg))
	if err != nil {
		return TransferStats{}, err
	}
	return newWireGuardParallelSender(ctx, stats, dial).run(shares)
}

type wireGuardParallelSender struct {
	ctx      context.Context
	stats    *TransferStats
	dial     func(context.Context) (net.Conn, error)
	errCh    chan error
	firstSet sync.Once
	total    atomic.Int64
	peakMu   sync.Mutex
	peak     intervalStats
}

func newWireGuardParallelSender(ctx context.Context, stats *TransferStats, dial func(context.Context) (net.Conn, error)) *wireGuardParallelSender {
	sender := &wireGuardParallelSender{
		ctx:   ctx,
		stats: stats,
		dial:  dial,
	}
	sender.peak.Observe(stats.StartedAt, 0)
	return sender
}

func (s *wireGuardParallelSender) run(shares []int64) (TransferStats, error) {
	s.errCh = make(chan error, len(shares))
	var (
		wg sync.WaitGroup
	)
	for i, share := range shares {
		wg.Add(1)
		go s.runStream(&wg, i+1, share)
	}
	wg.Wait()
	close(s.errCh)
	for err := range s.errCh {
		if err != nil {
			return TransferStats{}, err
		}
	}
	s.stats.BytesSent = s.total.Load()
	s.stats.PeakGoodputMbps = s.peak.PeakMbps()
	s.stats.markComplete(time.Now())
	return *s.stats, nil
}

func (s *wireGuardParallelSender) runStream(wg *sync.WaitGroup, streamID int, share int64) {
	defer wg.Done()
	probeWGTracef("send stream=%d dial start share=%d", streamID, share)
	tcpConn, err := s.dial(s.ctx)
	if err != nil {
		s.reportStreamError(streamID, "dial", err, 0)
		return
	}
	probeWGTracef("send stream=%d dial ok local=%v remote=%v", streamID, tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	defer func() { _ = tcpConn.Close() }()

	reader := &zeroReader{remaining: share}
	buf := make([]byte, 128<<10)
	var sent int64
	for {
		if err := s.ctx.Err(); err != nil {
			s.reportStreamError(streamID, "ctx", err, sent)
			return
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			written, err := s.writeStreamChunk(tcpConn, buf[:n])
			sent += written
			if err != nil {
				s.reportStreamError(streamID, "write", err, sent)
				return
			}
		}
		if readErr == io.EOF {
			s.finishStream(streamID, tcpConn, sent)
			return
		}
		if readErr != nil {
			s.reportStreamError(streamID, "read", readErr, sent)
			return
		}
	}
}

func (s *wireGuardParallelSender) writeStreamChunk(conn net.Conn, chunk []byte) (int64, error) {
	written, err := conn.Write(chunk)
	if written > 0 {
		s.firstSet.Do(func() {
			s.stats.FirstByteAt = time.Now()
		})
		s.observePeak(time.Now(), s.total.Add(int64(written)))
	}
	if err != nil {
		return int64(written), err
	}
	if written != len(chunk) {
		return int64(written), io.ErrShortWrite
	}
	return int64(written), nil
}

func (s *wireGuardParallelSender) finishStream(streamID int, conn net.Conn, sent int64) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			s.reportStreamError(streamID, "closewrite", err, sent)
			return
		}
	}
	if err := waitForWireGuardAck(s.ctx, conn); err != nil {
		s.reportStreamError(streamID, "ack", err, sent)
		return
	}
	probeWGTracef("send stream=%d done sent=%d", streamID, sent)
}

func (s *wireGuardParallelSender) observePeak(now time.Time, totalBytes int64) {
	s.peakMu.Lock()
	defer s.peakMu.Unlock()
	s.peak.Observe(now, totalBytes)
}

func (s *wireGuardParallelSender) reportStreamError(streamID int, phase string, err error, sent int64) {
	probeWGTracef("send stream=%d %s error=%v sent=%d", streamID, phase, err, sent)
	s.errCh <- err
}

func receiveWireGuardParallel(ctx context.Context, stats *TransferStats, ln net.Listener, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	if cfg.SizeBytes <= 0 {
		return TransferStats{}, fmt.Errorf("parallel wireguard receive requires positive size bytes")
	}
	if dst != io.Discard {
		return TransferStats{}, fmt.Errorf("parallel wireguard receive only supports io.Discard")
	}
	return newWireGuardParallelReceiver(ctx, stats, ln, cfg).run()
}

type wireGuardParallelReceiver struct {
	ctx            context.Context
	recvCtx        context.Context
	cancel         context.CancelFunc
	stats          *TransferStats
	ln             net.Listener
	cfg            WireGuardConfig
	wg             sync.WaitGroup
	firstSet       sync.Once
	total          atomic.Int64
	peakMu         sync.Mutex
	peak           intervalStats
	targetReached  atomic.Bool
	activeMu       sync.Mutex
	activeConn     []net.Conn
	readerDone     chan struct{}
	connCh         chan net.Conn
	errCh          chan error
	stopAcceptOnce sync.Once
}

func newWireGuardParallelReceiver(ctx context.Context, stats *TransferStats, ln net.Listener, cfg WireGuardConfig) *wireGuardParallelReceiver {
	recvCtx, cancel := context.WithCancel(ctx)
	receiver := &wireGuardParallelReceiver{
		ctx:        ctx,
		recvCtx:    recvCtx,
		cancel:     cancel,
		stats:      stats,
		ln:         ln,
		cfg:        cfg,
		readerDone: make(chan struct{}, wireGuardStreamCount(cfg)),
		connCh:     make(chan net.Conn, wireGuardStreamCount(cfg)),
		errCh:      make(chan error, 1),
	}
	receiver.peak.Observe(stats.StartedAt, 0)
	return receiver
}

func (r *wireGuardParallelReceiver) run() (TransferStats, error) {
	defer r.cancel()
	go r.acceptLoop()

	streamsAccepted := 0
	accepting := true
	for !r.done(accepting) {
		select {
		case tcpConn, ok := <-r.connCh:
			var err error
			accepting, streamsAccepted, err = r.handleAcceptedConn(tcpConn, ok, accepting, streamsAccepted)
			if err != nil {
				return TransferStats{}, err
			}
		case err := <-r.errCh:
			if err != nil {
				return r.stopAndWaitErr(err)
			}
		case <-r.readerDone:
			if err := r.checkReaderDrain(accepting); err != nil {
				return TransferStats{}, err
			}
		case <-r.ctx.Done():
			return r.stopAndWaitErr(r.ctx.Err())
		}
	}

	r.stop()
	r.wg.Wait()
	return r.finish()
}

func (r *wireGuardParallelReceiver) finish() (TransferStats, error) {
	if err := r.ctx.Err(); err != nil && err != context.Canceled {
		return TransferStats{}, err
	}
	r.stats.BytesReceived = min(r.total.Load(), r.cfg.SizeBytes)
	r.stats.PeakGoodputMbps = r.peak.PeakMbps()
	r.stats.markComplete(time.Now())
	return *r.stats, nil
}

func (r *wireGuardParallelReceiver) done(accepting bool) bool {
	return r.targetReached.Load() && !accepting && r.activeCount() == 0
}

func (r *wireGuardParallelReceiver) activeCount() int {
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	return len(r.activeConn)
}

func (r *wireGuardParallelReceiver) acceptLoop() {
	defer close(r.connCh)
	for {
		tcpConn, err := acceptConn(r.recvCtx, r.ln)
		if err != nil {
			if r.recvCtx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				r.reportErr(err)
			}
			return
		}
		select {
		case r.connCh <- tcpConn:
		case <-r.recvCtx.Done():
			_ = tcpConn.Close()
			return
		}
	}
}

func (r *wireGuardParallelReceiver) handleAcceptedConn(tcpConn net.Conn, ok bool, accepting bool, streamsAccepted int) (bool, int, error) {
	if !ok {
		return r.handleAcceptClosed(streamsAccepted)
	}
	streamsAccepted++
	r.startReader(streamsAccepted, tcpConn)
	return accepting, streamsAccepted, nil
}

func (r *wireGuardParallelReceiver) handleAcceptClosed(streamsAccepted int) (bool, int, error) {
	r.connCh = nil
	if streamsAccepted > 0 {
		return false, streamsAccepted, nil
	}
	r.stop()
	if err := r.recvCtx.Err(); err != nil && err != context.Canceled {
		return false, streamsAccepted, err
	}
	return false, streamsAccepted, io.ErrUnexpectedEOF
}

func (r *wireGuardParallelReceiver) startReader(streamID int, conn net.Conn) {
	probeWGTracef("recv accept stream=%d local=%v remote=%v", streamID, conn.LocalAddr(), conn.RemoteAddr())
	r.activeMu.Lock()
	r.activeConn = append(r.activeConn, conn)
	r.activeMu.Unlock()
	r.wg.Add(1)
	go r.readStream(streamID, conn)
}

func (r *wireGuardParallelReceiver) readStream(streamID int, conn net.Conn) {
	defer r.finishReader(streamID, conn)
	buf := make([]byte, 128<<10)
	var received int64
	for {
		if err := r.recvCtx.Err(); err != nil {
			probeWGTracef("recv stream=%d ctx error=%v received=%d total=%d", streamID, err, received, r.total.Load())
			return
		}
		n, readErr := conn.Read(buf)
		if n > 0 {
			received += r.observeRead(streamID, int64(n), received)
		}
		if readErr == io.EOF {
			r.ackStreamEOF(streamID, conn, received)
			return
		}
		if readErr != nil {
			r.reportReadError(streamID, readErr, received)
			return
		}
	}
}

func (r *wireGuardParallelReceiver) observeRead(streamID int, n int64, received int64) int64 {
	r.firstSet.Do(func() {
		r.stats.FirstByteAt = time.Now()
	})
	newTotal := r.total.Add(n)
	r.observePeak(time.Now(), newTotal)
	if newTotal >= r.cfg.SizeBytes && r.targetReached.CompareAndSwap(false, true) {
		probeWGTracef("recv stream=%d reached target received=%d total=%d", streamID, received+n, newTotal)
		r.stopAccepting()
	}
	return n
}

func (r *wireGuardParallelReceiver) ackStreamEOF(streamID int, conn net.Conn, received int64) {
	if err := writeWireGuardDrainAck(conn); err != nil {
		probeWGTracef("recv stream=%d ack write error=%v received=%d total=%d", streamID, err, received, r.total.Load())
		r.reportErr(err)
		r.stop()
		return
	}
	probeWGTracef("recv stream=%d eof received=%d total=%d", streamID, received, r.total.Load())
}

func (r *wireGuardParallelReceiver) reportReadError(streamID int, err error, received int64) {
	probeWGTracef("recv stream=%d read error=%v received=%d total=%d", streamID, err, received, r.total.Load())
	r.reportErr(err)
	r.stop()
}

func (r *wireGuardParallelReceiver) finishReader(streamID int, conn net.Conn) {
	r.wg.Done()
	_ = conn.Close()
	r.removeActive(conn)
	select {
	case r.readerDone <- struct{}{}:
	default:
	}
	probeWGTracef("recv stream=%d reader done total=%d", streamID, r.total.Load())
}

func (r *wireGuardParallelReceiver) removeActive(conn net.Conn) {
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	for i, active := range r.activeConn {
		if active == conn {
			r.activeConn = append(r.activeConn[:i], r.activeConn[i+1:]...)
			return
		}
	}
}

func (r *wireGuardParallelReceiver) checkReaderDrain(accepting bool) error {
	if accepting || r.activeCount() > 0 || r.total.Load() >= r.cfg.SizeBytes {
		return nil
	}
	r.stop()
	r.wg.Wait()
	return io.ErrUnexpectedEOF
}

func (r *wireGuardParallelReceiver) observePeak(now time.Time, totalBytes int64) {
	r.peakMu.Lock()
	defer r.peakMu.Unlock()
	r.peak.Observe(now, totalBytes)
}

func (r *wireGuardParallelReceiver) stopAccepting() {
	r.stopAcceptOnce.Do(func() {
		_ = r.ln.Close()
	})
}

func (r *wireGuardParallelReceiver) stop() {
	r.cancel()
	r.stopAccepting()
	r.activeMu.Lock()
	defer r.activeMu.Unlock()
	for _, conn := range r.activeConn {
		_ = conn.Close()
	}
	r.activeConn = nil
}

func (r *wireGuardParallelReceiver) stopAndWaitErr(err error) (TransferStats, error) {
	r.stop()
	r.wg.Wait()
	return TransferStats{}, err
}

func (r *wireGuardParallelReceiver) reportErr(err error) {
	select {
	case r.errCh <- err:
	default:
	}
}

type resolvedWireGuardConfig struct {
	privateKey [32]byte
	peerPublic [32]byte
	localAddr  netip.Addr
	peerAddr   netip.Addr
	port       uint16
}

func newWireGuardNode(conn net.PacketConn, cfg WireGuardConfig) (*wgtransport.Node, resolvedWireGuardConfig, error) {
	resolved, err := resolveWireGuardConfig(conn, cfg)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	node, err := wgtransport.NewNode(wgtransport.Config{
		PrivateKey:     resolved.privateKey,
		PeerPublicKey:  resolved.peerPublic,
		LocalAddr:      resolved.localAddr,
		PeerAddr:       resolved.peerAddr,
		PacketConn:     conn,
		Transport:      cfg.Transport,
		DirectEndpoint: strings.TrimSpace(cfg.DirectEndpoint),
	})
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	return node, resolved, nil
}

func parseHex32(raw string) ([32]byte, error) {
	var out [32]byte
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return out, err
	}
	if len(decoded) != len(out) {
		return out, fmt.Errorf("got %d bytes, want %d", len(decoded), len(out))
	}
	copy(out[:], decoded)
	return out, nil
}

func acceptConn(ctx context.Context, ln net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		_ = ln.Close()
		return nil, ctx.Err()
	case res := <-ch:
		return res.conn, res.err
	}
}

func waitForWireGuardAck(ctx context.Context, conn net.Conn) error {
	buf := make([]byte, len(wireGuardDrainAck))
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if !bytes.Equal(buf, wireGuardDrainAck) {
		return fmt.Errorf("unexpected wireguard drain ack %q", buf)
	}
	return nil
}

func writeWireGuardDrainAck(conn net.Conn) error {
	if _, err := conn.Write(wireGuardDrainAck); err != nil {
		return err
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	return nil
}
