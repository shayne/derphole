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

	wgtransport "github.com/shayne/derpcat/pkg/wg"
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
	defer node.Close()

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
	probeWGTracef("send single dial start peer=%s:%d", resolved.peerAddr, resolved.port)
	tcpConn, err := node.DialTCP(ctx, netip.AddrPortFrom(resolved.peerAddr, resolved.port))
	if err != nil {
		probeWGTracef("send single dial error=%v", err)
		return TransferStats{}, err
	}
	probeWGTracef("send single dial ok local=%v remote=%v", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	defer tcpConn.Close()

	var closeWrite func() error
	if closer, ok := tcpConn.(interface{ CloseWrite() error }); ok {
		closeWrite = closer.CloseWrite
	}

	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := tcpConn.Write(buf[:n])
			if written > 0 {
				if stats.FirstByteAt.IsZero() {
					stats.FirstByteAt = time.Now()
				}
				stats.BytesSent += int64(written)
				stats.observePeakGoodput(time.Now(), stats.BytesSent)
			}
			if writeErr != nil {
				return TransferStats{}, writeErr
			}
			if written != n {
				return TransferStats{}, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			if closeWrite != nil {
				if err := closeWrite(); err != nil {
					probeWGTracef("send single closewrite error=%v sent=%d", err, stats.BytesSent)
					return TransferStats{}, err
				}
			}
			if err := waitForWireGuardAck(ctx, tcpConn); err != nil {
				probeWGTracef("send single ack error=%v sent=%d", err, stats.BytesSent)
				return TransferStats{}, err
			}
			probeWGTracef("send single done sent=%d", stats.BytesSent)
			stats.markComplete(time.Now())
			return stats, nil
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func ReceiveWireGuardToWriter(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer node.Close()

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
	defer ln.Close()
	if wireGuardStreamCount(cfg) > 1 {
		return receiveWireGuardParallel(ctx, &stats, ln, dst, cfg)
	}

	probeWGTracef("recv single accept start port=%d", resolved.port)
	tcpConn, err := acceptConn(ctx, ln)
	if err != nil {
		probeWGTracef("recv single accept error=%v", err)
		return TransferStats{}, err
	}
	probeWGTracef("recv single accept ok local=%v remote=%v", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	defer tcpConn.Close()

	buf := make([]byte, 128<<10)
	ackSent := false
	for {
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := tcpConn.Read(buf)
		if n > 0 {
			if stats.FirstByteAt.IsZero() {
				stats.FirstByteAt = time.Now()
			}
			written, writeErr := dst.Write(buf[:n])
			if written > 0 {
				stats.BytesReceived += int64(written)
				stats.observePeakGoodput(time.Now(), stats.BytesReceived)
			}
			if writeErr != nil {
				return TransferStats{}, writeErr
			}
			if written != n {
				return TransferStats{}, io.ErrShortWrite
			}
			if !ackSent && cfg.SizeBytes > 0 && stats.BytesReceived >= cfg.SizeBytes {
				if err := writeWireGuardDrainAck(tcpConn); err != nil {
					probeWGTracef("recv single target ack write error=%v received=%d", err, stats.BytesReceived)
					return TransferStats{}, err
				}
				probeWGTracef("recv single reached target received=%d", stats.BytesReceived)
				ackSent = true
			}
		}
		if readErr == io.EOF {
			if cfg.SizeBytes > 0 && stats.BytesReceived < cfg.SizeBytes {
				return TransferStats{}, io.ErrUnexpectedEOF
			}
			if !ackSent {
				if err := writeWireGuardDrainAck(tcpConn); err != nil {
					probeWGTracef("recv single ack write error=%v received=%d", err, stats.BytesReceived)
					return TransferStats{}, err
				}
			}
			probeWGTracef("recv single done received=%d", stats.BytesReceived)
			stats.markComplete(time.Now())
			return stats, nil
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
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
	return strings.TrimSpace(os.Getenv("DERPCAT_PROBE_WG_TRACE")) != ""
}

func probeWGTracef(format string, args ...any) {
	if !probeWGTraceEnabled() {
		return
	}
	fmt.Fprintf(os.Stderr, "probe-wg: "+format+"\n", args...)
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

func sendWireGuardParallel(ctx context.Context, stats *TransferStats, dial func(context.Context) (net.Conn, error), cfg WireGuardConfig) (TransferStats, error) {
	if cfg.SizeBytes <= 0 {
		return TransferStats{}, fmt.Errorf("parallel wireguard send requires positive size bytes")
	}
	shares, err := wireGuardParallelShares(cfg.SizeBytes, wireGuardStreamCount(cfg))
	if err != nil {
		return TransferStats{}, err
	}
	var (
		wg       sync.WaitGroup
		errCh    = make(chan error, len(shares))
		firstSet sync.Once
		total    atomic.Int64
		peakMu   sync.Mutex
		peak     intervalStats
	)
	peak.Observe(stats.StartedAt, 0)
	observePeak := func(now time.Time, totalBytes int64) {
		peakMu.Lock()
		peak.Observe(now, totalBytes)
		peakMu.Unlock()
	}
	for i, share := range shares {
		streamID := i + 1
		share := share
		wg.Add(1)
		go func(streamID int, share int64) {
			defer wg.Done()
			probeWGTracef("send stream=%d dial start share=%d", streamID, share)
			tcpConn, err := dial(ctx)
			if err != nil {
				probeWGTracef("send stream=%d dial error=%v", streamID, err)
				errCh <- err
				return
			}
			probeWGTracef("send stream=%d dial ok local=%v remote=%v", streamID, tcpConn.LocalAddr(), tcpConn.RemoteAddr())
			defer tcpConn.Close()
			buf := make([]byte, 128<<10)
			reader := &zeroReader{remaining: share}
			var sent int64
			for {
				if err := ctx.Err(); err != nil {
					probeWGTracef("send stream=%d ctx error=%v sent=%d", streamID, err, sent)
					errCh <- err
					return
				}
				n, readErr := reader.Read(buf)
				if n > 0 {
					written, writeErr := tcpConn.Write(buf[:n])
					if written > 0 {
						firstSet.Do(func() {
							stats.FirstByteAt = time.Now()
						})
						totalBytes := total.Add(int64(written))
						observePeak(time.Now(), totalBytes)
						sent += int64(written)
					}
					if writeErr != nil {
						probeWGTracef("send stream=%d write error=%v sent=%d", streamID, writeErr, sent)
						errCh <- writeErr
						return
					}
					if written != n {
						probeWGTracef("send stream=%d short write written=%d want=%d sent=%d", streamID, written, n, sent)
						errCh <- io.ErrShortWrite
						return
					}
				}
				if readErr == io.EOF {
					if closer, ok := tcpConn.(interface{ CloseWrite() error }); ok {
						if err := closer.CloseWrite(); err != nil {
							probeWGTracef("send stream=%d closewrite error=%v sent=%d", streamID, err, sent)
							errCh <- err
							return
						}
					}
					if err := waitForWireGuardAck(ctx, tcpConn); err != nil {
						probeWGTracef("send stream=%d ack error=%v sent=%d", streamID, err, sent)
						errCh <- err
						return
					}
					probeWGTracef("send stream=%d done sent=%d", streamID, sent)
					return
				}
				if readErr != nil {
					probeWGTracef("send stream=%d read error=%v sent=%d", streamID, readErr, sent)
					errCh <- readErr
					return
				}
			}
		}(streamID, share)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return TransferStats{}, err
		}
	}
	stats.BytesSent = total.Load()
	stats.PeakGoodputMbps = peak.PeakMbps()
	stats.markComplete(time.Now())
	return *stats, nil
}

func receiveWireGuardParallel(ctx context.Context, stats *TransferStats, ln net.Listener, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	if cfg.SizeBytes <= 0 {
		return TransferStats{}, fmt.Errorf("parallel wireguard receive requires positive size bytes")
	}
	if dst != io.Discard {
		return TransferStats{}, fmt.Errorf("parallel wireguard receive only supports io.Discard")
	}
	recvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg             sync.WaitGroup
		firstSet       sync.Once
		total          atomic.Int64
		peakMu         sync.Mutex
		peak           intervalStats
		targetReached  atomic.Bool
		activeMu       sync.Mutex
		activeConn     []net.Conn
		readerDone     = make(chan struct{}, wireGuardStreamCount(cfg))
		connCh         = make(chan net.Conn, wireGuardStreamCount(cfg))
		errCh          = make(chan error, 1)
		stopAcceptOnce sync.Once
	)
	peak.Observe(stats.StartedAt, 0)
	observePeak := func(now time.Time, totalBytes int64) {
		peakMu.Lock()
		peak.Observe(now, totalBytes)
		peakMu.Unlock()
	}

	stopAccepting := func() {
		stopAcceptOnce.Do(func() {
			_ = ln.Close()
		})
	}

	stop := func() {
		cancel()
		stopAccepting()
		activeMu.Lock()
		defer activeMu.Unlock()
		for _, conn := range activeConn {
			_ = conn.Close()
		}
		activeConn = nil
	}

	go func() {
		defer close(connCh)
		for {
			tcpConn, err := acceptConn(recvCtx, ln)
			if err != nil {
				if recvCtx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case connCh <- tcpConn:
			case <-recvCtx.Done():
				_ = tcpConn.Close()
				return
			}
		}
	}()

	streamsAccepted := 0
	accepting := true
	for {
		activeMu.Lock()
		active := len(activeConn)
		activeMu.Unlock()
		if targetReached.Load() && !accepting && active == 0 {
			break
		}
		select {
		case tcpConn, ok := <-connCh:
			if !ok {
				accepting = false
				connCh = nil
				if streamsAccepted == 0 {
					stop()
					if err := recvCtx.Err(); err != nil && err != context.Canceled {
						return TransferStats{}, err
					}
					return TransferStats{}, io.ErrUnexpectedEOF
				}
				continue
			}
			streamsAccepted++
			streamID := streamsAccepted
			probeWGTracef("recv accept stream=%d local=%v remote=%v", streamID, tcpConn.LocalAddr(), tcpConn.RemoteAddr())
			activeMu.Lock()
			activeConn = append(activeConn, tcpConn)
			activeMu.Unlock()
			wg.Add(1)
			go func(streamID int, conn net.Conn) {
				defer wg.Done()
				defer func() {
					_ = conn.Close()
					activeMu.Lock()
					for i, active := range activeConn {
						if active == conn {
							activeConn = append(activeConn[:i], activeConn[i+1:]...)
							break
						}
					}
					activeMu.Unlock()
					select {
					case readerDone <- struct{}{}:
					default:
					}
					probeWGTracef("recv stream=%d reader done total=%d", streamID, total.Load())
				}()

				buf := make([]byte, 128<<10)
				var received int64
				for {
					if err := recvCtx.Err(); err != nil {
						probeWGTracef("recv stream=%d ctx error=%v received=%d total=%d", streamID, err, received, total.Load())
						return
					}
					n, readErr := conn.Read(buf)
					if n > 0 {
						firstSet.Do(func() {
							stats.FirstByteAt = time.Now()
						})
						newTotal := total.Add(int64(n))
						observePeak(time.Now(), newTotal)
						received += int64(n)
						if newTotal >= cfg.SizeBytes && targetReached.CompareAndSwap(false, true) {
							probeWGTracef("recv stream=%d reached target received=%d total=%d", streamID, received, newTotal)
							stopAccepting()
						}
					}
					if readErr == io.EOF {
						if err := writeWireGuardDrainAck(conn); err != nil {
							probeWGTracef("recv stream=%d ack write error=%v received=%d total=%d", streamID, err, received, total.Load())
							select {
							case errCh <- err:
							default:
							}
							stop()
							return
						}
						probeWGTracef("recv stream=%d eof received=%d total=%d", streamID, received, total.Load())
						return
					}
					if readErr != nil {
						probeWGTracef("recv stream=%d read error=%v received=%d total=%d", streamID, readErr, received, total.Load())
						select {
						case errCh <- readErr:
						default:
						}
						stop()
						return
					}
				}
			}(streamID, tcpConn)
		case err := <-errCh:
			if err != nil {
				stop()
				wg.Wait()
				return TransferStats{}, err
			}
		case <-readerDone:
			if !accepting {
				activeMu.Lock()
				active := len(activeConn)
				activeMu.Unlock()
				if active == 0 && total.Load() < cfg.SizeBytes {
					stop()
					wg.Wait()
					return TransferStats{}, io.ErrUnexpectedEOF
				}
			}
		case <-ctx.Done():
			stop()
			wg.Wait()
			return TransferStats{}, ctx.Err()
		}
	}

	stop()
	wg.Wait()
	if err := ctx.Err(); err != nil && err != context.Canceled {
		return TransferStats{}, err
	}
	stats.BytesReceived = min(total.Load(), cfg.SizeBytes)
	stats.PeakGoodputMbps = peak.PeakMbps()
	stats.markComplete(time.Now())
	return *stats, nil
}

type resolvedWireGuardConfig struct {
	privateKey [32]byte
	peerPublic [32]byte
	localAddr  netip.Addr
	peerAddr   netip.Addr
	port       uint16
}

func newWireGuardNode(conn net.PacketConn, cfg WireGuardConfig) (*wgtransport.Node, resolvedWireGuardConfig, error) {
	if conn == nil {
		return nil, resolvedWireGuardConfig{}, fmt.Errorf("nil packet conn")
	}
	if strings.TrimSpace(cfg.Transport) == "" {
		cfg.Transport = probeTransportBatched
	}
	if cfg.Transport != probeTransportBatched {
		return nil, resolvedWireGuardConfig{}, fmt.Errorf("wireguard probe mode requires %q transport", probeTransportBatched)
	}
	privateKey, err := parseHex32(cfg.PrivateKeyHex)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, fmt.Errorf("parse wg private key: %w", err)
	}
	peerPublic, err := parseHex32(cfg.PeerPublicHex)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, fmt.Errorf("parse wg peer public key: %w", err)
	}
	localAddr, err := netip.ParseAddr(strings.TrimSpace(cfg.LocalAddr))
	if err != nil {
		return nil, resolvedWireGuardConfig{}, fmt.Errorf("parse wg local addr: %w", err)
	}
	peerAddr, err := netip.ParseAddr(strings.TrimSpace(cfg.PeerAddr))
	if err != nil {
		return nil, resolvedWireGuardConfig{}, fmt.Errorf("parse wg peer addr: %w", err)
	}
	port := cfg.Port
	if port == 0 {
		port = defaultWireGuardProbePort
	}
	node, err := wgtransport.NewNode(wgtransport.Config{
		PrivateKey:     privateKey,
		PeerPublicKey:  peerPublic,
		LocalAddr:      localAddr,
		PeerAddr:       peerAddr,
		PacketConn:     conn,
		Transport:      cfg.Transport,
		DirectEndpoint: strings.TrimSpace(cfg.DirectEndpoint),
	})
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	return node, resolvedWireGuardConfig{
		privateKey: privateKey,
		peerPublic: peerPublic,
		localAddr:  localAddr,
		peerAddr:   peerAddr,
		port:       port,
	}, nil
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
