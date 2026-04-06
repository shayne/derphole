package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate wireguard probe port: %w", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, fmt.Errorf("allocate wireguard probe port: unexpected listener addr %T", ln.Addr())
	}
	return addr.Port, nil
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
	tcpConn, err := node.DialTCP(ctx, netip.AddrPortFrom(resolved.peerAddr, resolved.port))
	if err != nil {
		return TransferStats{}, err
	}
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
					return TransferStats{}, err
				}
			}
			if err := waitForWireGuardAck(ctx, tcpConn); err != nil {
				return TransferStats{}, err
			}
			stats.CompletedAt = time.Now()
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

	tcpConn, err := acceptConn(ctx, ln)
	if err != nil {
		return TransferStats{}, err
	}
	defer tcpConn.Close()

	buf := make([]byte, 128<<10)
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
			}
			if writeErr != nil {
				return TransferStats{}, writeErr
			}
			if written != n {
				return TransferStats{}, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			if _, err := tcpConn.Write(wireGuardDrainAck); err != nil {
				return TransferStats{}, err
			}
			stats.CompletedAt = time.Now()
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
	)
	for _, share := range shares {
		share := share
		wg.Add(1)
		go func() {
			defer wg.Done()
			tcpConn, err := dial(ctx)
			if err != nil {
				errCh <- err
				return
			}
			defer tcpConn.Close()
			buf := make([]byte, 128<<10)
			reader := &zeroReader{remaining: share}
			for {
				if err := ctx.Err(); err != nil {
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
						total.Add(int64(written))
					}
					if writeErr != nil {
						errCh <- writeErr
						return
					}
					if written != n {
						errCh <- io.ErrShortWrite
						return
					}
				}
				if readErr == io.EOF {
					if closer, ok := tcpConn.(interface{ CloseWrite() error }); ok {
						if err := closer.CloseWrite(); err != nil {
							errCh <- err
							return
						}
					}
					return
				}
				if readErr != nil {
					errCh <- readErr
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return TransferStats{}, err
		}
	}
	stats.BytesSent = total.Load()
	stats.CompletedAt = time.Now()
	return *stats, nil
}

func receiveWireGuardParallel(ctx context.Context, stats *TransferStats, ln net.Listener, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	if cfg.SizeBytes <= 0 {
		return TransferStats{}, fmt.Errorf("parallel wireguard receive requires positive size bytes")
	}
	if dst != io.Discard {
		return TransferStats{}, fmt.Errorf("parallel wireguard receive only supports io.Discard")
	}
	streams := wireGuardStreamCount(cfg)
	var (
		wg       sync.WaitGroup
		errCh    = make(chan error, streams)
		firstSet sync.Once
		total    atomic.Int64
	)
	for i := 0; i < streams; i++ {
		tcpConn, err := acceptConn(ctx, ln)
		if err != nil {
			return TransferStats{}, err
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			defer conn.Close()
			buf := make([]byte, 128<<10)
			for {
				if err := ctx.Err(); err != nil {
					errCh <- err
					return
				}
				n, readErr := conn.Read(buf)
				if n > 0 {
					firstSet.Do(func() {
						stats.FirstByteAt = time.Now()
					})
					total.Add(int64(n))
				}
				if readErr == io.EOF {
					return
				}
				if readErr != nil {
					errCh <- readErr
					return
				}
			}
		}(tcpConn)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return TransferStats{}, err
		}
	}
	stats.BytesReceived = total.Load()
	stats.CompletedAt = time.Now()
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
