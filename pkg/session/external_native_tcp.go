package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"
)

const externalNativeTCPDialFallbackDelay = 150 * time.Millisecond
const externalNativeTCPCopyBufferSize = 1 << 20
const defaultExternalNativeTCPConns = 2
const externalNativeTCPBearerAuthSize = 32 + sha256.Size

var externalNativeTCPBearerAuthDomain = []byte("derpcat-native-tcp-v1")

var externalNativeTCPAddrAllowed = externalNativeTCPAddrAllowedDefault
var externalNativeTCPListen = listenExternalNativeTCP

type externalNativeTCPAuth struct {
	Enabled      bool
	SessionID    [16]byte
	BearerSecret [32]byte
	LocalPublic  [32]byte
	PeerPublic   [32]byte
}

func externalNativeTCPAddrAllowedDefault(addr net.Addr) bool {
	ip, ok := sessionAddrIP(addr)
	if !ok {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip)
}

func externalNativeTCPConnCount() int {
	if raw := os.Getenv("DERPCAT_NATIVE_TCP_CONNS"); raw != "" {
		count, err := strconv.Atoi(raw)
		if err == nil && count > 0 {
			return count
		}
	}
	return defaultExternalNativeTCPConns
}

func externalNativeTCPHandshakeConnCount(peerCount, localCount int) int {
	if localCount < 1 {
		localCount = 1
	}
	if peerCount < 1 || peerCount >= localCount {
		return localCount
	}
	return peerCount
}

func listenExternalNativeTCP(addr net.Addr, tlsConfig *tls.Config) (net.Listener, error) {
	tcpAddr, network, ok := externalNativeTCPAddr(addr)
	if !ok {
		return nil, errors.New("native tcp direct address unavailable")
	}
	ln, err := net.Listen(network, tcpAddr.String())
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return ln, nil
	}
	return tls.NewListener(ln, tlsConfig), nil
}

func listenExternalNativeTCPOnCandidates(addrs []net.Addr, tlsConfig *tls.Config) (net.Listener, bool) {
	for _, addr := range externalNativeTCPListenCandidates(addrs) {
		if !externalNativeTCPAddrAllowed(addr) {
			continue
		}
		addrTLSConfig := tlsConfig
		if externalNativeTCPAddrIsTailscale(addr) {
			addrTLSConfig = nil
		}
		ln, err := externalNativeTCPListen(addr, addrTLSConfig)
		if err != nil {
			continue
		}
		return ln, true
	}
	return nil, false
}

func externalNativeTCPListenCandidates(addrs []net.Addr) []net.Addr {
	if len(addrs) == 0 {
		return nil
	}
	out := append([]net.Addr(nil), addrs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && externalNativeTCPAddrRank(out[j]) < externalNativeTCPAddrRank(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func externalNativeTCPAddrRank(addr net.Addr) int {
	ip, ok := sessionAddrIP(addr)
	if !ok {
		return 4
	}
	if publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip) {
		return 0
	}
	if ip.IsLoopback() {
		return 1
	}
	if ip.IsPrivate() {
		return 2
	}
	return 3
}

func selectExternalNativeTCPResponseAddr(requestAddr, peerAddr net.Addr, localCandidates []net.Addr) net.Addr {
	if requestAddr != nil {
		if addr := selectExternalQUICModeResponseAddr(requestAddr, localCandidates); addr != nil {
			return addr
		}
	}
	return selectExternalQUICModeResponseAddr(peerAddr, localCandidates)
}

func externalNativeTCPUseBearerAuth(localAddr, peerAddr net.Addr) bool {
	return externalNativeTCPAddrIsTailscale(localAddr) && externalNativeTCPAddrIsTailscale(peerAddr)
}

func externalNativeTCPAddrIsTailscale(addr net.Addr) bool {
	ip, ok := sessionAddrIP(addr)
	if !ok {
		return false
	}
	return publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip)
}

func dialExternalNativeTCP(ctx context.Context, addr net.Addr, tlsConfig *tls.Config, auth externalNativeTCPAuth) (net.Conn, error) {
	tcpAddr, network, ok := externalNativeTCPAddr(addr)
	if !ok {
		return nil, errors.New("native tcp direct address unavailable")
	}
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, network, tcpAddr.String())
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		if auth.Enabled {
			if err := dialExternalNativeTCPBearerAuth(ctx, rawConn, auth.SessionID, auth.BearerSecret, auth.LocalPublic, auth.PeerPublic); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
		}
		return rawConn, nil
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func acceptExternalNativeTCP(ctx context.Context, ln net.Listener, auth externalNativeTCPAuth) (net.Conn, error) {
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	select {
	case conn := <-connCh:
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			if auth.Enabled {
				if err := acceptExternalNativeTCPBearerAuth(ctx, conn, auth.SessionID, auth.BearerSecret, auth.LocalPublic, auth.PeerPublic); err != nil {
					_ = conn.Close()
					return nil, err
				}
			}
			return conn, nil
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		return tlsConn, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		_ = ln.Close()
		return nil, ctx.Err()
	}
}

func dialExternalNativeTCPConns(ctx context.Context, addr net.Addr, tlsConfig *tls.Config, auth externalNativeTCPAuth, connCount int) ([]net.Conn, error) {
	if connCount < 1 {
		return nil, errors.New("native tcp connection count must be positive")
	}
	conns := make([]net.Conn, 0, connCount)
	for range connCount {
		conn, err := dialExternalNativeTCP(ctx, addr, tlsConfig, auth)
		if err != nil {
			closeExternalNativeTCPConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func acceptExternalNativeTCPConns(ctx context.Context, ln net.Listener, auth externalNativeTCPAuth, connCount int) ([]net.Conn, error) {
	defer ln.Close()

	if connCount < 1 {
		return nil, errors.New("native tcp connection count must be positive")
	}
	conns := make([]net.Conn, 0, connCount)
	for range connCount {
		conn, err := acceptExternalNativeTCP(ctx, ln, auth)
		if err != nil {
			closeExternalNativeTCPConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func connectExternalNativeTCPConns(ctx context.Context, ln net.Listener, peerAddr net.Addr, clientTLSConfig *tls.Config, auth externalNativeTCPAuth, dialDelay time.Duration, connCount int) ([]net.Conn, error) {
	defer ln.Close()

	if connCount < 1 {
		return nil, errors.New("native tcp connection count must be positive")
	}
	conn, accepted, err := connectExternalNativeTCPConn(ctx, ln, peerAddr, clientTLSConfig, auth, dialDelay)
	if err != nil {
		return nil, err
	}
	conns := []net.Conn{conn}
	if connCount == 1 {
		return conns, nil
	}
	if accepted {
		extraConns, err := acceptExternalNativeTCPConns(ctx, ln, auth, connCount-1)
		if err != nil {
			closeExternalNativeTCPConns(conns)
			return nil, err
		}
		return append(conns, extraConns...), nil
	}
	_ = ln.Close()
	extraConns, err := dialExternalNativeTCPConns(ctx, peerAddr, clientTLSConfig, auth, connCount-1)
	if err != nil {
		closeExternalNativeTCPConns(conns)
		return nil, err
	}
	return append(conns, extraConns...), nil
}

func connectExternalNativeTCPSender(ctx context.Context, ln net.Listener, peerAddr net.Addr, clientTLSConfig *tls.Config, auth externalNativeTCPAuth) (net.Conn, error) {
	return connectExternalNativeTCP(ctx, ln, peerAddr, clientTLSConfig, auth, 0)
}

func connectExternalNativeTCPListener(ctx context.Context, ln net.Listener, peerAddr net.Addr, clientTLSConfig *tls.Config, auth externalNativeTCPAuth) (net.Conn, error) {
	return connectExternalNativeTCP(ctx, ln, peerAddr, clientTLSConfig, auth, externalNativeTCPDialFallbackDelay)
}

func connectExternalNativeTCP(ctx context.Context, ln net.Listener, peerAddr net.Addr, clientTLSConfig *tls.Config, auth externalNativeTCPAuth, dialDelay time.Duration) (net.Conn, error) {
	defer ln.Close()
	conn, _, err := connectExternalNativeTCPConn(ctx, ln, peerAddr, clientTLSConfig, auth, dialDelay)
	return conn, err
}

func connectExternalNativeTCPConn(ctx context.Context, ln net.Listener, peerAddr net.Addr, clientTLSConfig *tls.Config, auth externalNativeTCPAuth, dialDelay time.Duration) (net.Conn, bool, error) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn     net.Conn
		accepted bool
		err      error
	}
	resultCh := make(chan result, 2)
	go func() {
		conn, err := acceptExternalNativeTCP(connCtx, ln, auth)
		resultCh <- result{conn: conn, accepted: true, err: err}
	}()
	go func() {
		timer := time.NewTimer(dialDelay)
		defer timer.Stop()
		select {
		case <-connCtx.Done():
			resultCh <- result{err: connCtx.Err()}
			return
		case <-timer.C:
		}
		conn, err := dialExternalNativeTCP(connCtx, peerAddr, clientTLSConfig, auth)
		resultCh <- result{conn: conn, err: err}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case result := <-resultCh:
			if result.err == nil && result.conn != nil {
				cancel()
				select {
				case extra := <-resultCh:
					if extra.conn != nil {
						_ = extra.conn.Close()
					}
				case <-time.After(externalNativeTCPDialFallbackDelay):
				}
				return result.conn, result.accepted, nil
			}
			if result.conn != nil {
				_ = result.conn.Close()
			}
			if firstErr == nil {
				firstErr = result.err
			}
		case <-connCtx.Done():
			if firstErr != nil {
				return nil, false, firstErr
			}
			return nil, false, connCtx.Err()
		}
	}
	if firstErr != nil {
		return nil, false, firstErr
	}
	return nil, false, errors.New("native tcp direct connection unavailable")
}

func copyExternalNativeTCP(ctx context.Context, dst io.Writer, src io.Reader) error {
	type copyResult struct {
		err error
	}
	resultCh := make(chan copyResult, 1)
	go func() {
		_, err := io.CopyBuffer(dst, src, make([]byte, externalNativeTCPCopyBufferSize))
		resultCh <- copyResult{err: err}
	}()

	select {
	case result := <-resultCh:
		return result.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func dialExternalNativeTCPBearerAuth(ctx context.Context, conn net.Conn, sessionID [16]byte, bearerSecret, localPublic, peerPublic [32]byte) error {
	if err := conn.SetDeadline(time.Now().Add(externalNativeQUICWait)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	var msg [externalNativeTCPBearerAuthSize]byte
	if _, err := rand.Read(msg[:32]); err != nil {
		return err
	}
	mac := externalNativeTCPBearerMAC(sessionID, bearerSecret, localPublic, peerPublic, msg[:32])
	copy(msg[32:], mac[:])
	if _, err := conn.Write(msg[:]); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func acceptExternalNativeTCPBearerAuth(ctx context.Context, conn net.Conn, sessionID [16]byte, bearerSecret, localPublic, peerPublic [32]byte) error {
	if err := conn.SetDeadline(time.Now().Add(externalNativeQUICWait)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	var msg [externalNativeTCPBearerAuthSize]byte
	if _, err := io.ReadFull(conn, msg[:]); err != nil {
		return err
	}
	expected := externalNativeTCPBearerMAC(sessionID, bearerSecret, peerPublic, localPublic, msg[:32])
	if !hmac.Equal(msg[32:], expected[:]) {
		return errors.New("native tcp bearer authentication failed")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func externalNativeTCPBearerMAC(sessionID [16]byte, bearerSecret, localPublic, peerPublic [32]byte, nonce []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, bearerSecret[:])
	mac.Write(externalNativeTCPBearerAuthDomain)
	mac.Write(sessionID[:])
	mac.Write(localPublic[:])
	mac.Write(peerPublic[:])
	mac.Write(nonce)
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func closeExternalNativeTCPConns(conns []net.Conn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func externalNativeTCPAddr(addr net.Addr) (*net.TCPAddr, string, bool) {
	switch typed := addr.(type) {
	case *net.UDPAddr:
		if typed == nil {
			return nil, "", false
		}
		network := "tcp4"
		if typed.IP.To4() == nil {
			network = "tcp6"
		}
		return &net.TCPAddr{IP: append(net.IP(nil), typed.IP...), Port: typed.Port, Zone: typed.Zone}, network, true
	case *net.TCPAddr:
		if typed == nil {
			return nil, "", false
		}
		network := "tcp4"
		if typed.IP.To4() == nil {
			network = "tcp6"
		}
		return &net.TCPAddr{IP: append(net.IP(nil), typed.IP...), Port: typed.Port, Zone: typed.Zone}, network, true
	default:
		return nil, "", false
	}
}

func sessionAddrIP(addr net.Addr) (netip.Addr, bool) {
	switch typed := addr.(type) {
	case *net.UDPAddr:
		if typed == nil {
			return netip.Addr{}, false
		}
		ip, ok := netip.AddrFromSlice(typed.IP)
		return ip.Unmap(), ok
	case *net.TCPAddr:
		if typed == nil {
			return netip.Addr{}, false
		}
		ip, ok := netip.AddrFromSlice(typed.IP)
		return ip.Unmap(), ok
	default:
		return netip.Addr{}, false
	}
}
