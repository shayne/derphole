package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const externalNativeTCPDialFallbackDelay = 150 * time.Millisecond
const externalNativeTCPCopyBufferSizeDefault = 1 << 20
const defaultExternalNativeTCPConns = 2
const externalNativeTCPBearerAuthSize = 32 + sha256.Size
const externalNativeTCPBootstrapHelloSize = 1

var externalNativeTCPBearerAuthDomain = []byte("derphole-native-tcp-v1")

var externalNativeTCPAddrAllowed = externalNativeTCPAddrAllowedDefault
var externalNativeTCPListen = listenExternalNativeTCP

const externalNativeTCPBindAddrEnv = "DERPHOLE_NATIVE_TCP_BIND_ADDR"
const externalNativeTCPAdvertiseAddrEnv = "DERPHOLE_NATIVE_TCP_ADVERTISE_ADDR"
const externalNativeTCPChunkSizeEnv = "DERPHOLE_NATIVE_TCP_CHUNK_SIZE"

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
	if ip.IsLoopback() || ip.IsPrivate() || publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip) {
		return true
	}
	return ip.IsGlobalUnicast()
}

func externalNativeTCPConnCount() int {
	if raw := os.Getenv("DERPHOLE_NATIVE_TCP_CONNS"); raw != "" {
		count, err := strconv.Atoi(raw)
		if err == nil && count > 0 {
			return count
		}
	}
	return defaultExternalNativeTCPConns
}

func externalNativeTCPCopyChunkSize() int {
	if raw := os.Getenv(externalNativeTCPChunkSizeEnv); raw != "" {
		size, err := strconv.Atoi(raw)
		if err == nil && size > 0 {
			return size
		}
	}
	return externalNativeTCPCopyBufferSizeDefault
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

func externalNativeTCPPassiveConnCount(peerCount int) int {
	localCap := externalNativeTCPConnCap()
	if peerCount < 1 {
		return externalNativeTCPConnCount()
	}
	if peerCount > localCap {
		return localCap
	}
	return peerCount
}

func externalNativeTCPConnCap() int {
	localCap := MaxParallelStripes
	if raw := os.Getenv("DERPHOLE_NATIVE_TCP_CONNS"); raw != "" {
		count, err := strconv.Atoi(raw)
		if err == nil && count > 0 && count < localCap {
			localCap = count
		}
	}
	return localCap
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
	if ln, ok := listenExternalNativeTCPOnAddrs(externalNativeTCPBindOverrideAddrs(), tlsConfig); ok {
		return ln, true
	}
	return listenExternalNativeTCPOnAddrs(addrs, tlsConfig)
}

func listenExternalNativeTCPOnAddrs(addrs []net.Addr, tlsConfig *tls.Config) (net.Listener, bool) {
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
			if fallbackAddr := externalNativeTCPEphemeralPortAddr(addr); fallbackAddr != nil {
				ln, err = externalNativeTCPListen(fallbackAddr, addrTLSConfig)
			}
		}
		if err != nil {
			continue
		}
		return ln, true
	}
	return nil, false
}

func externalNativeTCPBindOverrideAddrs() []net.Addr {
	return externalNativeTCPEnvAddrs(externalNativeTCPBindAddrEnv)
}

func selectExternalNativeTCPOfferAddr(localCandidates []net.Addr) net.Addr {
	if overrides := externalNativeTCPBindOverrideAddrs(); len(overrides) > 0 {
		for _, addr := range externalNativeTCPListenCandidates(overrides) {
			if externalNativeTCPAddrAllowed(addr) {
				return cloneSessionAddr(addr)
			}
		}
	}
	for _, addr := range externalNativeTCPListenCandidates(localCandidates) {
		if externalNativeTCPAddrAllowed(addr) {
			return cloneSessionAddr(addr)
		}
	}
	return nil
}

func externalNativeTCPAdvertiseAddr(addr, peerAddr net.Addr) net.Addr {
	overrides := externalNativeTCPEnvAddrs(externalNativeTCPAdvertiseAddrEnv)
	if len(overrides) == 0 {
		return cloneSessionAddr(addr)
	}
	if peerAddr != nil {
		if selected := selectExternalNativeTCPRouteAddr(peerAddr, overrides); selected != nil {
			return selected
		}
	}
	return cloneSessionAddr(overrides[0])
}

func externalNativeTCPEnvAddrs(key string) []net.Addr {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		filtered = append(filtered, part)
	}
	return parseCandidateStrings(filtered)
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
	if ip.IsPrivate() {
		return 1
	}
	if ip.IsLoopback() {
		return 2
	}
	return 3
}

func externalNativeTCPEphemeralPortAddr(addr net.Addr) net.Addr {
	tcpAddr, _, ok := externalNativeTCPAddr(addr)
	if !ok || tcpAddr.Port == 0 {
		return nil
	}
	out := *tcpAddr
	out.Port = 0
	return &out
}

func selectExternalNativeTCPResponseAddr(requestAddr, peerAddr net.Addr, localCandidates []net.Addr) net.Addr {
	if externalNativeTCPRequestAddrAllowed(requestAddr, peerAddr, localCandidates) {
		if addr := selectExternalNativeTCPRouteAddr(requestAddr, localCandidates); addr != nil {
			return addr
		}
	}
	return selectExternalNativeTCPRouteAddr(peerAddr, localCandidates)
}

func externalNativeTCPRequestAddrAllowed(requestAddr, peerAddr net.Addr, localCandidates []net.Addr) bool {
	requestIP, ok := sessionAddrIP(requestAddr)
	if !ok {
		return false
	}
	if !requestIP.IsLoopback() {
		return true
	}
	peerIP, ok := sessionAddrIP(peerAddr)
	if ok && peerIP.IsLoopback() {
		return true
	}
	for _, candidate := range localCandidates {
		ip, ok := sessionAddrIP(candidate)
		if ok && !ip.IsLoopback() {
			return false
		}
	}
	return len(localCandidates) > 0
}

func selectExternalNativeTCPRouteAddr(peerAddr net.Addr, localCandidates []net.Addr) net.Addr {
	bestIdx := -1
	bestPrefixBits := -1
	bestRank := 0
	for idx, candidate := range localCandidates {
		if !externalNativeTCPAddrAllowed(candidate) || !externalNativeTCPRouteCanUseLocalAddrCandidate(candidate, peerAddr) {
			continue
		}
		rank := externalNativeTCPAddrRank(candidate)
		prefixBits := externalNativeTCPSharedPrefixBits(peerAddr, candidate)
		if bestIdx >= 0 && rank > bestRank {
			continue
		}
		if bestIdx >= 0 && rank == bestRank && prefixBits <= bestPrefixBits {
			continue
		}
		bestIdx = idx
		bestRank = rank
		bestPrefixBits = prefixBits
	}
	if bestIdx >= 0 {
		return cloneSessionAddr(localCandidates[bestIdx])
	}
	return nil
}

func externalNativeTCPRouteCanUseLocalAddrCandidate(localAddr, peerAddr net.Addr) bool {
	if externalNativeQUICStripeCanUseLocalAddrCandidate(localAddr, peerAddr) {
		return true
	}
	return externalNativeTCPAddrIsPublic(localAddr) && externalNativeTCPAddrIsPublic(peerAddr)
}

func externalNativeTCPSharedPrefixBits(peerAddr, candidate net.Addr) int {
	peerIP, ok := sessionAddrIP(peerAddr)
	if !ok {
		return 0
	}
	candidateIP, ok := sessionAddrIP(candidate)
	if !ok || peerIP.Is4() != candidateIP.Is4() || peerIP.Is6() != candidateIP.Is6() {
		return 0
	}
	if peerIP.Is4() {
		peerBytes := peerIP.As4()
		candidateBytes := candidateIP.As4()
		for i := range peerBytes {
			xor := peerBytes[i] ^ candidateBytes[i]
			if xor != 0 {
				return i*8 + bits.LeadingZeros8(uint8(xor))
			}
		}
		return 32
	}
	peerBytes := peerIP.As16()
	candidateBytes := candidateIP.As16()
	for i := range peerBytes {
		xor := peerBytes[i] ^ candidateBytes[i]
		if xor != 0 {
			return i*8 + bits.LeadingZeros8(uint8(xor))
		}
	}
	return 128
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

func externalNativeTCPAddrIsPublic(addr net.Addr) bool {
	ip, ok := sessionAddrIP(addr)
	if !ok {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip) {
		return false
	}
	return ip.IsGlobalUnicast()
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

func dialExternalNativeTCPBootstrapConns(ctx context.Context, addr net.Addr, tlsConfig *tls.Config, auth externalNativeTCPAuth, connCount int) ([]net.Conn, error) {
	if connCount < 1 {
		return nil, errors.New("native tcp bootstrap connection count must be positive")
	}
	firstConn, err := dialExternalNativeTCP(ctx, addr, tlsConfig, auth)
	if err != nil {
		return nil, err
	}
	acceptedCount, err := negotiateExternalNativeTCPBootstrapConnCount(ctx, firstConn, connCount)
	if err != nil {
		_ = firstConn.Close()
		return nil, err
	}
	conns := []net.Conn{firstConn}
	if acceptedCount == 1 {
		return conns, nil
	}
	extraConns, err := dialExternalNativeTCPConns(ctx, addr, tlsConfig, auth, acceptedCount-1)
	if err != nil {
		closeExternalNativeTCPConns(conns)
		return nil, err
	}
	return append(conns, extraConns...), nil
}

func acceptExternalNativeTCPBootstrapConns(ctx context.Context, ln net.Listener, auth externalNativeTCPAuth, localCap int) ([]net.Conn, error) {
	defer ln.Close()
	firstConn, err := acceptExternalNativeTCP(ctx, ln, auth)
	if err != nil {
		return nil, err
	}
	acceptedCount, err := acceptExternalNativeTCPBootstrapConnCount(ctx, firstConn, localCap)
	if err != nil {
		_ = firstConn.Close()
		return nil, err
	}
	conns := []net.Conn{firstConn}
	if acceptedCount == 1 {
		return conns, nil
	}
	extraConns, err := acceptExternalNativeTCPConns(ctx, ln, auth, acceptedCount-1)
	if err != nil {
		closeExternalNativeTCPConns(conns)
		return nil, err
	}
	return append(conns, extraConns...), nil
}

func negotiateExternalNativeTCPBootstrapConnCount(ctx context.Context, conn net.Conn, requestedCount int) (int, error) {
	if err := writeExternalNativeTCPBootstrapHello(conn, requestedCount); err != nil {
		return 0, err
	}
	acceptedCount, err := readExternalNativeTCPBootstrapHello(conn)
	if err != nil {
		return 0, err
	}
	if acceptedCount < 1 {
		return 0, errors.New("native tcp bootstrap peer rejected all connections")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return acceptedCount, nil
	}
}

func acceptExternalNativeTCPBootstrapConnCount(ctx context.Context, conn net.Conn, localCap int) (int, error) {
	requestedCount, err := readExternalNativeTCPBootstrapHello(conn)
	if err != nil {
		return 0, err
	}
	acceptedCount := requestedCount
	if localCap > 0 && acceptedCount > localCap {
		acceptedCount = localCap
	}
	if acceptedCount < 1 {
		return 0, errors.New("native tcp bootstrap connection count must be positive")
	}
	if err := writeExternalNativeTCPBootstrapHello(conn, acceptedCount); err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return acceptedCount, nil
	}
}

func writeExternalNativeTCPBootstrapHello(conn net.Conn, connCount int) error {
	if connCount < 1 || connCount > MaxParallelStripes {
		return errors.New("native tcp bootstrap connection count out of range")
	}
	var msg [externalNativeTCPBootstrapHelloSize]byte
	msg[0] = byte(connCount)
	_, err := conn.Write(msg[:])
	return err
}

func readExternalNativeTCPBootstrapHello(conn net.Conn) (int, error) {
	var msg [externalNativeTCPBootstrapHelloSize]byte
	if _, err := io.ReadFull(conn, msg[:]); err != nil {
		return 0, err
	}
	connCount := int(msg[0])
	if connCount < 1 || connCount > MaxParallelStripes {
		return 0, errors.New("native tcp bootstrap connection count out of range")
	}
	return connCount, nil
}

func dialExternalNativeTCPConns(ctx context.Context, addr net.Addr, tlsConfig *tls.Config, auth externalNativeTCPAuth, connCount int) ([]net.Conn, error) {
	if connCount < 1 {
		return nil, errors.New("native tcp connection count must be positive")
	}
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type dialResult struct {
		idx  int
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, connCount)
	for idx := range connCount {
		go func(idx int) {
			conn, err := dialExternalNativeTCP(connCtx, addr, tlsConfig, auth)
			resultCh <- dialResult{idx: idx, conn: conn, err: err}
		}(idx)
	}
	conns := make([]net.Conn, connCount)
	var firstErr error
	for i := 0; i < connCount; i++ {
		result := <-resultCh
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		if firstErr != nil {
			_ = result.conn.Close()
			continue
		}
		conns[result.idx] = result.conn
	}
	if firstErr != nil {
		closeExternalNativeTCPConns(conns)
		return nil, firstErr
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
	chunkSize := externalNativeTCPCopyChunkSize()
	go func() {
		_, err := io.CopyBuffer(dst, src, make([]byte, chunkSize))
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
