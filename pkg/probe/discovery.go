// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/traversal"
)

const (
	defaultDiscoveryTimeout = 750 * time.Millisecond
	defaultPunchInterval    = 25 * time.Millisecond
	defaultPunchPayload     = "derphole-punch"
	tailscaleV4Prefix       = "100.64.0.0/10"
	tailscaleV6Prefix       = "fd7a:115c:a1e0::/48"
)

var (
	fetchDERPMap           = derpbind.FetchMap
	gatherTraversalPackets = traversal.GatherCandidates
	interfaceAddrs         = net.InterfaceAddrs
	tailscaleV4Net         = netip.MustParsePrefix(tailscaleV4Prefix)
	tailscaleV6Net         = netip.MustParsePrefix(tailscaleV6Prefix)
)

type DirectResult struct {
	Direct bool
}

func DiscoverCandidates(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
	if conn == nil {
		return nil, errors.New("nil packet conn")
	}

	seen := candidateSet{}
	seen.add(conn.LocalAddr())
	seen.addInterfaceAddrs(conn.LocalAddr())

	discoveryCtx, cancel := context.WithTimeout(ctx, defaultDiscoveryTimeout)
	defer cancel()
	seen.addTraversalCandidates(discoveryCtx, conn)

	out := seen.addrs()
	return preferredCandidates(out, len(out)), nil
}

type candidateSet map[string]net.Addr

func (s candidateSet) add(addr net.Addr) {
	if addr == nil {
		return
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		s.addUDP(udpAddr)
		return
	}
	s[addr.String()] = addr
}

func (s candidateSet) addUDP(addr *net.UDPAddr) {
	if !candidateUDPAddrValid(addr) {
		return
	}
	cp := *addr
	if addr.IP != nil {
		cp.IP = append(net.IP(nil), addr.IP...)
	}
	s[cp.String()] = &cp
}

func candidateUDPAddrValid(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	return !ok || (!ip.IsUnspecified() && !ip.IsMulticast())
}

func (s candidateSet) addInterfaceAddrs(local net.Addr) {
	localUDP, ok := local.(*net.UDPAddr)
	if !ok {
		return
	}
	addrs, err := interfaceAddrs()
	if err != nil {
		return
	}
	for _, raw := range addrs {
		if addr, ok := interfaceCandidate(raw, localUDP.Port); ok {
			s.add(addr)
		}
	}
}

func interfaceCandidate(raw net.Addr, port int) (*net.UDPAddr, bool) {
	prefix, err := netip.ParsePrefix(raw.String())
	if err != nil {
		return nil, false
	}
	ip := prefix.Addr()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, false
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), ip.AsSlice()...),
		Port: port,
		Zone: ip.Zone(),
	}, true
}

func (s candidateSet) addTraversalCandidates(ctx context.Context, conn net.PacketConn) {
	dm, err := fetchDERPMap(ctx, derpbind.PublicDERPMapURL)
	if err != nil || dm == nil {
		return
	}
	raw, err := gatherTraversalPackets(ctx, conn, dm, nil)
	if err != nil {
		return
	}
	for _, candidate := range raw {
		addr, err := net.ResolveUDPAddr("udp", candidate)
		if err == nil {
			s.add(addr)
		}
	}
}

func (s candidateSet) addrs() []net.Addr {
	out := make([]net.Addr, 0, len(s))
	for _, addr := range s {
		out = append(out, addr)
	}
	return out
}

func ParseCandidateStrings(raw []string) []net.Addr {
	addrs := make([]net.Addr, 0, len(raw))
	for _, candidate := range raw {
		addrPort, err := netip.ParseAddrPort(candidate)
		if err != nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   append(net.IP(nil), addrPort.Addr().AsSlice()...),
			Port: int(addrPort.Port()),
			Zone: addrPort.Addr().Zone(),
		})
	}
	return addrs
}

func CandidateStrings(raw []net.Addr) []string {
	out := make([]string, 0, len(raw))
	for _, addr := range preferredCandidates(raw, len(raw)) {
		if addr == nil {
			continue
		}
		out = append(out, addr.String())
	}
	return out
}

func CandidateStringsInOrder(raw []net.Addr) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool)
	for _, addr := range raw {
		if addr == nil {
			continue
		}
		candidate := addr.String()
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
	}
	return out
}

func preferredCandidates(raw []net.Addr, limit int) []net.Addr {
	candidates := make([]net.Addr, 0, len(raw))
	for _, addr := range raw {
		if addr == nil {
			continue
		}
		candidates = append(candidates, addr)
	}
	sort.Slice(candidates, func(i, j int) bool {
		ri, ai := candidateRank(candidates[i])
		rj, aj := candidateRank(candidates[j])
		if ri != rj {
			return ri < rj
		}
		return ai.String() < aj.String()
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func candidateRank(addr net.Addr) (int, netip.Addr) {
	ip, ok := candidateIP(addr)
	if !ok {
		return 100, netip.Addr{}
	}
	return candidateIPRank(ip), ip
}

func candidateIP(addr net.Addr) (netip.Addr, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func candidateIPRank(ip netip.Addr) int {
	switch {
	case tailscaleV4Net.Contains(ip), tailscaleV6Net.Contains(ip):
		return 70
	case ip.IsLoopback():
		return 60
	case ip.IsLinkLocalUnicast():
		return 50
	case ip.IsPrivate():
		return privateCandidateRank(ip)
	case ip.Is6():
		return 20
	default:
		return 10
	}
}

func privateCandidateRank(ip netip.Addr) int {
	if ip.Is4() {
		return 30
	}
	return 35
}

func PunchAddrs(ctx context.Context, conn net.PacketConn, addrs []net.Addr, payload []byte, interval time.Duration) {
	if conn == nil || len(addrs) == 0 {
		return
	}
	if len(payload) == 0 {
		payload = []byte(defaultPunchPayload)
	}
	if interval <= 0 {
		interval = defaultPunchInterval
	}

	send := func() {
		for _, addr := range addrs {
			if addr == nil {
				continue
			}
			_, _ = conn.WriteTo(payload, addr)
		}
	}

	send()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func ObservePunchAddrs(ctx context.Context, conns []net.PacketConn, wait time.Duration) []net.Addr {
	observedByConn := ObservePunchAddrsByConn(ctx, conns, wait)
	seen := make(map[string]net.Addr)
	for _, observed := range observedByConn {
		for _, addr := range observed {
			if addr == nil {
				continue
			}
			seen[addr.String()] = cloneAddr(addr)
		}
	}

	out := make([]net.Addr, 0, len(seen))
	for _, addr := range seen {
		out = append(out, addr)
	}
	return preferredCandidates(out, len(out))
}

func ObservePunchAddrsByConn(ctx context.Context, conns []net.PacketConn, wait time.Duration) [][]net.Addr {
	if wait <= 0 {
		wait = 500 * time.Millisecond
	}
	observeCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	observer := newPunchObserver(observeCtx, cancel, conns)
	observer.run(conns)
	return observer.observed
}

func mapAddrs(seen map[string]net.Addr) []net.Addr {
	out := make([]net.Addr, 0, len(seen))
	for _, addr := range seen {
		out = append(out, addr)
	}
	return preferredCandidates(out, len(out))
}

type punchObserver struct {
	ctx           context.Context
	cancel        context.CancelFunc
	observed      [][]net.Addr
	expected      int32
	observedConns atomic.Int32
	wg            sync.WaitGroup
}

func newPunchObserver(ctx context.Context, cancel context.CancelFunc, conns []net.PacketConn) *punchObserver {
	return &punchObserver{
		ctx:      ctx,
		cancel:   cancel,
		observed: make([][]net.Addr, len(conns)),
		expected: countPacketConns(conns),
	}
}

func countPacketConns(conns []net.PacketConn) int32 {
	count := int32(0)
	for _, conn := range conns {
		if conn != nil {
			count++
		}
	}
	return count
}

func (o *punchObserver) run(conns []net.PacketConn) {
	if o.expected == 0 {
		return
	}
	for i, conn := range conns {
		o.start(i, conn)
	}
	o.wg.Wait()
}

func (o *punchObserver) start(i int, conn net.PacketConn) {
	if conn == nil {
		return
	}
	o.wg.Add(1)
	go o.observeConn(i, conn)
}

func (o *punchObserver) observeConn(i int, conn net.PacketConn) {
	defer o.wg.Done()
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 1500)
	seen := make(map[string]net.Addr)
	for {
		done, err := o.readPunch(conn, buf, seen)
		if done || err != nil {
			o.observed[i] = mapAddrs(seen)
			return
		}
	}
}

func (o *punchObserver) readPunch(conn net.PacketConn, buf []byte, seen map[string]net.Addr) (bool, error) {
	if err := o.ctx.Err(); err != nil {
		return true, err
	}
	if err := conn.SetReadDeadline(o.nextReadDeadline()); err != nil {
		return true, err
	}
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return o.handleReadError(err)
	}
	if string(buf[:n]) != defaultPunchPayload {
		return false, nil
	}
	o.observeAddr(seen, addr)
	return false, nil
}

func (o *punchObserver) nextReadDeadline() time.Time {
	deadline := time.Now().Add(50 * time.Millisecond)
	if ctxDeadline, ok := o.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func (o *punchObserver) handleReadError(err error) (bool, error) {
	if o.ctx.Err() != nil {
		return true, err
	}
	if isNetTimeout(err) {
		return false, nil
	}
	return true, err
}

func (o *punchObserver) observeAddr(seen map[string]net.Addr, addr net.Addr) {
	firstForConn := len(seen) == 0
	seen[addr.String()] = cloneAddr(addr)
	if firstForConn && o.observedConns.Add(1) >= o.expected {
		o.cancel()
	}
}

func PunchDirect(ctx context.Context, local net.PacketConn, remoteAddr string, remote net.PacketConn, localAddr string) (DirectResult, error) {
	result, err := traversal.ProbeDirect(ctx, local, remoteAddr, remote, localAddr)
	if err != nil {
		return DirectResult{}, err
	}
	return DirectResult{Direct: result.Direct}, nil
}
