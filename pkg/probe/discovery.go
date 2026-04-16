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

	seen := make(map[string]net.Addr)
	add := func(addr net.Addr) {
		if addr == nil {
			return
		}
		switch a := addr.(type) {
		case *net.UDPAddr:
			if ip, ok := netip.AddrFromSlice(a.IP); ok && (ip.IsUnspecified() || ip.IsMulticast()) {
				return
			}
			cp := *a
			if a.IP != nil {
				cp.IP = append(net.IP(nil), a.IP...)
			}
			seen[cp.String()] = &cp
		default:
			seen[addr.String()] = addr
		}
	}

	add(conn.LocalAddr())

	if addrs, err := interfaceAddrs(); err == nil {
		if localUDP, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			port := localUDP.Port
			for _, raw := range addrs {
				prefix, err := netip.ParsePrefix(raw.String())
				if err != nil {
					continue
				}
				ip := prefix.Addr()
				if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
					continue
				}
				add(&net.UDPAddr{
					IP:   append(net.IP(nil), ip.AsSlice()...),
					Port: port,
					Zone: ip.Zone(),
				})
			}
		}
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, defaultDiscoveryTimeout)
	defer cancel()

	if dm, err := fetchDERPMap(discoveryCtx, derpbind.PublicDERPMapURL); err == nil && dm != nil {
		if raw, err := gatherTraversalPackets(discoveryCtx, conn, dm, nil); err == nil {
			for _, candidate := range raw {
				addr, err := net.ResolveUDPAddr("udp", candidate)
				if err != nil {
					continue
				}
				add(addr)
			}
		}
	}

	out := make([]net.Addr, 0, len(seen))
	for _, addr := range seen {
		out = append(out, addr)
	}
	return preferredCandidates(out, len(out)), nil
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
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 100, netip.Addr{}
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return 100, netip.Addr{}
	}
	ip = ip.Unmap()
	switch {
	case tailscaleV4Net.Contains(ip), tailscaleV6Net.Contains(ip):
		return 70, ip
	case ip.IsLoopback():
		return 60, ip
	case ip.IsLinkLocalUnicast():
		return 50, ip
	case ip.IsPrivate():
		if ip.Is4() {
			return 30, ip
		}
		return 35, ip
	case ip.Is6():
		return 20, ip
	default:
		return 10, ip
	}
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

	observed := make([][]net.Addr, len(conns))
	expected := int32(0)
	for _, conn := range conns {
		if conn != nil {
			expected++
		}
	}
	if expected == 0 {
		return observed
	}
	var observedConns atomic.Int32
	var wg sync.WaitGroup
	for i, conn := range conns {
		if conn == nil {
			continue
		}
		wg.Add(1)
		go func(i int, conn net.PacketConn) {
			defer wg.Done()
			defer conn.SetReadDeadline(time.Time{})
			buf := make([]byte, 1500)
			seen := make(map[string]net.Addr)
			for {
				if err := observeCtx.Err(); err != nil {
					observed[i] = mapAddrs(seen)
					return
				}
				deadline := time.Now().Add(50 * time.Millisecond)
				if ctxDeadline, ok := observeCtx.Deadline(); ok && ctxDeadline.Before(deadline) {
					deadline = ctxDeadline
				}
				if err := conn.SetReadDeadline(deadline); err != nil {
					observed[i] = mapAddrs(seen)
					return
				}
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					if observeCtx.Err() != nil {
						observed[i] = mapAddrs(seen)
						return
					}
					if isNetTimeout(err) {
						continue
					}
					observed[i] = mapAddrs(seen)
					return
				}
				if string(buf[:n]) != defaultPunchPayload {
					continue
				}
				firstForConn := len(seen) == 0
				seen[addr.String()] = cloneAddr(addr)
				if firstForConn && observedConns.Add(1) >= expected {
					cancel()
				}
			}
		}(i, conn)
	}
	wg.Wait()
	return observed
}

func mapAddrs(seen map[string]net.Addr) []net.Addr {
	out := make([]net.Addr, 0, len(seen))
	for _, addr := range seen {
		out = append(out, addr)
	}
	return preferredCandidates(out, len(out))
}

func PunchDirect(ctx context.Context, local net.PacketConn, remoteAddr string, remote net.PacketConn, localAddr string) (DirectResult, error) {
	result, err := traversal.ProbeDirect(ctx, local, remoteAddr, remote, localAddr)
	if err != nil {
		return DirectResult{}, err
	}
	return DirectResult{Direct: result.Direct}, nil
}
