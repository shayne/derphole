package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/traversal"
)

const (
	defaultDiscoveryTimeout = 750 * time.Millisecond
	defaultPunchInterval    = 25 * time.Millisecond
	defaultPunchPayload     = "derpcat-punch"
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

func PunchDirect(ctx context.Context, local net.PacketConn, remoteAddr string, remote net.PacketConn, localAddr string) (DirectResult, error) {
	result, err := traversal.ProbeDirect(ctx, local, remoteAddr, remote, localAddr)
	if err != nil {
		return DirectResult{}, err
	}
	return DirectResult{Direct: result.Direct}, nil
}
