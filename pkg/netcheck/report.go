package netcheck

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
)

const (
	VerdictDirectFriendly  = "direct-friendly"
	VerdictDirectLimited   = "direct-limited"
	VerdictRelayOnlyLikely = "relay-only-likely"
	VerdictUnknown         = "unknown"
)

var (
	tailscaleIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

type Report struct {
	Verdict        string          `json:"verdict"`
	UDP            UDPReport       `json:"udp"`
	Candidates     CandidateReport `json:"candidates"`
	STUN           STUNReport      `json:"stun"`
	Recommendation string          `json:"recommendation"`
}

type UDPReport struct {
	Outbound        bool     `json:"outbound"`
	STUN            bool     `json:"stun"`
	PublicEndpoints []string `json:"public_endpoints,omitempty"`
	MappingStable   bool     `json:"mapping_stable"`
	PortPreserving  bool     `json:"port_preserving"`
}

type CandidateReport struct {
	LAN     []string `json:"lan,omitempty"`
	Overlay []string `json:"overlay,omitempty"`
	Public  []string `json:"public,omitempty"`
}

type STUNReport struct {
	Servers []STUNServerResult `json:"servers,omitempty"`
}

type STUNServerResult struct {
	Server         string `json:"server"`
	LocalEndpoint  string `json:"local_endpoint,omitempty"`
	MappedEndpoint string `json:"mapped_endpoint,omitempty"`
	Error          string `json:"error,omitempty"`
}

func Classify(report Report) string {
	if !report.UDP.Outbound && !report.UDP.STUN {
		return VerdictRelayOnlyLikely
	}
	if report.UDP.Outbound && report.UDP.STUN && len(report.UDP.PublicEndpoints) > 0 {
		if report.UDP.MappingStable && report.UDP.PortPreserving {
			return VerdictDirectFriendly
		}
		return VerdictDirectLimited
	}
	return VerdictUnknown
}

func Recommendation(verdict string) string {
	switch verdict {
	case VerdictDirectFriendly:
		return "This side looks capable of direct UDP. The peer still needs compatible NAT/firewall behavior."
	case VerdictDirectLimited:
		return "Direct UDP may fail with ordinary hole punching. Use a forwarded UDP port, routable overlay address, or relay fallback."
	case VerdictRelayOnlyLikely:
		return "Direct UDP is unlikely from this network. Use relay fallback."
	default:
		return "Network capabilities are incomplete or contradictory. Re-run netcheck or compare results from both sides."
	}
}

func CategorizeCandidateAddresses(raw []string) CandidateReport {
	var report CandidateReport
	for _, candidate := range raw {
		addr, value, ok := parseCandidateAddr(candidate)
		if !ok || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			continue
		}
		addr = addr.Unmap()
		switch {
		case tailscaleIPv4Prefix.Contains(addr) || tailscaleIPv6Prefix.Contains(addr):
			report.Overlay = appendUnique(report.Overlay, value)
		case addr.IsPrivate():
			report.LAN = appendUnique(report.LAN, value)
		default:
			report.Public = appendUnique(report.Public, value)
		}
	}
	sort.Strings(report.LAN)
	sort.Strings(report.Overlay)
	sort.Strings(report.Public)
	return report
}

func parseCandidateAddr(raw string) (netip.Addr, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, "", false
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		addr := prefix.Addr().Unmap()
		return addr, addr.String(), true
	}
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return addrPort.Addr().Unmap(), addrPort.String(), true
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		addr = addr.Unmap()
		return addr, addr.String(), true
	}
	return netip.Addr{}, "", false
}

func appendUnique(values []string, value string) []string {
	if value == "" || slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}
