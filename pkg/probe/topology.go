package probe

import (
	"net/netip"
	"slices"
	"strings"
)

const (
	TopologyClassSSHFrontDoorMismatch = "ssh-front-door-mismatch"
	TopologyClassRemoteUDPUnreachable = "remote-udp-unreachable"
	TopologyClassDirectUDPPossible    = "direct-udp-possible"
)

type TopologyReport struct {
	Host            string                  `json:"host,omitempty"`
	Target          string                  `json:"target,omitempty"`
	DNSAddresses    []string                `json:"dns_addresses,omitempty"`
	Local           TopologyHost            `json:"local,omitempty"`
	Remote          TopologyHost            `json:"remote,omitempty"`
	UDPReachability []UDPReachabilityResult `json:"udp_reachability,omitempty"`
	PunchTests      []UDPPunchResult        `json:"punch_tests,omitempty"`
	Classifications []string                `json:"classifications,omitempty"`
	Errors          []string                `json:"errors,omitempty"`
}

type TopologyHost struct {
	Hostname   string              `json:"hostname,omitempty"`
	EgressIP   string              `json:"egress_ip,omitempty"`
	Interfaces []TopologyInterface `json:"interfaces,omitempty"`
	Firewall   []string            `json:"firewall,omitempty"`
	UDPListen  []string            `json:"udp_listen,omitempty"`
	Error      string              `json:"error,omitempty"`
}

type TopologyInterface struct {
	Name  string   `json:"name,omitempty"`
	Addrs []string `json:"addrs,omitempty"`
}

type UDPReachabilityResult struct {
	Target    string `json:"target,omitempty"`
	Address   string `json:"address,omitempty"`
	Received  bool   `json:"received"`
	Reply     bool   `json:"reply"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	RemoteLog string `json:"remote_log,omitempty"`
}

type UDPPunchResult struct {
	Name             string   `json:"name,omitempty"`
	LocalAddress     string   `json:"local_address,omitempty"`
	RemoteAddress    string   `json:"remote_address,omitempty"`
	RemoteCandidates []string `json:"remote_candidates,omitempty"`
	LocalReceived    bool     `json:"local_received"`
	RemoteReceived   bool     `json:"remote_received"`
	Error            string   `json:"error,omitempty"`
}

func ClassifyTopology(report TopologyReport) []string {
	var classes []string
	add := func(class string) {
		if class == "" || slices.Contains(classes, class) {
			return
		}
		classes = append(classes, class)
	}

	if hasSSHFrontDoorMismatch(report) {
		add(TopologyClassSSHFrontDoorMismatch)
	}
	if len(report.UDPReachability) > 0 {
		anyReceived := false
		for _, result := range report.UDPReachability {
			if result.Received || result.Reply {
				anyReceived = true
				break
			}
		}
		if anyReceived {
			add(TopologyClassDirectUDPPossible)
		} else {
			add(TopologyClassRemoteUDPUnreachable)
		}
	}
	for _, result := range report.PunchTests {
		if result.LocalReceived || result.RemoteReceived {
			add(TopologyClassDirectUDPPossible)
			break
		}
	}
	return classes
}

func hasSSHFrontDoorMismatch(report TopologyReport) bool {
	egress := strings.TrimSpace(report.Remote.EgressIP)
	if egress == "" || len(report.DNSAddresses) == 0 {
		return false
	}
	if slices.Contains(report.DNSAddresses, egress) {
		return false
	}
	return topologyHostHasPrivateAddress(report.Remote)
}

func topologyHostHasPrivateAddress(host TopologyHost) bool {
	for _, iface := range host.Interfaces {
		for _, raw := range iface.Addrs {
			if topologyAddrIsPrivate(raw) {
				return true
			}
		}
	}
	return false
}

func topologyAddrIsPrivate(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		addr := prefix.Addr().Unmap()
		return addr.IsPrivate() || addr.IsLoopback()
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		addr = addr.Unmap()
		return addr.IsPrivate() || addr.IsLoopback()
	}
	return false
}
