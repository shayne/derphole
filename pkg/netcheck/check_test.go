package netcheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRunReportsDirectFriendlyMapping(t *testing.T) {
	oldProbe := probeSTUNServer
	oldInterfaces := interfaceAddrs
	defer func() {
		probeSTUNServer = oldProbe
		interfaceAddrs = oldInterfaces
	}()
	probeSTUNServer = func(ctx context.Context, server string, localPort int) STUNServerResult {
		return STUNServerResult{
			Server:         server,
			LocalEndpoint:  fmt.Sprintf("0.0.0.0:%d", localPort),
			MappedEndpoint: fmt.Sprintf("203.0.113.10:%d", localPort),
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{mustCIDR(t, "192.168.1.20/24")}, nil
	}

	report, err := Run(context.Background(), Config{
		STUNServers:       []string{"stun-a:3478", "stun-b:3478"},
		FreshSocketChecks: 2,
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Verdict != VerdictDirectFriendly {
		t.Fatalf("Verdict = %q, want %q", report.Verdict, VerdictDirectFriendly)
	}
	if !report.UDP.MappingStable || !report.UDP.PortPreserving {
		t.Fatalf("UDP = %#v, want stable port-preserving mapping", report.UDP)
	}
	if len(report.UDP.PublicEndpoints) == 0 || report.UDP.PublicEndpoints[0] == "" {
		t.Fatalf("PublicEndpoints = %v, want at least one public endpoint", report.UDP.PublicEndpoints)
	}
	if len(report.Candidates.LAN) != 1 || report.Candidates.LAN[0] != "192.168.1.20" {
		t.Fatalf("LAN candidates = %v, want interface address", report.Candidates.LAN)
	}
	if report.Recommendation == "" {
		t.Fatal("Recommendation is empty")
	}
}

func TestRunReportsDirectLimitedWhenMappingChanges(t *testing.T) {
	oldProbe := probeSTUNServer
	oldInterfaces := interfaceAddrs
	defer func() {
		probeSTUNServer = oldProbe
		interfaceAddrs = oldInterfaces
	}()
	count := 0
	probeSTUNServer = func(ctx context.Context, server string, localPort int) STUNServerResult {
		count++
		return STUNServerResult{
			Server:         server,
			LocalEndpoint:  fmt.Sprintf("0.0.0.0:%d", localPort),
			MappedEndpoint: fmt.Sprintf("198.51.100.20:%d", 50000+count),
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, nil
	}

	report, err := Run(context.Background(), Config{
		STUNServers:       []string{"stun-a:3478", "stun-b:3478"},
		FreshSocketChecks: 1,
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Verdict != VerdictDirectLimited {
		t.Fatalf("Verdict = %q, want %q", report.Verdict, VerdictDirectLimited)
	}
	if report.UDP.MappingStable {
		t.Fatalf("MappingStable = true, want false")
	}
	if report.UDP.PortPreserving {
		t.Fatalf("PortPreserving = true, want false")
	}
}

func TestRunReportsRelayOnlyLikelyWhenSTUNFails(t *testing.T) {
	oldProbe := probeSTUNServer
	oldInterfaces := interfaceAddrs
	defer func() {
		probeSTUNServer = oldProbe
		interfaceAddrs = oldInterfaces
	}()
	probeSTUNServer = func(ctx context.Context, server string, localPort int) STUNServerResult {
		return STUNServerResult{
			Server:        server,
			LocalEndpoint: fmt.Sprintf("0.0.0.0:%d", localPort),
			Error:         "timeout",
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, nil
	}

	report, err := Run(context.Background(), Config{
		STUNServers:       []string{"stun-a:3478"},
		FreshSocketChecks: 0,
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Verdict != VerdictRelayOnlyLikely {
		t.Fatalf("Verdict = %q, want %q", report.Verdict, VerdictRelayOnlyLikely)
	}
	if report.UDP.Outbound || report.UDP.STUN {
		t.Fatalf("UDP = %#v, want blocked", report.UDP)
	}
}

func mustCIDR(t *testing.T, raw string) net.Addr {
	t.Helper()
	prefix := netip.MustParsePrefix(raw)
	return &net.IPNet{
		IP:   append(net.IP(nil), prefix.Addr().AsSlice()...),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}
