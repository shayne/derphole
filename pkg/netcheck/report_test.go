package netcheck

import (
	"slices"
	"testing"
)

func TestClassifyReportDirectFriendly(t *testing.T) {
	report := Report{
		UDP: UDPReport{
			Outbound:        true,
			STUN:            true,
			PublicEndpoints: []string{"203.0.113.10:57179"},
			MappingStable:   true,
			PortPreserving:  true,
		},
	}
	got := Classify(report)
	if got != VerdictDirectFriendly {
		t.Fatalf("Classify() = %q, want %q", got, VerdictDirectFriendly)
	}
}

func TestClassifyReportDirectLimited(t *testing.T) {
	report := Report{
		UDP: UDPReport{
			Outbound:        true,
			STUN:            true,
			PublicEndpoints: []string{"198.51.100.20:51433"},
			MappingStable:   false,
			PortPreserving:  false,
		},
	}
	got := Classify(report)
	if got != VerdictDirectLimited {
		t.Fatalf("Classify() = %q, want %q", got, VerdictDirectLimited)
	}
}

func TestClassifyReportRelayOnlyLikely(t *testing.T) {
	report := Report{UDP: UDPReport{Outbound: false, STUN: false}}
	got := Classify(report)
	if got != VerdictRelayOnlyLikely {
		t.Fatalf("Classify() = %q, want %q", got, VerdictRelayOnlyLikely)
	}
}

func TestClassifyReportUnknownWhenIncomplete(t *testing.T) {
	report := Report{UDP: UDPReport{Outbound: true, STUN: false}}
	got := Classify(report)
	if got != VerdictUnknown {
		t.Fatalf("Classify() = %q, want %q", got, VerdictUnknown)
	}
}

func TestCategorizeCandidateAddresses(t *testing.T) {
	got := CategorizeCandidateAddresses([]string{
		"192.168.1.20/24",
		"100.64.10.20/32",
		"fd7a:115c:a1e0::1/48",
		"203.0.113.10",
		"203.0.113.10:57179",
		"127.0.0.1",
		"fe80::1/64",
	})
	if !slices.Contains(got.LAN, "192.168.1.20") {
		t.Fatalf("LAN = %v, want private address", got.LAN)
	}
	if !slices.Contains(got.Overlay, "100.64.10.20") {
		t.Fatalf("Overlay = %v, want Tailscale IPv4 address", got.Overlay)
	}
	if !slices.Contains(got.Overlay, "fd7a:115c:a1e0::1") {
		t.Fatalf("Overlay = %v, want Tailscale IPv6 address", got.Overlay)
	}
	if !slices.Contains(got.Public, "203.0.113.10") {
		t.Fatalf("Public = %v, want public address", got.Public)
	}
	if !slices.Contains(got.Public, "203.0.113.10:57179") {
		t.Fatalf("Public = %v, want public endpoint with port", got.Public)
	}
	if slices.Contains(got.LAN, "127.0.0.1") || slices.Contains(got.Public, "127.0.0.1") {
		t.Fatalf("loopback address should be skipped: %#v", got)
	}
	if slices.Contains(got.Public, "fe80::1") {
		t.Fatalf("link-local address should be skipped: %#v", got)
	}
}

func TestRecommendationMatchesVerdict(t *testing.T) {
	tests := []struct {
		verdict string
		want    string
	}{
		{VerdictDirectFriendly, "This side looks capable of direct UDP. Use topology to test a specific peer."},
		{VerdictDirectLimited, "Direct UDP may fail with ordinary hole punching. Use a forwarded UDP port, routable overlay address, or relay fallback."},
		{VerdictRelayOnlyLikely, "Direct UDP is unlikely from this network. Use relay fallback."},
		{VerdictUnknown, "Network capabilities are incomplete or contradictory. Use topology to test a specific peer."},
	}
	for _, tc := range tests {
		t.Run(tc.verdict, func(t *testing.T) {
			if got := Recommendation(tc.verdict); got != tc.want {
				t.Fatalf("Recommendation(%q) = %q, want %q", tc.verdict, got, tc.want)
			}
		})
	}
}
