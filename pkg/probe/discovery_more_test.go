// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"net"
	"net/netip"
	"testing"
)

func TestNormalizeTransportForCLI(t *testing.T) {
	for _, raw := range []string{"", "legacy", " LEGACY "} {
		got, err := NormalizeTransportForCLI(raw)
		if err != nil {
			t.Fatalf("NormalizeTransportForCLI(%q) error = %v", raw, err)
		}
		if got != probeTransportLegacy {
			t.Fatalf("NormalizeTransportForCLI(%q) = %q, want legacy", raw, got)
		}
	}
	if got, err := NormalizeTransportForCLI("batched"); err != nil || got != probeTransportBatched {
		t.Fatalf("NormalizeTransportForCLI(batched) = %q, %v; want batched nil", got, err)
	}
	if _, err := NormalizeTransportForCLI("unknown"); err == nil {
		t.Fatal("NormalizeTransportForCLI(unknown) error = nil, want failure")
	}
}

func TestInterfaceCandidateFiltersInvalidAddresses(t *testing.T) {
	got, ok := interfaceCandidate(&net.IPNet{IP: net.ParseIP("192.168.10.8"), Mask: net.CIDRMask(24, 32)}, 4242)
	if !ok || got.String() != "192.168.10.8:4242" {
		t.Fatalf("interfaceCandidate(private) = %v, %v; want 192.168.10.8:4242 true", got, ok)
	}
	for _, raw := range []net.Addr{
		&net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		&net.IPNet{IP: net.ParseIP("224.0.0.1"), Mask: net.CIDRMask(4, 32)},
		stringAddr("not-a-prefix"),
	} {
		if got, ok := interfaceCandidate(raw, 4242); ok || got != nil {
			t.Fatalf("interfaceCandidate(%v) = %v, %v; want nil false", raw, got, ok)
		}
	}
}

func TestCandidateIPRankOrdersAddressFamilies(t *testing.T) {
	tests := []struct {
		ip   string
		want int
	}{
		{"8.8.8.8", 10},
		{"2001:4860:4860::8888", 20},
		{"192.168.1.5", 30},
		{"fd00::1", 35},
		{"169.254.1.1", 50},
		{"127.0.0.1", 60},
		{"100.64.0.1", 70},
		{"fd7a:115c:a1e0::1", 70},
	}
	for _, tt := range tests {
		if got := candidateIPRank(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Fatalf("candidateIPRank(%s) = %d, want %d", tt.ip, got, tt.want)
		}
	}
}

type stringAddr string

func (a stringAddr) Network() string { return "test" }
func (a stringAddr) String() string  { return string(a) }
