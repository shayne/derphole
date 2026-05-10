// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package candidate

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

type stringAddr string

func (a stringAddr) Network() string { return "test" }

func (a stringAddr) String() string { return string(a) }

func TestValidateClaimStringsRejectsMalformedAndUnsafeCandidates(t *testing.T) {
	for _, value := range []string{
		"",
		"udp4:203.0.113.10:12345",
		"127.0.0.1:12345",
		"0.0.0.0:12345",
		"[::ffff:0.0.0.0]:12345",
		"[::ffff:127.0.0.1]:12345",
		"224.0.0.1:12345",
		"203.0.113.10:0",
		"203.0.113.10",
		"203.0.113.10:12345 ",
	} {
		if err := ValidateClaimStrings([]string{value}); err == nil {
			t.Fatalf("ValidateClaimStrings(%q) error = nil, want rejection", value)
		}
	}
}

func TestValidateClaimStringsRejectsDuplicateCanonicalEndpoint(t *testing.T) {
	if err := ValidateClaimStrings([]string{"203.0.113.10:12345", "203.0.113.10:12345"}); err == nil {
		t.Fatal("ValidateClaimStrings(duplicate) error = nil, want rejection")
	}
	if err := ValidateClaimStrings([]string{"203.0.113.10:12345", "[::ffff:203.0.113.10]:12345"}); err == nil {
		t.Fatal("ValidateClaimStrings(mapped duplicate) error = nil, want rejection")
	}
}

func TestValidateClaimStringsHonorsCountBoundary(t *testing.T) {
	values := make([]string, 0, MaxCount+1)
	for i := 0; i < MaxCount; i++ {
		values = append(values, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), 10000).String())
	}
	if err := ValidateClaimStrings(values); err != nil {
		t.Fatalf("ValidateClaimStrings(MaxCount values) error = %v, want nil", err)
	}
	values = append(values, "203.0.113.250:10000")
	if err := ValidateClaimStrings(values); err == nil {
		t.Fatal("ValidateClaimStrings(MaxCount+1 values) error = nil, want rejection")
	}
}

func TestParsePeerAddrsDropsInvalidUnsafeAndDuplicateCandidates(t *testing.T) {
	addrs := ParsePeerAddrs([]string{
		"127.0.0.1:1",
		"203.0.113.10:12345",
		"203.0.113.10:12345",
		"[::ffff:0.0.0.0]:12345",
		"[::ffff:203.0.113.10]:12345",
		"[fd7a:115c:a1e0::1]:41641",
		"bad",
	})
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2 (%v)", len(addrs), addrs)
	}
	if addrs[0].String() != "203.0.113.10:12345" {
		t.Fatalf("addrs[0] = %v, want 203.0.113.10:12345", addrs[0])
	}
	if addrs[1].String() != "[fd7a:115c:a1e0::1]:41641" {
		t.Fatalf("addrs[1] = %v, want fd7a ULA", addrs[1])
	}
}

func TestParsePeerAddrsCapsValidCandidates(t *testing.T) {
	values := make([]string, 0, MaxCount+1)
	for i := 0; i < MaxCount+1; i++ {
		values = append(values, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), 10000).String())
	}
	addrs := ParsePeerAddrs(values)
	if len(addrs) != MaxCount {
		t.Fatalf("len(addrs) = %d, want %d", len(addrs), MaxCount)
	}
}

func TestParseLocalAddrsKeepsLoopbackAndDropsInvalidCandidates(t *testing.T) {
	addrs := ParseLocalAddrs([]string{
		"127.0.0.1:10001",
		"127.0.0.1:10001",
		"0.0.0.0:10001",
		"[::ffff:198.51.100.10]:10002",
		"[ff02::1]:10003",
		"bad",
	})
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2 (%v)", len(addrs), addrs)
	}
	if addrs[0].String() != "127.0.0.1:10001" {
		t.Fatalf("addrs[0] = %v, want loopback local addr", addrs[0])
	}
	if addrs[1].String() != "198.51.100.10:10002" {
		t.Fatalf("addrs[1] = %v, want mapped IPv4 normalized", addrs[1])
	}
}

func TestStringifyLocalAddrsCapsDeduplicatesAndSkipsUnsafe(t *testing.T) {
	input := make([]net.Addr, 0, MaxCount+2)
	input = append(input, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	for i := 0; i < MaxCount+1; i++ {
		input = append(input, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 10000 + i})
	}
	got := StringifyLocalAddrs(input)
	if len(got) != MaxCount {
		t.Fatalf("len(got) = %d, want %d", len(got), MaxCount)
	}
	if got[0] != "203.0.113.10:10000" {
		t.Fatalf("got[0] = %q, want canonical addr", got[0])
	}
}

func TestParseAddrPortRejectsNonCanonicalAndPredicateFailure(t *testing.T) {
	if _, ok := parseAddrPort("[2001:0db8::1]:12345", func(netip.AddrPort) bool { return true }); ok {
		t.Fatal("parseAddrPort(non-canonical IPv6) ok = true, want false")
	}
	if _, ok := parseAddrPort("203.0.113.10:12345", func(netip.AddrPort) bool { return false }); ok {
		t.Fatal("parseAddrPort(predicate false) ok = true, want false")
	}
	if _, ok := parseAddrPort(strings.Repeat("1", MaxLength+1), func(netip.AddrPort) bool { return true }); ok {
		t.Fatal("parseAddrPort(over length limit) ok = true, want false")
	}
}

func TestPeerAndLocalAddrValidationRules(t *testing.T) {
	valid := netip.MustParseAddrPort("203.0.113.10:12345")
	if !validPeerAddrPort(valid, policy{}) {
		t.Fatal("validPeerAddrPort(valid public endpoint) = false, want true")
	}
	if !validLocalAddrPort(valid) {
		t.Fatal("validLocalAddrPort(valid public endpoint) = false, want true")
	}

	for name, ap := range map[string]netip.AddrPort{
		"zero port":   netip.MustParseAddrPort("203.0.113.10:0"),
		"unspecified": netip.MustParseAddrPort("0.0.0.0:12345"),
		"multicast":   netip.MustParseAddrPort("224.0.0.1:12345"),
		"zone":        netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("eth0"), 12345),
	} {
		if validPeerAddrPort(ap, policy{}) {
			t.Fatalf("validPeerAddrPort(%s) = true, want false", name)
		}
		if validLocalAddrPort(ap) {
			t.Fatalf("validLocalAddrPort(%s) = true, want false", name)
		}
	}

	loopback := netip.MustParseAddrPort("127.0.0.1:12345")
	if validPeerAddrPort(loopback, policy{}) {
		t.Fatal("validPeerAddrPort(loopback without option) = true, want false")
	}
	if !validPeerAddrPort(loopback, policy{allowLoopback: true}) {
		t.Fatal("validPeerAddrPort(loopback allowed) = false, want true")
	}
	if !validLocalAddrPort(loopback) {
		t.Fatal("validLocalAddrPort(loopback) = false, want true")
	}
	if validLocalAdvertiseAddrPort(loopback) {
		t.Fatal("validLocalAdvertiseAddrPort(loopback) = true, want false")
	}
}

func TestAddrPortFromNetAddrCoversConcreteAndStringForms(t *testing.T) {
	for name, addr := range map[string]net.Addr{
		"udp":    &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345},
		"tcp":    &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
		"string": stringAddr("203.0.113.20:23456"),
	} {
		if _, ok := addrPortFromNetAddr(addr); !ok {
			t.Fatalf("addrPortFromNetAddr(%s) ok = false, want true", name)
		}
	}

	for name, addr := range map[string]net.Addr{
		"missing port": stringAddr("203.0.113.10"),
		"bad host":     stringAddr("bad:12345"),
		"zone":         stringAddr("[fe80::1%eth0]:12345"),
		"bad port":     stringAddr("203.0.113.10:notaport"),
		"port high":    stringAddr("203.0.113.10:65536"),
	} {
		if _, ok := addrPortFromNetAddr(addr); ok {
			t.Fatalf("addrPortFromNetAddr(%s) ok = true, want false", name)
		}
	}
}

func TestAddrPortFromIPPortBoundaries(t *testing.T) {
	for name, tc := range map[string]struct {
		ip   net.IP
		port int
		zone string
	}{
		"nil IP":      {port: 1},
		"zero port":   {ip: net.ParseIP("203.0.113.10"), port: 0},
		"high port":   {ip: net.ParseIP("203.0.113.10"), port: 65536},
		"short slice": {ip: net.IP{1, 2, 3}, port: 1},
	} {
		if _, ok := addrPortFromIPPort(tc.ip, tc.port, tc.zone); ok {
			t.Fatalf("addrPortFromIPPort(%s) ok = true, want false", name)
		}
	}

	ap, ok := addrPortFromIPPort(net.ParseIP("::ffff:203.0.113.10"), 65535, "")
	if !ok {
		t.Fatal("addrPortFromIPPort(mapped IPv4) ok = false, want true")
	}
	if want := netip.MustParseAddrPort("203.0.113.10:65535"); ap != want {
		t.Fatalf("addrPortFromIPPort(mapped IPv4) = %v, want %v", ap, want)
	}

	ap, ok = addrPortFromIPPort(net.ParseIP("fe80::1"), 12345, "eth0")
	if !ok || ap.Addr().Zone() != "eth0" {
		t.Fatalf("addrPortFromIPPort(zone) = (%v, %v), want zone eth0", ap, ok)
	}
}

func TestNewPolicyIgnoresNilOptions(t *testing.T) {
	p := newPolicy(nil, AllowLoopback())
	if !p.allowLoopback {
		t.Fatal("newPolicy(nil, AllowLoopback()).allowLoopback = false, want true")
	}
}

func FuzzValidateClaimStrings(f *testing.F) {
	for _, value := range []string{
		"203.0.113.10:12345",
		"127.0.0.1:12345",
		"[2001:db8::1]:443",
		"[::ffff:203.0.113.10]:12345",
		"",
		"bad",
	} {
		f.Add(value)
	}

	f.Fuzz(func(t *testing.T, value string) {
		err := ValidateClaimStrings([]string{value}, AllowLoopback())
		addrs := ParsePeerAddrs([]string{value}, AllowLoopback())
		if err == nil {
			if len(addrs) != 1 {
				t.Fatalf("accepted %q but parsed %d addresses", value, len(addrs))
			}
			if got := addrs[0].String(); ValidateClaimStrings([]string{got}, AllowLoopback()) != nil {
				t.Fatalf("accepted %q but parsed invalid canonical %q", value, got)
			}
		}
	})
}

func FuzzStringifyLocalAddrs(f *testing.F) {
	for _, seed := range []struct {
		host string
		port int
	}{
		{"203.0.113.10", 12345},
		{"127.0.0.1", 12345},
		{"0.0.0.0", 12345},
		{"2001:db8::1", 443},
		{"bad", 1},
	} {
		f.Add(seed.host, seed.port)
	}

	f.Fuzz(func(t *testing.T, host string, port int) {
		addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
		values := StringifyLocalAddrs([]net.Addr{addr})
		if len(values) > 1 {
			t.Fatalf("StringifyLocalAddrs returned %d values for one address", len(values))
		}
		if len(values) == 1 {
			if err := ValidateClaimStrings(values); err != nil {
				t.Fatalf("StringifyLocalAddrs emitted invalid claim %q: %v", values[0], err)
			}
		}
	})
}
