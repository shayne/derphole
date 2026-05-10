// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package candidate

import (
	"net"
	"testing"
)

func TestValidateClaimStringsRejectsMalformedAndUnsafeCandidates(t *testing.T) {
	for _, value := range []string{
		"",
		"udp4:203.0.113.10:12345",
		"127.0.0.1:12345",
		"0.0.0.0:12345",
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
}

func TestParsePeerAddrsDropsInvalidUnsafeAndDuplicateCandidates(t *testing.T) {
	addrs := ParsePeerAddrs([]string{
		"127.0.0.1:1",
		"203.0.113.10:12345",
		"203.0.113.10:12345",
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
