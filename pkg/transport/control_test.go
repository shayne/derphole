// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"fmt"
	"net"
	"testing"
)

func TestParseCandidateAddrsCapsOversizedInput(t *testing.T) {
	raw := make([]string, maxControlCandidates+5)
	for i := range raw {
		raw[i] = fmt.Sprintf("100.64.0.%d:%d", i+1, 1234+i)
	}

	addrs := parseCandidateAddrs(raw)
	if got, want := len(addrs), maxControlCandidates; got != want {
		t.Fatalf("len(addrs) = %d, want %d", got, want)
	}
}

func TestParseCandidateAddrsDropsUnsafeAndDeduplicates(t *testing.T) {
	addrs := parseCandidateAddrs([]string{
		"127.0.0.1:1",
		"100.64.0.10:1234",
		"100.64.0.10:1234",
		"bad",
	})
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1 (%v)", len(addrs), addrs)
	}
	if addrs[0].String() != "100.64.0.10:1234" {
		t.Fatalf("addr = %v, want 100.64.0.10:1234", addrs[0])
	}
}

func TestStringifyCandidatesCapsAndSkipsOversized(t *testing.T) {
	addrs := make([]net.Addr, 0, maxControlCandidates+2)
	for i := 0; i < maxControlCandidates+1; i++ {
		addrs = append(addrs, &net.TCPAddr{IP: net.IPv4(100, 64, 0, 9), Port: 1000 + i})
	}
	addrs = append(addrs, oversizedAddr("x"))

	raw := stringifyCandidates(addrs)
	if got, want := len(raw), maxControlCandidates; got != want {
		t.Fatalf("len(raw) = %d, want %d", got, want)
	}
	for _, candidate := range raw {
		if len(candidate) > maxControlCandidateLength {
			t.Fatalf("candidate %q exceeds max length %d", candidate, maxControlCandidateLength)
		}
	}
}

type oversizedAddr string

func (a oversizedAddr) Network() string { return "udp" }

func (a oversizedAddr) String() string {
	buf := make([]byte, maxControlCandidateLength+1)
	for i := range buf {
		buf[i] = 'a'
	}
	return string(buf)
}
