// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"testing"
	"time"
)

func TestPathSelectorPrefersDirectOverRelayRegardlessOfRTT(t *testing.T) {
	selector := defaultPathSelector()
	direct := selectablePath{
		path: PathDirect,
		key:  "203.0.113.10:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 12345},
		rtt:  1000 * time.Millisecond,
	}
	relay := selectablePath{
		path: PathRelay,
		key:  "relay",
		rtt:  time.Millisecond,
	}

	selected, ok := selector.selectPath(selectablePath{}, false, []selectablePath{relay, direct})
	if !ok {
		t.Fatal("selectPath() ok = false, want true")
	}
	if selected.path != PathDirect || selected.key != direct.key {
		t.Fatalf("selectPath() = (%v, %q), want (%v, %q)", selected.path, selected.key, PathDirect, direct.key)
	}
}

func TestPathSelectorKeepsCurrentDirectWhenRTTImprovementIsBelowHysteresis(t *testing.T) {
	selector := defaultPathSelector()
	current := selectablePath{
		path: PathDirect,
		key:  "203.0.113.20:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 12345},
		rtt:  20 * time.Millisecond,
	}
	candidate := selectablePath{
		path: PathDirect,
		key:  "203.0.113.21:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 21), Port: 12345},
		rtt:  16 * time.Millisecond,
	}

	selected, ok := selector.selectPath(current, true, []selectablePath{candidate})
	if !ok {
		t.Fatal("selectPath() ok = false, want true")
	}
	if selected.path != PathDirect || selected.key != current.key {
		t.Fatalf("selectPath() = (%v, %q), want current (%v, %q)", selected.path, selected.key, current.path, current.key)
	}
}

func TestPathSelectorSwitchesDirectWhenRTTImprovementMeetsHysteresis(t *testing.T) {
	selector := defaultPathSelector()
	current := selectablePath{
		path: PathDirect,
		key:  "203.0.113.30:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 30), Port: 12345},
		rtt:  20 * time.Millisecond,
	}
	candidate := selectablePath{
		path: PathDirect,
		key:  "203.0.113.31:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 31), Port: 12345},
		rtt:  15 * time.Millisecond,
	}

	selected, ok := selector.selectPath(current, true, []selectablePath{candidate})
	if !ok {
		t.Fatal("selectPath() ok = false, want true")
	}
	if selected.path != PathDirect || selected.key != candidate.key {
		t.Fatalf("selectPath() = (%v, %q), want candidate (%v, %q)", selected.path, selected.key, candidate.path, candidate.key)
	}
}

func TestPathSelectorPrefersPrivateAndCGNATWhenRTTIsClose(t *testing.T) {
	selector := defaultPathSelector()
	current := selectablePath{
		path: PathDirect,
		key:  "203.0.113.40:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 40), Port: 12345},
		rtt:  5 * time.Millisecond,
	}
	candidate := selectablePath{
		path: PathDirect,
		key:  "100.100.10.20:12345",
		addr: &net.UDPAddr{IP: net.IPv4(100, 100, 10, 20), Port: 12345},
		rtt:  6 * time.Millisecond,
	}

	selected, ok := selector.selectPath(current, true, []selectablePath{candidate})
	if !ok {
		t.Fatal("selectPath() ok = false, want true")
	}
	if selected.path != PathDirect || selected.key != candidate.key {
		t.Fatalf("selectPath() = (%v, %q), want CGNAT candidate (%v, %q)", selected.path, selected.key, candidate.path, candidate.key)
	}
}

func TestPathSelectorKeepsCurrentWhenNoBetterCandidateExists(t *testing.T) {
	selector := defaultPathSelector()
	current := selectablePath{
		path: PathDirect,
		key:  "100.100.10.30:12345",
		addr: &net.UDPAddr{IP: net.IPv4(100, 100, 10, 30), Port: 12345},
		rtt:  5 * time.Millisecond,
	}
	candidate := selectablePath{
		path: PathDirect,
		key:  "203.0.113.50:12345",
		addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 50), Port: 12345},
		rtt:  8 * time.Millisecond,
	}

	selected, ok := selector.selectPath(current, true, []selectablePath{candidate})
	if !ok {
		t.Fatal("selectPath() ok = false, want true")
	}
	if selected.path != PathDirect || selected.key != current.key {
		t.Fatalf("selectPath() = (%v, %q), want current (%v, %q)", selected.path, selected.key, current.path, current.key)
	}
}
