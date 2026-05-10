// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"strings"
	"testing"
)

func TestFormatHumanDirectFriendly(t *testing.T) {
	report := Report{
		Verdict: VerdictDirectFriendly,
		UDP: UDPReport{
			Outbound:        true,
			STUN:            true,
			PublicEndpoints: []string{"203.0.113.10:57179"},
			MappingStable:   true,
			PortPreserving:  true,
		},
		Candidates: CandidateReport{
			LAN:     []string{"192.168.1.20"},
			Overlay: []string{"100.64.10.20"},
			Public:  []string{"203.0.113.10:57179"},
		},
		Recommendation: Recommendation(VerdictDirectFriendly),
	}
	got := FormatHuman(report)
	for _, want := range []string{
		"Network check: direct-friendly",
		"Outbound UDP: yes",
		"STUN: yes",
		"Public endpoint: 203.0.113.10:57179",
		"Mapping: stable across STUN servers",
		"Port preservation: yes",
		"LAN: 192.168.1.20",
		"Overlay: 100.64.10.20",
		"Public: 203.0.113.10:57179",
		"This side looks capable of direct UDP.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatHuman() missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "topology") {
		t.Fatalf("FormatHuman() should not reference unavailable topology command:\n%s", got)
	}
}

func TestFormatHumanDirectLimited(t *testing.T) {
	report := Report{
		Verdict: VerdictDirectLimited,
		UDP: UDPReport{
			Outbound:        true,
			STUN:            true,
			PublicEndpoints: []string{"198.51.100.20:51433", "198.51.100.20:60000"},
			MappingStable:   false,
			PortPreserving:  false,
		},
		Recommendation: Recommendation(VerdictDirectLimited),
	}
	got := FormatHuman(report)
	for _, want := range []string{
		"Network check: direct-limited",
		"Public endpoint: 198.51.100.20:51433, 198.51.100.20:60000",
		"Mapping: changes by STUN destination",
		"Port preservation: no",
		"LAN: none",
		"Direct UDP may fail with ordinary hole punching.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatHuman() missing %q in:\n%s", want, got)
		}
	}
}

func TestFormatHumanRelayOnlyLikely(t *testing.T) {
	report := Report{
		Verdict:        VerdictRelayOnlyLikely,
		UDP:            UDPReport{},
		Recommendation: Recommendation(VerdictRelayOnlyLikely),
	}
	got := FormatHuman(report)
	for _, want := range []string{
		"Network check: relay-only-likely",
		"Outbound UDP: no",
		"STUN: no",
		"Public endpoint: unavailable",
		"Mapping: unavailable",
		"Direct UDP is unlikely from this network.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatHuman() missing %q in:\n%s", want, got)
		}
	}
}
