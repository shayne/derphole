// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "testing"

func TestParseParallelPolicyAcceptsFixedAndAuto(t *testing.T) {
	cases := []struct {
		raw  string
		want ParallelPolicy
	}{
		{raw: "8", want: FixedParallelPolicy(8)},
		{raw: "auto", want: AutoParallelPolicy()},
	}
	for _, tc := range cases {
		got, err := ParseParallelPolicy(tc.raw)
		if err != nil {
			t.Fatalf("ParseParallelPolicy(%q) error = %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("ParseParallelPolicy(%q) = %#v, want %#v", tc.raw, got, tc.want)
		}
	}
}

func TestParseParallelPolicyRejectsInvalidValues(t *testing.T) {
	for _, raw := range []string{"", "0", "-1", "bogus", "17"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseParallelPolicy(raw); err == nil {
				t.Fatalf("ParseParallelPolicy(%q) error = nil, want error", raw)
			}
		})
	}
}

func TestDefaultParallelPolicyUsesInitialStripeCount(t *testing.T) {
	if got, want := DefaultParallelPolicy(), FixedParallelPolicy(4); got != want {
		t.Fatalf("DefaultParallelPolicy() = %#v, want %#v", got, want)
	}
}

func TestParallelAutoControllerRequestsGrowthWhenThroughputImproves(t *testing.T) {
	c := newParallelAutoController(AutoParallelPolicy())

	first := c.Observe(parallelWindow{
		Target:         4,
		BacklogLimited: true,
		ThroughputMbps: 300,
	})
	if first.NextTarget != 8 {
		t.Fatalf("first Observe() next target = %d, want 8", first.NextTarget)
	}

	for i := 0; i < AutoParallelHoldSamples; i++ {
		hold := c.Observe(parallelWindow{
			Target:             8,
			BacklogLimited:     true,
			ThroughputMbps:     410,
			PreviousThroughput: 300,
		})
		if hold.NextTarget != 0 || hold.StopReason != "" {
			t.Fatalf("hold Observe() = %#v, want no decision", hold)
		}
	}

	second := c.Observe(parallelWindow{
		Target:             8,
		BacklogLimited:     true,
		ThroughputMbps:     470,
		PreviousThroughput: 410,
	})
	if second.NextTarget != 10 {
		t.Fatalf("second Observe() next target = %d, want 10", second.NextTarget)
	}
	if second.StopReason != "" {
		t.Fatalf("second Observe() stop reason = %q, want empty", second.StopReason)
	}
}

func TestParallelAutoControllerStopsOnDiminishingReturn(t *testing.T) {
	c := newParallelAutoController(AutoParallelPolicy())

	first := c.Observe(parallelWindow{
		Target:         4,
		BacklogLimited: true,
		ThroughputMbps: 300,
	})
	if first.NextTarget != 8 {
		t.Fatalf("first Observe() next target = %d, want 8", first.NextTarget)
	}

	for i := 0; i < AutoParallelHoldSamples; i++ {
		hold := c.Observe(parallelWindow{
			Target:             8,
			BacklogLimited:     true,
			ThroughputMbps:     320,
			PreviousThroughput: 300,
		})
		if hold.NextTarget != 0 || hold.StopReason != "" {
			t.Fatalf("hold Observe() = %#v, want no decision", hold)
		}
	}

	second := c.Observe(parallelWindow{
		Target:             8,
		BacklogLimited:     true,
		ThroughputMbps:     320,
		PreviousThroughput: 300,
	})
	if second.NextTarget != 0 {
		t.Fatalf("second Observe() next target = %d, want 0", second.NextTarget)
	}
	if second.StopReason != "diminishing-return" {
		t.Fatalf("second Observe() stop reason = %q, want %q", second.StopReason, "diminishing-return")
	}
}

func TestParallelAutoControllerRespectsCapBelowFloor(t *testing.T) {
	c := newParallelAutoController(ParallelPolicy{
		Mode:    ParallelModeAuto,
		Initial: 4,
		Cap:     6,
	})

	first := c.Observe(parallelWindow{
		Target:             6,
		BacklogLimited:     true,
		ThroughputMbps:     320,
		PreviousThroughput: 300,
	})
	if first.NextTarget != 0 {
		t.Fatalf("Observe() next target = %d, want 0", first.NextTarget)
	}
	if first.StopReason != "" {
		t.Fatalf("Observe() stop reason = %q, want empty", first.StopReason)
	}
}
