// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"testing"
	"time"
)

func TestIntervalStatsTracksPeakThroughputFromMeasuredDeltas(t *testing.T) {
	var stats intervalStats
	started := time.Unix(100, 0)

	stats.Observe(started, 0)
	stats.Observe(started.Add(100*time.Millisecond), 1<<20)
	stats.Observe(started.Add(200*time.Millisecond), 3<<20)

	if got, want := stats.PeakMbps(), float64(2<<20)*8/0.1/1_000_000; !almostEqual(got, want) {
		t.Fatalf("PeakMbps() = %f, want %f", got, want)
	}
}

func TestIntervalStatsIgnoresNonMonotonicOrZeroDeltaSamples(t *testing.T) {
	var stats intervalStats
	started := time.Unix(200, 0)

	stats.Observe(started, 0)
	stats.Observe(started.Add(100*time.Millisecond), 1024)
	peak := stats.PeakMbps()

	stats.Observe(started.Add(100*time.Millisecond), 1024)
	stats.Observe(started.Add(90*time.Millisecond), 2048)
	stats.Observe(started.Add(150*time.Millisecond), 512)

	if got := stats.PeakMbps(); !almostEqual(got, peak) {
		t.Fatalf("PeakMbps() = %f, want %f", got, peak)
	}
}

func TestIntervalStatsIgnoresSubWindowBurstsForPeak(t *testing.T) {
	var stats intervalStats
	started := time.Unix(300, 0)

	stats.Observe(started, 0)
	stats.Observe(started.Add(100*time.Millisecond), 1<<20)
	firstPeak := stats.PeakMbps()

	stats.Observe(started.Add(101*time.Millisecond), 2<<20)
	if got := stats.PeakMbps(); !almostEqual(got, firstPeak) {
		t.Fatalf("PeakMbps() after sub-window burst = %f, want %f", got, firstPeak)
	}

	stats.Observe(started.Add(200*time.Millisecond), 3<<20)
	if got, want := stats.PeakMbps(), float64(2<<20)*8/0.1/1_000_000; !almostEqual(got, want) {
		t.Fatalf("PeakMbps() = %f, want %f", got, want)
	}
}

func TestIntervalStatsObserveCompletionCapturesFastTransferPeak(t *testing.T) {
	var stats intervalStats
	started := time.Unix(400, 0)

	stats.Observe(started, 0)
	stats.Observe(started.Add(time.Millisecond), 1<<20)
	if got := stats.PeakMbps(); got != 0 {
		t.Fatalf("PeakMbps() before completion = %f, want 0", got)
	}

	stats.ObserveCompletion(started.Add(5*time.Millisecond), 2<<20)
	if got, want := stats.PeakMbps(), float64(2<<20)*8/0.005/1_000_000; !almostEqual(got, want) {
		t.Fatalf("PeakMbps() = %f, want %f", got, want)
	}
}
