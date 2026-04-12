package derphole

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgressReporterUsesRecentSmoothedRate(t *testing.T) {
	start := time.Unix(0, 0)
	now := start
	prevProgressNow := progressNow
	progressNow = func() time.Time { return now }
	t.Cleanup(func() { progressNow = prevProgressNow })

	var out bytes.Buffer
	progress := NewProgressReporter(&out, 20*1024*1024)

	now = start.Add(100 * time.Millisecond)
	progress.Add(10 * 1024 * 1024)

	now = start.Add(10 * time.Second)
	progress.Add(1024)

	got := out.String()
	if !strings.Contains(got, "719.1KiB/s") {
		t.Fatalf("progress output = %q, want tqdm-style smoothed recent rate near 719.1KiB/s", got)
	}
	if strings.Contains(got, "1.0MiB/s") {
		t.Fatalf("progress output = %q, want tqdm-style recent rate, not cumulative average", got)
	}
}
