package session

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/derpcat/pkg/telemetry"
)

func TestExternalTransferMetricsTrackRelayAndDirectBytes(t *testing.T) {
	start := time.Unix(0, 0)
	m := newExternalTransferMetrics(start)
	m.RecordRelayWrite(32<<10, start.Add(20*time.Millisecond))
	m.RecordDirectWrite(1<<20, start.Add(450*time.Millisecond))
	m.Complete(start.Add(1450 * time.Millisecond))

	if got := m.TotalDurationMS(); got != 1450 {
		t.Fatalf("TotalDurationMS() = %d, want 1450", got)
	}
	if got := m.FirstByteMS(); got != 20 {
		t.Fatalf("FirstByteMS() = %d, want 20", got)
	}
	if got := m.DirectBytes(); got != 1<<20 {
		t.Fatalf("DirectBytes() = %d, want %d", got, 1<<20)
	}
}

func TestEmitExternalTransferMetricsIncludesWallAndPeakValues(t *testing.T) {
	start := time.Unix(0, 0)
	m := newExternalTransferMetrics(start)
	m.RecordRelayWrite(64<<10, start.Add(15*time.Millisecond))
	m.RecordDirectWrite(1<<20, start.Add(300*time.Millisecond))
	m.Complete(start.Add(1300 * time.Millisecond))

	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	m.Emit(emitter, "udp-send", probe.TransferStats{PeakGoodputMbps: 2011.4})

	got := buf.String()
	for _, needle := range []string{
		"udp-send-wall-duration-ms=1300",
		"udp-send-session-first-byte-ms=15",
		"udp-send-relay-bytes=65536",
		"udp-send-direct-bytes=1048576",
		"udp-send-peak-goodput-mbps=2011.40",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("metrics output missing %q in %q", needle, got)
		}
	}
}
