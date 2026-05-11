// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
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

func TestExternalTransferMetricsNilReceiverWriteAndCompleteNoop(t *testing.T) {
	var m *externalTransferMetrics

	m.RecordRelayWrite(1024, time.Unix(1, 0))
	m.RecordDirectWrite(2048, time.Unix(2, 0))
	m.Complete(time.Unix(3, 0))
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

func TestExternalTransferMetricsUpdatesTrace(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(10, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	metrics.RecordRelayWrite(1024, time.Unix(10, int64(500*time.Millisecond)))
	metrics.Tick(time.Unix(10, int64(500*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, ",send,relay,1024,0,1024,1024,") {
		t.Fatalf("trace body missing relay progress:\n%s", body)
	}
}

func TestListenConfigTraceUpdatesReceiveRelayPrefixTrace(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ListenConfig{Trace: rec}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(20, 0), cfg.Trace, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	metrics.RecordRelayWrite(2048, time.Unix(20, int64(250*time.Millisecond)))
	metrics.Tick(time.Unix(20, int64(250*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, ",receive,relay,2048,0,2048,2048,") {
		t.Fatalf("trace body missing receive relay progress:\n%s", body)
	}
}
