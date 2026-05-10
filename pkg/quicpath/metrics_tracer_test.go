// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

func TestQUICMetricsTraceCountsCongestionStateTransitions(t *testing.T) {
	trace := &quicMetricsTrace{}

	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateApplicationLimited})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateApplicationLimited})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateCongestionAvoidance})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery})

	if trace.summary.SlowStartEvents != 1 {
		t.Fatalf("SlowStartEvents = %d, want 1", trace.summary.SlowStartEvents)
	}
	if trace.summary.ApplicationLimitedEvents != 2 {
		t.Fatalf("ApplicationLimitedEvents = %d, want 2", trace.summary.ApplicationLimitedEvents)
	}
	if trace.summary.CongestionAvoidanceEvents != 1 {
		t.Fatalf("CongestionAvoidanceEvents = %d, want 1", trace.summary.CongestionAvoidanceEvents)
	}
	if trace.summary.RecoveryEvents != 1 {
		t.Fatalf("RecoveryEvents = %d, want 1", trace.summary.RecoveryEvents)
	}
}

func TestQUICMetricsTraceCountsLossEvents(t *testing.T) {
	trace := &quicMetricsTrace{}

	trace.recordEvent(qlog.PacketLost{})
	trace.recordEvent(&qlog.PacketLost{})
	trace.recordEvent(qlog.SpuriousLoss{})
	trace.recordEvent(&qlog.SpuriousLoss{})

	if trace.summary.PacketLostEvents != 2 {
		t.Fatalf("PacketLostEvents = %d, want 2", trace.summary.PacketLostEvents)
	}
	if trace.summary.SpuriousLossEvents != 2 {
		t.Fatalf("SpuriousLossEvents = %d, want 2", trace.summary.SpuriousLossEvents)
	}
}

func TestQUICMetricsTraceRecordsMaxMetrics(t *testing.T) {
	trace := &quicMetricsTrace{}

	trace.recordEvent(qlog.MetricsUpdated{
		CongestionWindow: 10,
		BytesInFlight:    20,
		PacketsInFlight:  2,
		SmoothedRTT:      5 * time.Millisecond,
		LatestRTT:        6 * time.Millisecond,
		MinRTT:           4 * time.Millisecond,
	})
	trace.recordEvent(&qlog.MetricsUpdated{
		CongestionWindow: 9,
		BytesInFlight:    21,
		PacketsInFlight:  3,
		SmoothedRTT:      3 * time.Millisecond,
		LatestRTT:        7 * time.Millisecond,
		MinRTT:           2 * time.Millisecond,
	})
	trace.recordEvent(qlog.MTUUpdated{Value: 1280})
	trace.recordEvent(&qlog.MTUUpdated{Value: 1400})

	if trace.summary.MetricsEvents != 2 {
		t.Fatalf("MetricsEvents = %d, want 2", trace.summary.MetricsEvents)
	}
	if trace.summary.MaxCongestionWindow != 10 {
		t.Fatalf("MaxCongestionWindow = %d, want 10", trace.summary.MaxCongestionWindow)
	}
	if trace.summary.MaxBytesInFlight != 21 {
		t.Fatalf("MaxBytesInFlight = %d, want 21", trace.summary.MaxBytesInFlight)
	}
	if trace.summary.MaxPacketsInFlight != 3 {
		t.Fatalf("MaxPacketsInFlight = %d, want 3", trace.summary.MaxPacketsInFlight)
	}
	if trace.summary.MaxSmoothedRTTMS != 5 {
		t.Fatalf("MaxSmoothedRTTMS = %f, want 5", trace.summary.MaxSmoothedRTTMS)
	}
	if trace.summary.MaxLatestRTTMS != 7 {
		t.Fatalf("MaxLatestRTTMS = %f, want 7", trace.summary.MaxLatestRTTMS)
	}
	if trace.summary.MaxMinRTTMS != 4 {
		t.Fatalf("MaxMinRTTMS = %f, want 4", trace.summary.MaxMinRTTMS)
	}
	if trace.summary.MaxMTU != 1400 {
		t.Fatalf("MaxMTU = %d, want 1400", trace.summary.MaxMTU)
	}
}

func TestQUICMetricsTraceProducerLifecycleWritesSummary(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DERPHOLE_QUIC_METRICS_DIR", dir)

	tracer := metricsTracerFromEnv()
	if tracer == nil {
		t.Fatal("metricsTracerFromEnv() = nil, want tracer")
	}
	trace := tracer(context.Background(), true, quic.ConnectionIDFromBytes([]byte{0xaa, 0xbb}))
	if !trace.SupportsSchemas(qlog.EventSchema) {
		t.Fatal("SupportsSchemas(qlog.EventSchema) = false, want true")
	}
	if trace.SupportsSchemas("other") {
		t.Fatal("SupportsSchemas(other) = true, want false")
	}

	first := trace.AddProducer()
	second := trace.AddProducer()
	first.RecordEvent(qlog.PacketLost{})
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, "*.metrics.json")); err != nil || len(matches) != 0 {
		t.Fatalf("metrics files after first close = %v, %v; want none", matches, err)
	}
	second.RecordEvent(qlog.SpuriousLoss{})
	if err := second.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*.metrics.json"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("metrics files = %v, want one file", matches)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var summary quicMetricsSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if summary.Events != 2 || summary.PacketLostEvents != 1 || summary.SpuriousLossEvents != 1 {
		t.Fatalf("summary = %+v, want both loss events", summary)
	}
}
