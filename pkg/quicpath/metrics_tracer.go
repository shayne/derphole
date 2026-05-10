// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type quicMetricsSummary struct {
	Events                    uint64  `json:"events"`
	MetricsEvents             uint64  `json:"metrics_events"`
	SlowStartEvents           uint64  `json:"slow_start_events"`
	CongestionAvoidanceEvents uint64  `json:"congestion_avoidance_events"`
	RecoveryEvents            uint64  `json:"recovery_events"`
	ApplicationLimitedEvents  uint64  `json:"application_limited_events"`
	PacketLostEvents          uint64  `json:"packet_lost_events"`
	SpuriousLossEvents        uint64  `json:"spurious_loss_events"`
	MaxCongestionWindow       int     `json:"max_congestion_window"`
	MaxBytesInFlight          int     `json:"max_bytes_in_flight"`
	MaxPacketsInFlight        int     `json:"max_packets_in_flight"`
	MaxSmoothedRTTMS          float64 `json:"max_smoothed_rtt_ms"`
	MaxLatestRTTMS            float64 `json:"max_latest_rtt_ms"`
	MaxMinRTTMS               float64 `json:"max_min_rtt_ms"`
	MaxMTU                    uint64  `json:"max_mtu"`
}

type quicMetricsTrace struct {
	mu        sync.Mutex
	path      string
	producers int
	summary   quicMetricsSummary
}

type quicMetricsRecorder struct {
	trace *quicMetricsTrace
}

func metricsTracerFromEnv() func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	dir := os.Getenv("DERPHOLE_QUIC_METRICS_DIR")
	if dir == "" {
		return nil
	}
	return func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		perspective := "server"
		if isClient {
			perspective = "client"
		}
		return &quicMetricsTrace{
			path: filepath.Join(dir, fmt.Sprintf("derphole-%s-%s.metrics.json", connID, perspective)),
		}
	}
}

func (t *quicMetricsTrace) AddProducer() qlogwriter.Recorder {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.producers++
	return &quicMetricsRecorder{trace: t}
}

func (t *quicMetricsTrace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema
}

func (r *quicMetricsRecorder) RecordEvent(ev qlogwriter.Event) {
	r.trace.recordEvent(ev)
}

func (r *quicMetricsRecorder) Close() error {
	return r.trace.closeProducer()
}

func (t *quicMetricsTrace) recordEvent(ev qlogwriter.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.summary.Events++
	t.recordEventLocked(ev)
}

func (t *quicMetricsTrace) recordEventLocked(ev qlogwriter.Event) {
	if t.recordMetricsEventLocked(ev) {
		return
	}
	if t.recordCongestionEventLocked(ev) {
		return
	}
	if t.recordLossEventLocked(ev) {
		return
	}
	t.recordMTUEventLocked(ev)
}

func (t *quicMetricsTrace) recordMetricsEventLocked(ev qlogwriter.Event) bool {
	switch event := ev.(type) {
	case qlog.MetricsUpdated:
		t.recordMetricsUpdatedLocked(event)
		return true
	case *qlog.MetricsUpdated:
		if event != nil {
			t.recordMetricsUpdatedLocked(*event)
		}
		return true
	default:
		return false
	}
}

func (t *quicMetricsTrace) recordCongestionEventLocked(ev qlogwriter.Event) bool {
	switch event := ev.(type) {
	case qlog.CongestionStateUpdated:
		t.recordCongestionStateUpdatedLocked(event.State)
		return true
	case *qlog.CongestionStateUpdated:
		if event != nil {
			t.recordCongestionStateUpdatedLocked(event.State)
		}
		return true
	default:
		return false
	}
}

func (t *quicMetricsTrace) recordLossEventLocked(ev qlogwriter.Event) bool {
	switch event := ev.(type) {
	case qlog.PacketLost:
		t.summary.PacketLostEvents++
		return true
	case *qlog.PacketLost:
		if event != nil {
			t.summary.PacketLostEvents++
		}
		return true
	case qlog.SpuriousLoss:
		t.summary.SpuriousLossEvents++
		return true
	case *qlog.SpuriousLoss:
		if event != nil {
			t.summary.SpuriousLossEvents++
		}
		return true
	default:
		return false
	}
}

func (t *quicMetricsTrace) recordMTUEventLocked(ev qlogwriter.Event) {
	switch event := ev.(type) {
	case qlog.MTUUpdated:
		t.recordMTULocked(uint64(event.Value))
	case *qlog.MTUUpdated:
		if event != nil {
			t.recordMTULocked(uint64(event.Value))
		}
	}
}

func (t *quicMetricsTrace) recordMTULocked(value uint64) {
	if value > t.summary.MaxMTU {
		t.summary.MaxMTU = value
	}
}

func (t *quicMetricsTrace) recordCongestionStateUpdatedLocked(state qlog.CongestionState) {
	switch state {
	case qlog.CongestionStateSlowStart:
		t.summary.SlowStartEvents++
	case qlog.CongestionStateCongestionAvoidance:
		t.summary.CongestionAvoidanceEvents++
	case qlog.CongestionStateRecovery:
		t.summary.RecoveryEvents++
	case qlog.CongestionStateApplicationLimited:
		t.summary.ApplicationLimitedEvents++
	}
}

func (t *quicMetricsTrace) recordMetricsUpdatedLocked(ev qlog.MetricsUpdated) {
	t.summary.MetricsEvents++
	if ev.CongestionWindow > t.summary.MaxCongestionWindow {
		t.summary.MaxCongestionWindow = ev.CongestionWindow
	}
	if ev.BytesInFlight > t.summary.MaxBytesInFlight {
		t.summary.MaxBytesInFlight = ev.BytesInFlight
	}
	if ev.PacketsInFlight > t.summary.MaxPacketsInFlight {
		t.summary.MaxPacketsInFlight = ev.PacketsInFlight
	}
	if v := durationMillis(ev.SmoothedRTT); v > t.summary.MaxSmoothedRTTMS {
		t.summary.MaxSmoothedRTTMS = v
	}
	if v := durationMillis(ev.LatestRTT); v > t.summary.MaxLatestRTTMS {
		t.summary.MaxLatestRTTMS = v
	}
	if v := durationMillis(ev.MinRTT); v > t.summary.MaxMinRTTMS {
		t.summary.MaxMinRTTMS = v
	}
}

func (t *quicMetricsTrace) closeProducer() error {
	t.mu.Lock()
	if t.producers > 0 {
		t.producers--
	}
	done := t.producers == 0
	summary := t.summary
	path := t.path
	t.mu.Unlock()

	if !done {
		return nil
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(summary); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
