// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// MechanismSnapshot is the in-process transport evidence accumulated for a
// set of QUIC connections.
type MechanismSnapshot struct {
	TelemetryPresent     bool
	Connections          uint32
	Streams              uint32
	PacketsSent          uint64
	PacketsReceived      uint64
	PacketsLost          uint64
	WireBytesSent        uint64
	RecoveryWireBytes    uint64
	SmoothedRTT          time.Duration
	HandshakeDuration    time.Duration
	FirstByteDuration    time.Duration
	StreamBytesSent      uint64
	StreamBytesReceived  uint64
	Version              string
	RawSocketBackend     string
	NativeSendBackend    string
	NativeReceiveBackend string
	CloseReason          string
	NativeGSO            string
	NativeReceiveBatch   string
}

type mechanismStreamKey struct {
	connection uint64
	streamID   qlog.StreamID
}

type mechanismInterval struct {
	start int64
	end   int64
}

// MechanismTrace is shared by every connection owned by one direct QUIC
// endpoint. Each qlog producer receives an independent connection identity so
// equal stream IDs on different connections never share recovery state.
type MechanismTrace struct {
	mu             sync.Mutex
	nextConnection uint64
	snapshot       MechanismSnapshot
	streamRanges   map[mechanismStreamKey][]mechanismInterval
	seenStreams    map[mechanismStreamKey]struct{}
}

type mechanismRecorder struct {
	trace      *MechanismTrace
	connection uint64
}

func newQUICMechanismTrace() *MechanismTrace {
	return NewMechanismTrace()
}

func NewMechanismTrace() *MechanismTrace {
	return &MechanismTrace{
		streamRanges: make(map[mechanismStreamKey][]mechanismInterval),
		seenStreams:  make(map[mechanismStreamKey]struct{}),
	}
}

func (t *MechanismTrace) AddProducer() qlogwriter.Recorder {
	t.mu.Lock()
	connection := t.nextConnection
	t.nextConnection++
	t.snapshot.Connections++
	t.mu.Unlock()
	return &mechanismRecorder{trace: t, connection: connection}
}

func (*MechanismTrace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema
}

func (t *MechanismTrace) Snapshot() MechanismSnapshot {
	if t == nil {
		return MechanismSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshot
}

func (r *mechanismRecorder) RecordEvent(event qlogwriter.Event) {
	if r == nil || r.trace == nil {
		return
	}
	r.trace.recordMechanismEvent(r.connection, event)
}

func (*mechanismRecorder) Close() error { return nil }

func (t *MechanismTrace) recordMechanismEvent(connection uint64, event qlogwriter.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snapshot.TelemetryPresent = true
	event = mechanismEventValue(event)
	switch event := event.(type) {
	case qlog.PacketSent:
		t.recordPacketSentLocked(connection, event)
	case qlog.PacketReceived:
		t.snapshot.PacketsReceived++
		t.recordStreamsLocked(connection, event.Frames)
	case qlog.PacketLost:
		t.snapshot.PacketsLost++
	case qlog.MetricsUpdated:
		t.recordSmoothedRTTLocked(event.SmoothedRTT)
	}
}

func mechanismEventValue(event qlogwriter.Event) qlogwriter.Event {
	switch event := event.(type) {
	case *qlog.PacketSent:
		if event != nil {
			return *event
		}
	case *qlog.PacketReceived:
		if event != nil {
			return *event
		}
	case *qlog.PacketLost:
		if event != nil {
			return *event
		}
	case *qlog.MetricsUpdated:
		if event != nil {
			return *event
		}
	}
	return event
}

func (t *MechanismTrace) recordPacketSentLocked(connection uint64, event qlog.PacketSent) {
	t.snapshot.PacketsSent++
	if event.Raw.Length > 0 {
		t.snapshot.WireBytesSent += uint64(event.Raw.Length)
	}
	recovery := t.packetContainsRecoveryLocked(connection, event.Frames)
	if recovery && event.Raw.Length > 0 {
		t.snapshot.RecoveryWireBytes += uint64(event.Raw.Length)
	}
	t.recordStreamsLocked(connection, event.Frames)
	t.mergePacketStreamRangesLocked(connection, event.Frames)
}

func (t *MechanismTrace) packetContainsRecoveryLocked(connection uint64, frames []qlog.Frame) bool {
	for _, frame := range frames {
		stream, ok := mechanismStreamFrame(frame)
		if !ok || stream.Length <= 0 {
			continue
		}
		key := mechanismStreamKey{connection: connection, streamID: stream.StreamID}
		if mechanismRangeOverlaps(t.streamRanges[key], stream.Offset, stream.Offset+stream.Length) {
			return true
		}
	}
	return false
}

func (t *MechanismTrace) mergePacketStreamRangesLocked(connection uint64, frames []qlog.Frame) {
	for _, frame := range frames {
		stream, ok := mechanismStreamFrame(frame)
		if !ok || stream.Length <= 0 {
			continue
		}
		key := mechanismStreamKey{connection: connection, streamID: stream.StreamID}
		t.streamRanges[key] = mergeMechanismInterval(t.streamRanges[key], mechanismInterval{start: stream.Offset, end: stream.Offset + stream.Length})
	}
}

func (t *MechanismTrace) recordStreamsLocked(connection uint64, frames []qlog.Frame) {
	for _, frame := range frames {
		stream, ok := mechanismStreamFrame(frame)
		if !ok {
			continue
		}
		key := mechanismStreamKey{connection: connection, streamID: stream.StreamID}
		if _, seen := t.seenStreams[key]; seen {
			continue
		}
		t.seenStreams[key] = struct{}{}
		t.snapshot.Streams++
	}
}

func (t *MechanismTrace) recordSmoothedRTTLocked(rtt time.Duration) {
	if rtt > t.snapshot.SmoothedRTT {
		t.snapshot.SmoothedRTT = rtt
	}
}

func mechanismStreamFrame(frame qlog.Frame) (qlog.StreamFrame, bool) {
	switch stream := frame.Frame.(type) {
	case qlog.StreamFrame:
		return stream, true
	case *qlog.StreamFrame:
		if stream != nil {
			return *stream, true
		}
	}
	return qlog.StreamFrame{}, false
}

func mechanismRangeOverlaps(intervals []mechanismInterval, start, end int64) bool {
	if end <= start {
		return false
	}
	for _, interval := range intervals {
		if start < interval.end && end > interval.start {
			return true
		}
	}
	return false
}

func mergeMechanismInterval(intervals []mechanismInterval, next mechanismInterval) []mechanismInterval {
	if next.end <= next.start {
		return intervals
	}
	intervals = append(intervals, next)
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start < intervals[j].start })
	merged := intervals[:0]
	for _, interval := range intervals {
		last := len(merged) - 1
		if last < 0 || interval.start > merged[last].end {
			merged = append(merged, interval)
			continue
		}
		if interval.end > merged[last].end {
			merged[last].end = interval.end
		}
	}
	return merged
}

type multiplexTrace struct {
	traces []qlogwriter.Trace
}

type multiplexRecorder struct {
	recorders []qlogwriter.Recorder
}

func (t *multiplexTrace) AddProducer() qlogwriter.Recorder {
	recorders := make([]qlogwriter.Recorder, 0, len(t.traces))
	for _, trace := range t.traces {
		if trace != nil {
			recorders = append(recorders, trace.AddProducer())
		}
	}
	return &multiplexRecorder{recorders: recorders}
}

func (t *multiplexTrace) SupportsSchemas(schema string) bool {
	for _, trace := range t.traces {
		if trace != nil && !trace.SupportsSchemas(schema) {
			return false
		}
	}
	return len(t.traces) > 0
}

func (r *multiplexRecorder) RecordEvent(event qlogwriter.Event) {
	for _, recorder := range r.recorders {
		recorder.RecordEvent(event)
	}
}

func (r *multiplexRecorder) Close() error {
	var errs []error
	for _, recorder := range r.recorders {
		if err := recorder.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

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
