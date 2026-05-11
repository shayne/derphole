// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleSend    Role = "send"
	RoleReceive Role = "receive"
)

type Phase string

const (
	PhaseClaim         Phase = "claim"
	PhaseRelay         Phase = "relay"
	PhaseDirectPrepare Phase = "direct_prepare"
	PhaseDirectProbe   Phase = "direct_probe"
	PhaseDirectExecute Phase = "direct_execute"
	PhaseOverlap       Phase = "overlap"
	PhaseComplete      Phase = "complete"
	PhaseError         Phase = "error"
)

var Header = []string{
	"timestamp_unix_ms",
	"elapsed_ms",
	"role",
	"phase",
	"relay_bytes",
	"direct_bytes",
	"app_bytes",
	"delta_app_bytes",
	"app_mbps",
	"direct_rate_selected_mbps",
	"direct_rate_active_mbps",
	"direct_lanes_active",
	"direct_lanes_available",
	"direct_probe_state",
	"direct_probe_summary",
	"replay_window_bytes",
	"repair_queue_bytes",
	"retransmit_count",
	"out_of_order_bytes",
	"last_state",
	"last_error",
}

const HeaderLine = "timestamp_unix_ms,elapsed_ms,role,phase,relay_bytes,direct_bytes,app_bytes,delta_app_bytes,app_mbps,direct_rate_selected_mbps,direct_rate_active_mbps,direct_lanes_active,direct_lanes_available,direct_probe_state,direct_probe_summary,replay_window_bytes,repair_queue_bytes,retransmit_count,out_of_order_bytes,last_state,last_error"

type Snapshot struct {
	At                     time.Time
	Phase                  Phase
	RelayBytes             int64
	DirectBytes            int64
	AppBytes               int64
	DirectRateSelectedMbps int
	DirectRateActiveMbps   int
	DirectLanesActive      int
	DirectLanesAvailable   int
	DirectProbeState       string
	DirectProbeSummary     string
	ReplayWindowBytes      uint64
	RepairQueueBytes       uint64
	RetransmitCount        int64
	OutOfOrderBytes        uint64
	LastState              string
	LastError              string
}

type Recorder struct {
	mu      sync.Mutex
	role    Role
	start   time.Time
	w       *csv.Writer
	lastAt  time.Time
	lastApp int64
	current Snapshot
	closed  bool
	err     error
}

func NewRecorder(out io.Writer, role Role, start time.Time) (*Recorder, error) {
	if out == nil {
		return nil, errors.New("transfertrace: nil writer")
	}
	if start.IsZero() {
		start = time.Now()
	}
	w := csv.NewWriter(out)
	if err := w.Write(Header); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return &Recorder{
		role:  role,
		start: start,
		w:     w,
	}, nil
}

func (r *Recorder) Update(update func(*Snapshot)) {
	if update == nil {
		return
	}
	r.mu.Lock()
	snap := r.current
	update(&snap)
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Observe(snap Snapshot) {
	r.mu.Lock()
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Tick(at time.Time) {
	r.mu.Lock()
	snap := r.current
	snap.At = at
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Error(at time.Time, message string) {
	r.mu.Lock()
	snap := r.current
	snap.At = at
	snap.Phase = PhaseError
	snap.LastError = message
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Complete(at time.Time) {
	r.mu.Lock()
	snap := r.current
	snap.At = at
	snap.Phase = PhaseComplete
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Run(ctxDone <-chan struct{}, interval time.Duration, now func() time.Time) {
	ticker := time.NewTicker(runInterval(interval))
	defer ticker.Stop()
	runTicks(ctxDone, ticker.C, func() {
		r.Tick(runNow(now))
	})
}

func runTicks(done <-chan struct{}, ticks <-chan time.Time, tick func()) {
	for {
		select {
		case <-done:
			return
		case <-ticks:
			tick()
		}
	}
}

func runInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return time.Second
	}
	return interval
}

func runNow(now func() time.Time) time.Time {
	if now == nil {
		return time.Now()
	}
	return now()
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.err
	}
	r.closed = true
	r.w.Flush()
	if err := r.w.Error(); err != nil && r.err == nil {
		r.err = err
	}
	return r.err
}

func (r *Recorder) observeLocked(snap Snapshot) {
	if r.closed || r.err != nil {
		return
	}
	if snap.At.IsZero() {
		snap.At = time.Now()
	}
	deltaBytes := snap.AppBytes - r.lastApp
	if deltaBytes < 0 {
		deltaBytes = 0
	}
	deltaMS := int64(0)
	if !r.lastAt.IsZero() {
		deltaMS = snap.At.Sub(r.lastAt).Milliseconds()
	} else {
		deltaMS = snap.At.Sub(r.start).Milliseconds()
	}
	if deltaMS < 0 {
		deltaMS = 0
	}
	if err := r.w.Write(r.row(snap, deltaBytes, deltaMS)); err != nil {
		r.err = err
		return
	}
	r.w.Flush()
	if err := r.w.Error(); err != nil {
		r.err = err
		return
	}
	r.current = snap
	r.lastAt = snap.At
	r.lastApp = snap.AppBytes
}

func (r *Recorder) row(snap Snapshot, deltaBytes int64, deltaMS int64) []string {
	return []string{
		strconv.FormatInt(snap.At.UnixMilli(), 10),
		strconv.FormatInt(snap.At.Sub(r.start).Milliseconds(), 10),
		string(r.role),
		string(snap.Phase),
		strconv.FormatInt(snap.RelayBytes, 10),
		strconv.FormatInt(snap.DirectBytes, 10),
		strconv.FormatInt(snap.AppBytes, 10),
		strconv.FormatInt(deltaBytes, 10),
		formatMbps(deltaBytes, deltaMS),
		formatOptionalInt(snap.DirectRateSelectedMbps),
		formatOptionalInt(snap.DirectRateActiveMbps),
		formatOptionalInt(snap.DirectLanesActive),
		formatOptionalInt(snap.DirectLanesAvailable),
		snap.DirectProbeState,
		snap.DirectProbeSummary,
		formatOptionalUint64(snap.ReplayWindowBytes),
		formatOptionalUint64(snap.RepairQueueBytes),
		formatOptionalInt64(snap.RetransmitCount),
		formatOptionalUint64(snap.OutOfOrderBytes),
		snap.LastState,
		snap.LastError,
	}
}

func formatMbps(deltaBytes int64, deltaMS int64) string {
	if deltaBytes == 0 || deltaMS <= 0 {
		return "0.00"
	}
	return fmt.Sprintf("%.2f", float64(deltaBytes*8)/float64(deltaMS*1000))
}

func formatOptionalInt(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func formatOptionalInt64(value int64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func formatOptionalUint64(value uint64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatUint(value, 10)
}

func init() {
	if strings.Join(Header, ",") != HeaderLine {
		panic("transfertrace: header mismatch")
	}
}
