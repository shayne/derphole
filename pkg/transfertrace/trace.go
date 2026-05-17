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

var header = [...]string{
	"timestamp_unix_ms",
	"elapsed_ms",
	"role",
	"phase",
	"relay_bytes",
	"direct_bytes",
	"app_bytes",
	"delta_app_bytes",
	"app_mbps",
	"local_sent_bytes",
	"peer_received_bytes",
	"setup_elapsed_ms",
	"transfer_elapsed_ms",
	"direct_validated",
	"fallback_reason",
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
	"rate_target_mbps",
	"rate_ceiling_mbps",
	"rate_exploration_ceiling_mbps",
	"rate_selected_mbps",
	"active_lanes",
	"available_lanes",
	"lane_min",
	"lane_cap",
	"controller_decision",
	"controller_reason",
	"send_goodput_mbps",
	"receive_goodput_mbps",
	"receiver_committed_mbps",
	"replay_bytes",
	"retransmits",
	"repair_requests",
	"repair_bytes",
	"peer_recv_queue_depth",
	"peer_recv_queue_depth_max",
	"direct_packet_bytes",
	"direct_committed_bytes",
}

var Header = append([]string(nil), header[:]...)

var HeaderLine = strings.Join(header[:], ",")

type Snapshot struct {
	At                         time.Time
	Phase                      Phase
	RelayBytes                 int64
	DirectBytes                int64
	AppBytes                   int64
	LocalSentBytes             int64
	PeerReceivedBytes          int64
	SetupElapsedMS             int64
	TransferElapsedMS          int64
	DirectValidated            bool
	FallbackReason             string
	DirectRateSelectedMbps     int
	DirectRateActiveMbps       int
	DirectLanesActive          int
	DirectLanesAvailable       int
	RateTargetMbps             int
	RateCeilingMbps            int
	RateExplorationCeilingMbps int
	LaneMin                    int
	LaneCap                    int
	ControllerDecision         string
	ControllerReason           string
	DirectProbeState           string
	DirectProbeSummary         string
	ReplayWindowBytes          uint64
	ReplayBytes                uint64
	RepairQueueBytes           uint64
	RetransmitCount            int64
	RepairRequests             int64
	RepairBytes                int64
	OutOfOrderBytes            uint64
	PeerRecvQueueDepth         int
	PeerRecvQueueDepthMax      int
	DirectPacketBytes          int64
	DirectCommittedBytes       int64
	LastState                  string
	LastError                  string
}

type Recorder struct {
	mu                       sync.Mutex
	role                     Role
	start                    time.Time
	w                        *csv.Writer
	lastAt                   time.Time
	lastApp                  int64
	lastLocalSentBytes       int64
	lastDirectPacketBytes    int64
	lastDirectCommittedBytes int64
	lastPeerReceivedBytes    int64
	current                  Snapshot
	closed                   bool
	terminal                 bool
	err                      error
}

func NewRecorder(out io.Writer, role Role, start time.Time) (*Recorder, error) {
	if out == nil {
		return nil, errors.New("transfertrace: nil writer")
	}
	if start.IsZero() {
		start = time.Now()
	}
	w := csv.NewWriter(out)
	if err := w.Write(headerCopy()); err != nil {
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

// Update copies the current snapshot, calls update while holding Recorder.mu,
// and stores the mutated snapshot without recording a CSV row. The callback
// must be fast, non-blocking, and must not call Recorder methods.
func (r *Recorder) Update(update func(*Snapshot)) {
	if update == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.terminal || r.err != nil {
		return
	}
	snap := r.current
	update(&snap)
	r.current = snap
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
	defer r.mu.Unlock()
	if r.closed || r.terminal || r.err != nil {
		return
	}
	snap := r.current
	snap.At = at
	snap.Phase = PhaseError
	snap.LastError = message
	r.observeLocked(snap)
	if r.err == nil {
		r.terminal = true
	}
}

func (r *Recorder) Complete(at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.terminal || r.err != nil {
		return
	}
	snap := r.current
	snap.At = at
	snap.Phase = PhaseComplete
	r.observeLocked(snap)
	if r.err == nil {
		r.terminal = true
	}
}

// Run records ticks until ctxDone is closed. Close flushes and prevents future
// writes, but it does not stop a running Run loop.
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
	if r.closed || r.terminal || r.err != nil {
		return
	}
	if snap.At.IsZero() {
		snap.At = time.Now()
	}
	deltaBytes := nonNegativeDelta(snap.AppBytes, r.lastApp)
	localSentDelta := nonNegativeDelta(snap.LocalSentBytes, r.lastLocalSentBytes)
	directPacketDelta := nonNegativeDelta(snap.DirectPacketBytes, r.lastDirectPacketBytes)
	directCommittedDelta := nonNegativeDelta(snap.DirectCommittedBytes, r.lastDirectCommittedBytes)
	peerReceivedDelta := nonNegativeDelta(snap.PeerReceivedBytes, r.lastPeerReceivedBytes)
	deltaMS := int64(0)
	if !r.lastAt.IsZero() {
		deltaMS = snap.At.Sub(r.lastAt).Milliseconds()
	} else {
		deltaMS = snap.At.Sub(r.start).Milliseconds()
	}
	if deltaMS < 0 {
		deltaMS = 0
	}
	if err := r.w.Write(r.row(snap, deltaBytes, deltaMS, localSentDelta, directPacketDelta, directCommittedDelta, peerReceivedDelta)); err != nil {
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
	r.lastLocalSentBytes = snap.LocalSentBytes
	r.lastDirectPacketBytes = snap.DirectPacketBytes
	r.lastDirectCommittedBytes = snap.DirectCommittedBytes
	r.lastPeerReceivedBytes = snap.PeerReceivedBytes
}

func (r *Recorder) row(snap Snapshot, deltaBytes int64, deltaMS int64, localSentDelta int64, directPacketDelta int64, directCommittedDelta int64, peerReceivedDelta int64) []string {
	sendGoodput := ""
	if r.role == RoleSend && snap.LocalSentBytes > 0 {
		sendGoodput = formatMbps(localSentDelta, deltaMS)
	}
	receiveGoodput := ""
	if r.role == RoleReceive && snap.DirectPacketBytes > 0 {
		receiveGoodput = formatMbps(directPacketDelta, deltaMS)
	}
	receiverCommittedGoodput := ""
	if r.role == RoleReceive && snap.DirectCommittedBytes > 0 {
		receiverCommittedGoodput = formatMbps(directCommittedDelta, deltaMS)
	} else if r.role == RoleSend && snap.PeerReceivedBytes > 0 {
		receiverCommittedGoodput = formatMbps(peerReceivedDelta, deltaMS)
	}

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
		strconv.FormatInt(snap.LocalSentBytes, 10),
		strconv.FormatInt(snap.PeerReceivedBytes, 10),
		formatOptionalInt64(snap.SetupElapsedMS),
		formatOptionalInt64(snap.TransferElapsedMS),
		strconv.FormatBool(snap.DirectValidated),
		snap.FallbackReason,
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
		formatOptionalInt(snap.RateTargetMbps),
		formatOptionalInt(snap.RateCeilingMbps),
		formatOptionalInt(snap.RateExplorationCeilingMbps),
		formatOptionalInt(snap.DirectRateSelectedMbps),
		formatOptionalInt(snap.DirectLanesActive),
		formatOptionalInt(snap.DirectLanesAvailable),
		formatOptionalInt(snap.LaneMin),
		formatOptionalInt(snap.LaneCap),
		snap.ControllerDecision,
		snap.ControllerReason,
		sendGoodput,
		receiveGoodput,
		receiverCommittedGoodput,
		formatOptionalUint64(snap.ReplayBytes),
		formatOptionalInt64(snap.RetransmitCount),
		formatOptionalInt64(snap.RepairRequests),
		formatOptionalInt64(snap.RepairBytes),
		formatOptionalInt(snap.PeerRecvQueueDepth),
		formatOptionalInt(snap.PeerRecvQueueDepthMax),
		formatOptionalInt64(snap.DirectPacketBytes),
		formatOptionalInt64(snap.DirectCommittedBytes),
	}
}

func nonNegativeDelta(current int64, previous int64) int64 {
	delta := current - previous
	if delta < 0 {
		return 0
	}
	return delta
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

func headerCopy() []string {
	return append([]string(nil), header[:]...)
}

func init() {
	if strings.Join(header[:], ",") != HeaderLine {
		panic("transfertrace: header mismatch")
	}
}
