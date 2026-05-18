// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
)

type Options struct {
	Role             Role
	StallWindow      time.Duration
	ExpectedBytes    int64
	ExpectedBytesSet bool
}

type Result struct {
	Rows          int
	FinalAppBytes int64
	FinalPhase    Phase
	MaxFlatline   time.Duration
	Diagnostics   DiagnosticsSummary
}

type DiagnosticsSummary struct {
	MaxRateTargetMbps             int
	MaxReplayBytes                uint64
	MaxRetransmits                int64
	MaxPeerRecvQueueDepth         int
	DirectTransport               string
	ReceiverCommittedMbpsMin      float64
	ReceiverCommittedMbpsMax      float64
	ReceiverCommittedMbpsObserved bool
}

type PairOptions struct {
	Role                       Role
	PeerRole                   Role
	RateTolerance              float64
	ProgressLeadToleranceBytes int64
}

type PairResult struct {
	PrimaryRows          int
	PeerRows             int
	ProgressDeltaBytes   int64
	MaxProgressLeadBytes int64
	SenderRateMbps       float64
	ReceiverRateMbps     float64
}

type checkerIndexes struct {
	fields             int
	header             []string
	timestamp          int
	timestampName      string
	role               int
	phase              int
	elapsedMS          int
	appBytes           int
	peerReceivedBytes  int
	transferElapsedMS  int
	directValidated    int
	fallbackReason     int
	lastState          int
	lastError          int
	directTransport    int
	numericDiagnostics []checkerNumericDiagnostic
}

type checkerRow struct {
	rowNo             int
	timestamp         time.Time
	elapsedMS         int64
	phase             Phase
	appBytes          int64
	peerReceivedBytes int64
	transferElapsedMS int64
	directValidated   bool
	fallbackReason    string
	lastState         string
	lastError         string
	diagnostics       checkerRowDiagnostics
}

type checkerRowDiagnostics struct {
	rateTargetMbps                int
	receiverCommittedMbps         float64
	receiverCommittedMbpsObserved bool
	replayBytes                   uint64
	retransmits                   int64
	peerRecvQueueDepth            int
	peerRecvQueueDepthMax         int
	directTransport               string
}

type checkerNumericDiagnosticKind int

const (
	checkerNumericDiagnosticInt checkerNumericDiagnosticKind = iota
	checkerNumericDiagnosticInt64
	checkerNumericDiagnosticUint64
	checkerNumericDiagnosticFloat
)

type checkerNumericDiagnosticColumn struct {
	name string
	kind checkerNumericDiagnosticKind
}

type checkerNumericDiagnostic struct {
	name  string
	index int
	kind  checkerNumericDiagnosticKind
}

type checkerNumericDiagnosticValue struct {
	intValue    int
	int64Value  int64
	uint64Value uint64
	floatValue  float64
}

var checkerNumericDiagnosticColumns = []checkerNumericDiagnosticColumn{
	{name: "rate_target_mbps", kind: checkerNumericDiagnosticInt},
	{name: "rate_ceiling_mbps", kind: checkerNumericDiagnosticInt},
	{name: "rate_exploration_ceiling_mbps", kind: checkerNumericDiagnosticInt},
	{name: "rate_selected_mbps", kind: checkerNumericDiagnosticInt},
	{name: "active_lanes", kind: checkerNumericDiagnosticInt},
	{name: "available_lanes", kind: checkerNumericDiagnosticInt},
	{name: "lane_min", kind: checkerNumericDiagnosticInt},
	{name: "lane_cap", kind: checkerNumericDiagnosticInt},
	{name: "send_goodput_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "receive_goodput_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "receiver_committed_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "replay_bytes", kind: checkerNumericDiagnosticUint64},
	{name: "retransmits", kind: checkerNumericDiagnosticInt64},
	{name: "repair_requests", kind: checkerNumericDiagnosticInt64},
	{name: "repair_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "peer_recv_queue_depth", kind: checkerNumericDiagnosticInt},
	{name: "peer_recv_queue_depth_max", kind: checkerNumericDiagnosticInt},
	{name: "direct_packet_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "direct_committed_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "quic_handshake_ms", kind: checkerNumericDiagnosticInt64},
	{name: "quic_first_byte_ms", kind: checkerNumericDiagnosticInt64},
	{name: "quic_stream_bytes_sent", kind: checkerNumericDiagnosticInt64},
	{name: "quic_stream_bytes_received", kind: checkerNumericDiagnosticInt64},
	{name: "quic_stream_goodput_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "quic_loss_events", kind: checkerNumericDiagnosticInt64},
}

type checker struct {
	opts         Options
	result       Result
	lastAppBytes int64
	active       bool
	activeSince  time.Time
	lastPhase    Phase
}

func Check(r io.Reader, opts Options) (Result, error) {
	if opts.StallWindow <= 0 {
		opts.StallWindow = time.Second
	}
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return Result{}, fmt.Errorf("read header: %w", err)
	}
	indexes, err := checkerHeaderIndexes(header)
	if err != nil {
		return Result{}, err
	}

	c := checker{opts: opts}
	if err := c.scanRows(cr, indexes); err != nil {
		return c.result, err
	}
	return c.finish()
}

func CheckPair(primary io.Reader, peer io.Reader, opts PairOptions) (PairResult, error) {
	if opts.Role != RoleSend && opts.Role != RoleReceive {
		return PairResult{}, fmt.Errorf("primary role must be send or receive")
	}
	if opts.PeerRole == "" {
		opts.PeerRole = oppositeRole(opts.Role)
	}
	primaryRows, err := readCheckerRows(primary, opts.Role)
	if err != nil {
		return PairResult{}, fmt.Errorf("read primary trace: %w", err)
	}
	peerRows, err := readCheckerRows(peer, opts.PeerRole)
	if err != nil {
		return PairResult{}, fmt.Errorf("read peer trace: %w", err)
	}
	if len(primaryRows) == 0 {
		return PairResult{}, fmt.Errorf("no rows matched primary role %q", opts.Role)
	}
	if len(peerRows) == 0 {
		return PairResult{}, fmt.Errorf("no rows matched peer role %q", opts.PeerRole)
	}
	return compareCheckerPair(primaryRows, peerRows, opts)
}

func (c *checker) scanRows(cr *csv.Reader, indexes checkerIndexes) error {
	rowNo := 1
	for {
		record, err := cr.Read()
		rowNo++
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("row %d: read row: %w", rowNo, err)
		}
		role := Role(field(record, indexes.role))
		if c.opts.Role != "" && role != c.opts.Role {
			continue
		}
		row, err := parseCheckerRow(record, indexes, rowNo)
		if err != nil {
			return err
		}
		if err := c.consume(row); err != nil {
			return err
		}
	}
}

func (c *checker) consume(row checkerRow) error {
	c.result.Rows++
	c.result.FinalAppBytes = row.appBytes
	c.result.FinalPhase = row.phase
	c.recordDiagnostics(row)
	if row.lastError != "" {
		return fmt.Errorf("row %d: terminal error: %s", row.rowNo, row.lastError)
	}
	if err := validateCheckerRowStatus(row); err != nil {
		return err
	}

	active := isActivePhase(row.phase)
	if c.result.Rows == 1 {
		c.recordFirstRow(row, active)
		return nil
	}
	if !active {
		c.recordInactive(row)
		return nil
	}
	if !c.active || row.appBytes > c.lastAppBytes {
		c.recordActiveProgress(row)
		return nil
	}
	if row.phase != c.lastPhase {
		c.recordActivePhaseChange(row)
		return nil
	}
	return c.checkFlatline(row)
}

func (c *checker) recordDiagnostics(row checkerRow) {
	diagnostics := &c.result.Diagnostics
	rowDiagnostics := row.diagnostics
	diagnostics.MaxRateTargetMbps = maxInt(diagnostics.MaxRateTargetMbps, rowDiagnostics.rateTargetMbps)
	diagnostics.MaxReplayBytes = maxUint64(diagnostics.MaxReplayBytes, rowDiagnostics.replayBytes)
	diagnostics.MaxRetransmits = maxInt64(diagnostics.MaxRetransmits, rowDiagnostics.retransmits)
	diagnostics.MaxPeerRecvQueueDepth = maxInt(diagnostics.MaxPeerRecvQueueDepth, maxInt(rowDiagnostics.peerRecvQueueDepth, rowDiagnostics.peerRecvQueueDepthMax))
	if rowDiagnostics.directTransport != "" {
		diagnostics.DirectTransport = rowDiagnostics.directTransport
	}
	recordReceiverCommittedMbps(diagnostics, rowDiagnostics)
}

func recordReceiverCommittedMbps(diagnostics *DiagnosticsSummary, row checkerRowDiagnostics) {
	if !row.receiverCommittedMbpsObserved {
		return
	}
	if !diagnostics.ReceiverCommittedMbpsObserved || row.receiverCommittedMbps < diagnostics.ReceiverCommittedMbpsMin {
		diagnostics.ReceiverCommittedMbpsMin = row.receiverCommittedMbps
	}
	if !diagnostics.ReceiverCommittedMbpsObserved || row.receiverCommittedMbps > diagnostics.ReceiverCommittedMbpsMax {
		diagnostics.ReceiverCommittedMbpsMax = row.receiverCommittedMbps
	}
	diagnostics.ReceiverCommittedMbpsObserved = true
}

func maxInt(a int, b int) int {
	if b > a {
		return b
	}
	return a
}

func maxInt64(a int64, b int64) int64 {
	if b > a {
		return b
	}
	return a
}

func maxUint64(a uint64, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func (c *checker) checkFlatline(row checkerRow) error {
	flatline := row.timestamp.Sub(c.activeSince)
	if flatline > c.result.MaxFlatline {
		c.result.MaxFlatline = flatline
	}
	if flatline > c.opts.StallWindow {
		return fmt.Errorf("row %d: app bytes stalled for %s in phase %s", row.rowNo, flatline, row.phase)
	}
	return nil
}

func (c *checker) recordFirstRow(row checkerRow, active bool) {
	c.lastAppBytes = row.appBytes
	c.active = active
	c.lastPhase = row.phase
	if active {
		c.activeSince = row.timestamp
	}
}

func (c *checker) recordInactive(row checkerRow) {
	if row.appBytes > c.lastAppBytes {
		c.lastAppBytes = row.appBytes
	}
	c.active = false
	c.lastPhase = row.phase
}

func (c *checker) recordActiveProgress(row checkerRow) {
	c.lastAppBytes = row.appBytes
	c.active = true
	c.activeSince = row.timestamp
	c.lastPhase = row.phase
}

func (c *checker) recordActivePhaseChange(row checkerRow) {
	c.active = true
	c.activeSince = row.timestamp
	c.lastPhase = row.phase
}

func (c *checker) finish() (Result, error) {
	if c.result.Rows == 0 {
		return c.result, c.noRowsError()
	}
	if c.expectedBytesSet() && c.result.FinalAppBytes != c.opts.ExpectedBytes {
		return c.result, fmt.Errorf("final app bytes = %d, want %d", c.result.FinalAppBytes, c.opts.ExpectedBytes)
	}
	if c.result.FinalPhase != PhaseComplete {
		return c.result, fmt.Errorf("final phase = %s, want %s", c.result.FinalPhase, PhaseComplete)
	}
	return c.result, nil
}

func readCheckerRows(r io.Reader, role Role) ([]checkerRow, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	indexes, err := checkerHeaderIndexes(header)
	if err != nil {
		return nil, err
	}
	if indexes.peerReceivedBytes < 0 {
		return nil, fmt.Errorf("missing required header %q for peer trace check", "peer_received_bytes")
	}
	rowNo := 1
	var rows []checkerRow
	for {
		record, err := cr.Read()
		rowNo++
		if err == io.EOF {
			return rows, nil
		}
		if err != nil {
			return nil, fmt.Errorf("row %d: read row: %w", rowNo, err)
		}
		if Role(field(record, indexes.role)) != role {
			continue
		}
		row, err := parseCheckerRow(record, indexes, rowNo)
		if err != nil {
			return nil, err
		}
		if err := validateReadCheckerRow(row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
}

func validateReadCheckerRow(row checkerRow) error {
	if row.lastError != "" {
		return fmt.Errorf("row %d: terminal error: %s", row.rowNo, row.lastError)
	}
	return validateCheckerRowStatus(row)
}

func compareCheckerPair(primaryRows []checkerRow, peerRows []checkerRow, opts PairOptions) (PairResult, error) {
	senderRows, receiverRows := senderReceiverRows(primaryRows, peerRows, opts.Role)
	senderFinal := senderRows[len(senderRows)-1]
	receiverFinal := receiverRows[len(receiverRows)-1]
	if senderFinal.phase != PhaseComplete {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, fmt.Errorf("sender final phase = %s, want %s", senderFinal.phase, PhaseComplete)
	}
	if receiverFinal.phase != PhaseComplete {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, fmt.Errorf("receiver final phase = %s, want %s", receiverFinal.phase, PhaseComplete)
	}
	delta := absInt64(senderFinal.peerReceivedBytes - receiverFinal.appBytes)
	maxLead := maxSenderProgressLead(senderRows, receiverRows)
	result := PairResult{
		PrimaryRows:          len(primaryRows),
		PeerRows:             len(peerRows),
		ProgressDeltaBytes:   delta,
		MaxProgressLeadBytes: maxLead,
		SenderRateMbps:       mbps(senderFinal.peerReceivedBytes, senderFinal.transferElapsedMS),
		ReceiverRateMbps:     mbps(receiverFinal.appBytes, receiverTransferElapsedMS(receiverRows)),
	}
	if delta != 0 {
		return result, fmt.Errorf("sender peer_received_bytes = %d, receiver app_bytes = %d", senderFinal.peerReceivedBytes, receiverFinal.appBytes)
	}
	if maxLead > opts.ProgressLeadToleranceBytes {
		return result, fmt.Errorf("sender progress leads receiver by %d bytes, tolerance=%d", maxLead, opts.ProgressLeadToleranceBytes)
	}
	if rateDiverged(result.SenderRateMbps, result.ReceiverRateMbps, opts.RateTolerance) {
		return result, fmt.Errorf("transfer rate diverged: sender_peer_mbps=%.2f receiver_mbps=%.2f tolerance=%.2f", result.SenderRateMbps, result.ReceiverRateMbps, normalizedRateTolerance(opts.RateTolerance))
	}
	return result, nil
}

func senderReceiverRows(primaryRows []checkerRow, peerRows []checkerRow, role Role) ([]checkerRow, []checkerRow) {
	if role == RoleSend {
		return primaryRows, peerRows
	}
	return peerRows, primaryRows
}

func maxSenderProgressLead(senderRows []checkerRow, receiverRows []checkerRow) int64 {
	var maxLead int64
	receiverIndex := 0
	var receiverBytes int64
	useTransferElapsed := useTransferElapsedForProgressLead(senderRows, receiverRows)
	receiverBaseElapsed := firstReceiverAppElapsedMS(receiverRows)
	for _, sender := range senderRows {
		if sender.phase == PhaseComplete {
			continue
		}
		senderElapsed := comparableElapsed(sender, useTransferElapsed, 0)
		for receiverIndex < len(receiverRows) && comparableElapsed(receiverRows[receiverIndex], useTransferElapsed, receiverBaseElapsed) <= senderElapsed {
			if receiverRows[receiverIndex].appBytes > receiverBytes {
				receiverBytes = receiverRows[receiverIndex].appBytes
			}
			receiverIndex++
		}
		lead := sender.peerReceivedBytes - receiverBytes
		if lead > maxLead {
			maxLead = lead
		}
	}
	return maxLead
}

func useTransferElapsedForProgressLead(senderRows []checkerRow, receiverRows []checkerRow) bool {
	senderHasTransferElapsed := false
	for _, row := range senderRows {
		if row.peerReceivedBytes > 0 && row.transferElapsedMS > 0 {
			senderHasTransferElapsed = true
			break
		}
	}
	if !senderHasTransferElapsed {
		return false
	}
	for _, row := range receiverRows {
		if row.appBytes > 0 && (row.transferElapsedMS > 0 || row.elapsedMS > 0) {
			return true
		}
	}
	return false
}

func firstReceiverAppElapsedMS(rows []checkerRow) int64 {
	for _, row := range rows {
		if row.appBytes > 0 && row.elapsedMS > 0 {
			return row.elapsedMS
		}
	}
	return 0
}

func receiverTransferElapsedMS(rows []checkerRow) int64 {
	if len(rows) == 0 {
		return 0
	}
	final := rows[len(rows)-1]
	if final.transferElapsedMS > 0 {
		return final.transferElapsedMS
	}
	base := firstReceiverAppElapsedMS(rows)
	if base > 0 && final.elapsedMS > base {
		return final.elapsedMS - base
	}
	return 0
}

func comparableElapsed(row checkerRow, useTransferElapsed bool, receiverBaseElapsed int64) int64 {
	if useTransferElapsed {
		if row.transferElapsedMS > 0 {
			return row.transferElapsedMS
		}
		if receiverBaseElapsed > 0 && row.elapsedMS > 0 {
			return row.elapsedMS - receiverBaseElapsed
		}
	}
	return row.timestamp.UnixMilli()
}

func oppositeRole(role Role) Role {
	if role == RoleSend {
		return RoleReceive
	}
	return RoleSend
}

func mbps(bytes int64, elapsedMS int64) float64 {
	if bytes <= 0 || elapsedMS <= 0 {
		return 0
	}
	return float64(bytes*8) / float64(elapsedMS*1000)
}

func rateDiverged(a float64, b float64, tolerance float64) bool {
	if a == 0 || b == 0 {
		return false
	}
	maxRate := math.Max(a, b)
	if maxRate == 0 {
		return false
	}
	return math.Abs(a-b)/maxRate > normalizedRateTolerance(tolerance)
}

func normalizedRateTolerance(tolerance float64) float64 {
	if tolerance <= 0 {
		return 0.10
	}
	return tolerance
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func (c *checker) expectedBytesSet() bool {
	return c.opts.ExpectedBytesSet || c.opts.ExpectedBytes > 0
}

func (c *checker) noRowsError() error {
	if c.opts.Role != "" {
		return fmt.Errorf("no rows matched role %q", c.opts.Role)
	}
	return fmt.Errorf("no rows")
}

func checkerHeaderIndexes(header []string) (checkerIndexes, error) {
	positions := map[string]int{}
	for i, name := range header {
		positions[name] = i
	}
	lookup := func(name string) (int, error) {
		i, ok := positions[name]
		if !ok {
			return 0, fmt.Errorf("missing required header %q", name)
		}
		return i, nil
	}
	optional := func(name string) int {
		if i, ok := positions[name]; ok {
			return i
		}
		return -1
	}

	timestamp, timestampName, err := lookupTimestamp(positions)
	if err != nil {
		return checkerIndexes{}, err
	}
	role, err := lookup("role")
	if err != nil {
		return checkerIndexes{}, err
	}
	phase, err := lookup("phase")
	if err != nil {
		return checkerIndexes{}, err
	}
	appBytes, err := lookup("app_bytes")
	if err != nil {
		return checkerIndexes{}, err
	}
	lastError, err := lookup("last_error")
	if err != nil {
		return checkerIndexes{}, err
	}
	return checkerIndexes{
		fields:             len(header),
		header:             append([]string(nil), header...),
		timestamp:          timestamp,
		timestampName:      timestampName,
		role:               role,
		phase:              phase,
		elapsedMS:          optional("elapsed_ms"),
		appBytes:           appBytes,
		peerReceivedBytes:  optional("peer_received_bytes"),
		transferElapsedMS:  optional("transfer_elapsed_ms"),
		directValidated:    optional("direct_validated"),
		fallbackReason:     optional("fallback_reason"),
		lastState:          optional("last_state"),
		lastError:          lastError,
		directTransport:    optional("direct_transport"),
		numericDiagnostics: checkerNumericDiagnostics(positions),
	}, nil
}

func checkerNumericDiagnostics(positions map[string]int) []checkerNumericDiagnostic {
	diagnostics := make([]checkerNumericDiagnostic, 0, len(checkerNumericDiagnosticColumns))
	for _, column := range checkerNumericDiagnosticColumns {
		index, ok := positions[column.name]
		if !ok {
			continue
		}
		diagnostics = append(diagnostics, checkerNumericDiagnostic{
			name:  column.name,
			index: index,
			kind:  column.kind,
		})
	}
	return diagnostics
}

func lookupTimestamp(positions map[string]int) (int, string, error) {
	if i, ok := positions["timestamp_unix_ms"]; ok {
		return i, "timestamp_unix_ms", nil
	}
	if i, ok := positions["timestamp_ms"]; ok {
		return i, "timestamp_ms", nil
	}
	return 0, "", fmt.Errorf("missing required timestamp header %q or %q", "timestamp_unix_ms", "timestamp_ms")
}

func parseCheckerRow(record []string, indexes checkerIndexes, rowNo int) (checkerRow, error) {
	var err error
	record, err = normalizeCheckerRecord(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	if err := requireCheckerRowFields(record, indexes, rowNo); err != nil {
		return checkerRow{}, err
	}
	timestampMS, err := parseIntField(record, indexes.timestamp, indexes.timestampName, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	elapsedMS, err := parseOptionalIntField(record, indexes.elapsedMS, "elapsed_ms", rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	appBytes, err := parseIntField(record, indexes.appBytes, "app_bytes", rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	peerReceivedBytes, err := parseOptionalIntField(record, indexes.peerReceivedBytes, "peer_received_bytes", rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	transferElapsedMS, err := parseOptionalIntField(record, indexes.transferElapsedMS, "transfer_elapsed_ms", rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	directValidated, err := parseOptionalBoolField(record, indexes.directValidated, "direct_validated", rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	diagnostics, err := parseCheckerRowDiagnostics(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	return checkerRow{
		rowNo:             rowNo,
		timestamp:         time.UnixMilli(timestampMS),
		elapsedMS:         elapsedMS,
		phase:             Phase(field(record, indexes.phase)),
		appBytes:          appBytes,
		peerReceivedBytes: peerReceivedBytes,
		transferElapsedMS: transferElapsedMS,
		directValidated:   directValidated,
		fallbackReason:    field(record, indexes.fallbackReason),
		lastState:         field(record, indexes.lastState),
		lastError:         field(record, indexes.lastError),
		diagnostics:       diagnostics,
	}, nil
}

func parseCheckerRowDiagnostics(record []string, indexes checkerIndexes, rowNo int) (checkerRowDiagnostics, error) {
	var diagnostics checkerRowDiagnostics
	for _, column := range indexes.numericDiagnostics {
		value, observed, err := parseCheckerNumericDiagnostic(record, column, rowNo)
		if err != nil {
			return checkerRowDiagnostics{}, err
		}
		if observed {
			diagnostics.record(column.name, value)
		}
	}
	diagnostics.directTransport = field(record, indexes.directTransport)
	return diagnostics, nil
}

func (d *checkerRowDiagnostics) record(name string, value checkerNumericDiagnosticValue) {
	switch name {
	case "rate_target_mbps":
		d.rateTargetMbps = value.intValue
	case "receiver_committed_mbps":
		d.receiverCommittedMbps = value.floatValue
		d.receiverCommittedMbpsObserved = true
	case "replay_bytes":
		d.replayBytes = value.uint64Value
	case "retransmits":
		d.retransmits = value.int64Value
	case "peer_recv_queue_depth":
		d.peerRecvQueueDepth = value.intValue
	case "peer_recv_queue_depth_max":
		d.peerRecvQueueDepthMax = value.intValue
	}
}

func normalizeCheckerRecord(record []string, indexes checkerIndexes, rowNo int) ([]string, error) {
	if len(record) == indexes.fields {
		return record, nil
	}
	if len(record) > indexes.fields || !missingOnlyTrailingOptionalDiagnostics(indexes.header, len(record)) {
		return nil, fmt.Errorf("row %d: wrong number of fields: got %d, want %d", rowNo, len(record), indexes.fields)
	}
	padded := make([]string, indexes.fields)
	copy(padded, record)
	return padded, nil
}

func missingOnlyTrailingOptionalDiagnostics(header []string, missingStart int) bool {
	if missingStart >= len(header) {
		return false
	}
	for _, name := range header[missingStart:] {
		if !isOptionalTrailingDiagnosticColumn(name) {
			return false
		}
	}
	return true
}

func isOptionalTrailingDiagnosticColumn(name string) bool {
	switch name {
	case "rate_target_mbps",
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
		"direct_transport",
		"quic_handshake_ms",
		"quic_first_byte_ms",
		"quic_stream_bytes_sent",
		"quic_stream_bytes_received",
		"quic_stream_goodput_mbps",
		"quic_smoothed_rtt_ms",
		"quic_loss_events",
		"quic_close_reason":
		return true
	default:
		return false
	}
}

func requireCheckerRowFields(record []string, indexes checkerIndexes, rowNo int) error {
	required := []struct {
		index int
		name  string
	}{
		{indexes.timestamp, indexes.timestampName},
		{indexes.phase, "phase"},
		{indexes.appBytes, "app_bytes"},
	}
	for _, field := range required {
		if err := requireField(record, field.index, field.name, rowNo); err != nil {
			return err
		}
	}
	return nil
}

func validateCheckerRowStatus(row checkerRow) error {
	if row.lastState == "connected-direct" && !row.directValidated {
		return fmt.Errorf("row %d: connected-direct without direct validation", row.rowNo)
	}
	if row.lastState == "direct-fallback-relay" && row.fallbackReason == "" {
		return fmt.Errorf("row %d: direct-fallback-relay missing fallback reason", row.rowNo)
	}
	return nil
}

func requireField(record []string, index int, name string, rowNo int) error {
	if index < 0 || index >= len(record) {
		return fmt.Errorf("row %d: missing required field %q", rowNo, name)
	}
	return nil
}

func parseIntField(record []string, index int, name string, rowNo int) (int64, error) {
	value := field(record, index)
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
	}
	return n, nil
}

func parseOptionalIntField(record []string, index int, name string, rowNo int) (int64, error) {
	if index < 0 {
		return 0, nil
	}
	value := field(record, index)
	if value == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
	}
	return n, nil
}

func parseOptionalBoolField(record []string, index int, name string, rowNo int) (bool, error) {
	if index < 0 {
		return false, nil
	}
	value := field(record, index)
	if value == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
	}
	return b, nil
}

func parseCheckerNumericDiagnostic(record []string, column checkerNumericDiagnostic, rowNo int) (checkerNumericDiagnosticValue, bool, error) {
	value := field(record, column.index)
	if value == "" {
		return checkerNumericDiagnosticValue{}, false, nil
	}
	switch column.kind {
	case checkerNumericDiagnosticInt:
		n, err := strconv.Atoi(value)
		return checkerNumericDiagnosticValue{intValue: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticInt64:
		n, err := strconv.ParseInt(value, 10, 64)
		return checkerNumericDiagnosticValue{int64Value: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticUint64:
		n, err := strconv.ParseUint(value, 10, 64)
		return checkerNumericDiagnosticValue{uint64Value: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticFloat:
		n, err := parseCheckerDiagnosticFloat(value)
		return checkerNumericDiagnosticValue{floatValue: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	default:
		return checkerNumericDiagnosticValue{}, false, fmt.Errorf("row %d: unsupported numeric diagnostic %s", rowNo, column.name)
	}
}

func parseCheckerDiagnosticFloat(value string) (float64, error) {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, errors.New("non-finite value")
	}
	return n, nil
}

func formatCheckerNumericDiagnosticError(err error, rowNo int, name string, value string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
}

func field(record []string, index int) string {
	if index < 0 || index >= len(record) {
		return ""
	}
	return record[index]
}

func isActivePhase(phase Phase) bool {
	switch phase {
	case PhaseRelay, PhaseDirectPrepare, PhaseDirectProbe, PhaseDirectExecute, PhaseOverlap:
		return true
	default:
		return false
	}
}
