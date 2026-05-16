// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"encoding/csv"
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
	fields            int
	timestamp         int
	timestampName     string
	role              int
	phase             int
	appBytes          int
	peerReceivedBytes int
	transferElapsedMS int
	directValidated   int
	fallbackReason    int
	lastState         int
	lastError         int
}

type checkerRow struct {
	rowNo             int
	timestamp         time.Time
	phase             Phase
	appBytes          int64
	peerReceivedBytes int64
	transferElapsedMS int64
	directValidated   bool
	fallbackReason    string
	lastState         string
	lastError         string
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
		ReceiverRateMbps:     mbps(receiverFinal.appBytes, receiverFinal.transferElapsedMS),
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
	for _, sender := range senderRows {
		senderElapsed := comparableElapsed(sender)
		for receiverIndex < len(receiverRows) && comparableElapsed(receiverRows[receiverIndex]) <= senderElapsed {
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

func comparableElapsed(row checkerRow) int64 {
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
		fields:            len(header),
		timestamp:         timestamp,
		timestampName:     timestampName,
		role:              role,
		phase:             phase,
		appBytes:          appBytes,
		peerReceivedBytes: optional("peer_received_bytes"),
		transferElapsedMS: optional("transfer_elapsed_ms"),
		directValidated:   optional("direct_validated"),
		fallbackReason:    optional("fallback_reason"),
		lastState:         optional("last_state"),
		lastError:         lastError,
	}, nil
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
	if len(record) != indexes.fields {
		return checkerRow{}, fmt.Errorf("row %d: wrong number of fields: got %d, want %d", rowNo, len(record), indexes.fields)
	}
	if err := requireField(record, indexes.timestamp, indexes.timestampName, rowNo); err != nil {
		return checkerRow{}, err
	}
	if err := requireField(record, indexes.phase, "phase", rowNo); err != nil {
		return checkerRow{}, err
	}
	if err := requireField(record, indexes.appBytes, "app_bytes", rowNo); err != nil {
		return checkerRow{}, err
	}
	timestampMS, err := parseIntField(record, indexes.timestamp, indexes.timestampName, rowNo)
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
	return checkerRow{
		rowNo:             rowNo,
		timestamp:         time.UnixMilli(timestampMS),
		phase:             Phase(field(record, indexes.phase)),
		appBytes:          appBytes,
		peerReceivedBytes: peerReceivedBytes,
		transferElapsedMS: transferElapsedMS,
		directValidated:   directValidated,
		fallbackReason:    field(record, indexes.fallbackReason),
		lastState:         field(record, indexes.lastState),
		lastError:         field(record, indexes.lastError),
	}, nil
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
