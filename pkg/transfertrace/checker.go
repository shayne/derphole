// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"encoding/csv"
	"fmt"
	"io"
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

type checkerIndexes struct {
	fields        int
	timestamp     int
	timestampName string
	role          int
	phase         int
	appBytes      int
	lastError     int
}

type checkerRow struct {
	rowNo     int
	timestamp time.Time
	phase     Phase
	appBytes  int64
	lastError string
}

type checker struct {
	opts         Options
	result       Result
	lastAppBytes int64
	active       bool
	activeSince  time.Time
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
	if active {
		c.activeSince = row.timestamp
	}
}

func (c *checker) recordInactive(row checkerRow) {
	if row.appBytes > c.lastAppBytes {
		c.lastAppBytes = row.appBytes
	}
	c.active = false
}

func (c *checker) recordActiveProgress(row checkerRow) {
	c.lastAppBytes = row.appBytes
	c.active = true
	c.activeSince = row.timestamp
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
		fields:        len(header),
		timestamp:     timestamp,
		timestampName: timestampName,
		role:          role,
		phase:         phase,
		appBytes:      appBytes,
		lastError:     lastError,
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
	return checkerRow{
		rowNo:     rowNo,
		timestamp: time.UnixMilli(timestampMS),
		phase:     Phase(field(record, indexes.phase)),
		appBytes:  appBytes,
		lastError: field(record, indexes.lastError),
	}, nil
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
