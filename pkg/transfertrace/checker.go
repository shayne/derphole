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
	Role          Role
	StallWindow   time.Duration
	ExpectedBytes int64
}

type Result struct {
	Rows          int
	FinalAppBytes int64
	FinalPhase    Phase
	MaxFlatline   time.Duration
}

type checkerIndexes struct {
	timestamp     int
	timestampName string
	role          int
	phase         int
	appBytes      int
	lastError     int
}

type checkerRow struct {
	timestamp time.Time
	role      Role
	phase     Phase
	appBytes  int64
	lastError string
}

type checker struct {
	opts           Options
	result         Result
	lastAppBytes   int64
	lastProgressAt time.Time
}

func Check(r io.Reader, opts Options) (Result, error) {
	if opts.StallWindow <= 0 {
		opts.StallWindow = time.Second
	}
	cr := csv.NewReader(r)
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
	for {
		record, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read row: %w", err)
		}
		row, err := parseCheckerRow(record, indexes)
		if err != nil {
			return err
		}
		if err := c.consume(row); err != nil {
			return err
		}
	}
}

func (c *checker) consume(row checkerRow) error {
	if c.opts.Role != "" && row.role != c.opts.Role {
		return nil
	}
	if row.lastError != "" {
		return fmt.Errorf("terminal error: %s", row.lastError)
	}

	c.result.Rows++
	c.result.FinalAppBytes = row.appBytes
	c.result.FinalPhase = row.phase
	if c.result.Rows == 1 || row.appBytes > c.lastAppBytes {
		c.recordProgress(row)
		return nil
	}
	if isActivePhase(row.phase) {
		return c.checkFlatline(row)
	}
	return nil
}

func (c *checker) recordProgress(row checkerRow) {
	c.lastAppBytes = row.appBytes
	c.lastProgressAt = row.timestamp
}

func (c *checker) checkFlatline(row checkerRow) error {
	flatline := row.timestamp.Sub(c.lastProgressAt)
	if flatline > c.result.MaxFlatline {
		c.result.MaxFlatline = flatline
	}
	if flatline > c.opts.StallWindow {
		return fmt.Errorf("app bytes stalled for %s in phase %s", flatline, row.phase)
	}
	return nil
}

func (c *checker) finish() (Result, error) {
	if c.result.Rows == 0 {
		return c.result, c.noRowsError()
	}
	if c.opts.ExpectedBytes > 0 && c.result.FinalAppBytes != c.opts.ExpectedBytes {
		return c.result, fmt.Errorf("final app bytes = %d, want %d", c.result.FinalAppBytes, c.opts.ExpectedBytes)
	}
	if c.result.FinalPhase != PhaseComplete {
		return c.result, fmt.Errorf("final phase = %s, want %s", c.result.FinalPhase, PhaseComplete)
	}
	return c.result, nil
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
	return 0, "", fmt.Errorf("missing required header %q", "timestamp_unix_ms")
}

func parseCheckerRow(record []string, indexes checkerIndexes) (checkerRow, error) {
	timestampMS, err := parseIntField(record, indexes.timestamp, indexes.timestampName)
	if err != nil {
		return checkerRow{}, err
	}
	appBytes, err := parseIntField(record, indexes.appBytes, "app_bytes")
	if err != nil {
		return checkerRow{}, err
	}
	return checkerRow{
		timestamp: time.UnixMilli(timestampMS),
		role:      Role(field(record, indexes.role)),
		phase:     Phase(field(record, indexes.phase)),
		appBytes:  appBytes,
		lastError: field(record, indexes.lastError),
	}, nil
}

func parseIntField(record []string, index int, name string) (int64, error) {
	value := field(record, index)
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s %q: %w", name, value, err)
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
