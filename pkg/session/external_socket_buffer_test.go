// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
)

type externalSocketBufferTestConn struct {
	readRequested  int
	writeRequested int
	readErr        error
	writeErr       error
}

func (c *externalSocketBufferTestConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *externalSocketBufferTestConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func (c *externalSocketBufferTestConn) Close() error { return nil }

func (c *externalSocketBufferTestConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *externalSocketBufferTestConn) SetDeadline(time.Time) error {
	return nil
}

func (c *externalSocketBufferTestConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *externalSocketBufferTestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *externalSocketBufferTestConn) SetReadBuffer(bytes int) error {
	c.readRequested = bytes
	return c.readErr
}

func (c *externalSocketBufferTestConn) SetWriteBuffer(bytes int) error {
	c.writeRequested = bytes
	return c.writeErr
}

func TestTuneExternalPacketConnRequestsBothBuffers(t *testing.T) {
	t.Parallel()

	conn := &externalSocketBufferTestConn{
		readErr:  errors.New("read denied"),
		writeErr: errors.New("write denied"),
	}
	stats := tuneExternalPacketConn(conn)
	if conn.readRequested != externalPacketConnSocketBufferBytes ||
		conn.writeRequested != externalPacketConnSocketBufferBytes {
		t.Fatalf("requested read=%d write=%d, want %d",
			conn.readRequested,
			conn.writeRequested,
			externalPacketConnSocketBufferBytes,
		)
	}
	if stats.RequestedBytes != externalPacketConnSocketBufferBytes ||
		stats.ReadSetError == nil ||
		stats.WriteSetError == nil {
		t.Fatalf("stats = %#v, want requested size and setter errors", stats)
	}
}

func TestTuneExternalPacketConnReceiveOnlyUsesBulkDataWindow(t *testing.T) {
	conn := &externalSocketBufferTestConn{}
	stats := tuneExternalPacketConnReceive(conn, externalV2BulkPacketReceiveSocketBufferBytes)
	if conn.readRequested != externalV2BulkPacketReceiveSocketBufferBytes || conn.writeRequested != 0 {
		t.Fatalf("requested read=%d write=%d, want receive-only %d", conn.readRequested, conn.writeRequested, externalV2BulkPacketReceiveSocketBufferBytes)
	}
	if stats.RequestedBytes != externalV2BulkPacketReceiveSocketBufferBytes {
		t.Fatalf("stats requested bytes = %d", stats.RequestedBytes)
	}
}

func TestOpenExternalV2DataPacketPathReportsSocketBuffersPerLane(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")

	var output bytes.Buffer
	emitter := telemetry.New(&output, telemetry.LevelVerbose)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path, err := openExternalV2DataPacketPath(ctx, nil, emitter, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer path.Close()

	var socketBufferLines []string
	for line := range strings.SplitSeq(strings.TrimSpace(output.String()), "\n") {
		if strings.HasPrefix(line, "v2-raw-direct-socket-buffer=") {
			socketBufferLines = append(socketBufferLines, line)
		}
	}
	if len(socketBufferLines) != 2 {
		t.Fatalf("socket-buffer lines = %q, want one per lane", socketBufferLines)
	}
	for wantLane, line := range socketBufferLines {
		var lane, requested, readBytes, writeBytes int
		var readSetError, writeSetError, inspectError bool
		if _, err := fmt.Sscanf(
			line,
			"v2-raw-direct-socket-buffer=lane:%d requested:%d read:%d write:%d read_set_error:%t write_set_error:%t inspect_error:%t",
			&lane,
			&requested,
			&readBytes,
			&writeBytes,
			&readSetError,
			&writeSetError,
			&inspectError,
		); err != nil {
			t.Fatalf("parse socket-buffer line %q: %v", line, err)
		}
		if lane != wantLane || requested != externalPacketConnSocketBufferBytes {
			t.Fatalf("socket-buffer line = %q, want lane=%d requested=%d",
				line,
				wantLane,
				externalPacketConnSocketBufferBytes,
			)
		}
		if inspectError {
			if readBytes != 0 || writeBytes != 0 {
				t.Fatalf("socket-buffer line = %q, want zero effective sizes after inspection error", line)
			}
		} else if readBytes <= 0 || writeBytes <= 0 {
			t.Fatalf("socket-buffer line = %q, want positive effective sizes after successful inspection", line)
		}
	}
}
