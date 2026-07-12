// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestTerminalFanoutReplaysThenStreamsFutureData(t *testing.T) {
	pr, pw := io.Pipe()
	local := newStringCapture()
	fanout := newTerminalFanout(pr, local)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fanout.Run(ctx) }()

	if _, err := pw.Write([]byte("ready")); err != nil {
		t.Fatalf("write ready: %v", err)
	}
	waitForString(t, ctx, local.String, "ready")

	sub := fanout.Reader()
	defer sub.Close()
	if _, err := pw.Write([]byte("input:hello")); err != nil {
		t.Fatalf("write input: %v", err)
	}

	got := readN(t, sub, len("readyinput:hello"))
	if got != "readyinput:hello" {
		t.Fatalf("subscriber data = %q, want replay plus future data", got)
	}
}

func TestTerminalFanoutBuffersFutureDataBeforeSubscriberReadStarts(t *testing.T) {
	pr, pw := io.Pipe()
	fanout := newTerminalFanout(pr, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fanout.Run(ctx) }()

	if _, err := pw.Write([]byte("ready")); err != nil {
		t.Fatalf("write ready: %v", err)
	}
	sub := fanout.Reader()
	defer sub.Close()
	if _, err := pw.Write([]byte("input:hello")); err != nil {
		t.Fatalf("write input: %v", err)
	}

	got := readN(t, sub, len("readyinput:hello"))
	if got != "readyinput:hello" {
		t.Fatalf("subscriber data = %q, want replay plus buffered future data", got)
	}
}

func TestTerminalFanoutDeliversFinalDataBeforeEOF(t *testing.T) {
	pr, pw := io.Pipe()
	fanout := newTerminalFanout(pr, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fanout.Run(ctx) }()

	sub := fanout.Reader()
	defer sub.Close()
	if _, err := pw.Write([]byte("final")); err != nil {
		t.Fatalf("write final: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}

	got := readN(t, sub, len("final"))
	if got != "final" {
		t.Fatalf("subscriber data = %q, want final data before EOF", got)
	}
}

func TestTerminalFanoutRespondsToPrimaryDeviceAttributeQuery(t *testing.T) {
	pr, pw := io.Pipe()
	input := newCaptureWriter()
	fanout := newTerminalFanout(pr, io.Discard)
	fanout.setTerminalResponseWriter(input)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = fanout.Run(ctx) }()

	if _, err := pw.Write([]byte("\x1b[c")); err != nil {
		t.Fatalf("write query: %v", err)
	}

	waitForCapturedWrite(t, ctx, input, "\x1b[?1;2c")
}

func TestTerminalFanoutRespondsToSplitPrimaryDeviceAttributeQuery(t *testing.T) {
	pr, pw := io.Pipe()
	input := newCaptureWriter()
	fanout := newTerminalFanout(pr, io.Discard)
	fanout.setTerminalResponseWriter(input)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = fanout.Run(ctx) }()

	if _, err := pw.Write([]byte("\x1b")); err != nil {
		t.Fatalf("write query prefix: %v", err)
	}
	if _, err := pw.Write([]byte("[0c")); err != nil {
		t.Fatalf("write query suffix: %v", err)
	}

	waitForCapturedWrite(t, ctx, input, "\x1b[?1;2c")
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, n)
		_, _ = io.ReadFull(r, buf)
		done <- string(buf)
	}()
	select {
	case got := <-done:
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out reading subscriber data")
		return ""
	}
}
