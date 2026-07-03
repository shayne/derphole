// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestRunHelpListenShowsListenHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "listen"}, {"listen", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), listenHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestListenHelpMentionsRawStreamUsage(t *testing.T) {
	help := listenHelpText()
	for _, want := range []string{
		"direct-path promotion",
		"Listen for one incoming raw byte stream and write it to stdout.",
		"derphole listen",
		"derphole listen --print-token-only",
		"--force-relay",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("listenHelpText() = %q, want %q", help, want)
		}
	}
}

func TestRunListenPassesTransferTraceFromEnvironment(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_TRACE_CSV", filepath.Join(t.TempDir(), "listen.csv"))
	prev := listenSession
	t.Cleanup(func() {
		listenSession = prev
	})

	var got *transfertrace.Recorder
	listenSession = func(_ context.Context, cfg session.ListenConfig) (string, error) {
		got = cfg.Trace
		cfg.TokenSink <- "raw-stream-token"
		return "raw-stream-token", nil
	}

	code := runListen(nil, telemetry.LevelQuiet, io.Discard, io.Discard)
	if code != 0 {
		t.Fatalf("runListen() code = %d, want 0", code)
	}
	if got == nil {
		t.Fatal("Trace was nil")
	}
}

func TestRunListenConfiguresBlockReceiverForRegularFile(t *testing.T) {
	prev := listenSession
	t.Cleanup(func() {
		listenSession = prev
	})

	file, err := os.CreateTemp(t.TempDir(), "listen-output")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer file.Close()

	listenSession = func(ctx context.Context, cfg session.ListenConfig) (string, error) {
		if cfg.BlockReceiver == nil {
			t.Fatal("BlockReceiver was nil")
		}
		sink, err := cfg.BlockReceiver(ctx, session.BlockReceiveRequest{PayloadSize: 5})
		if err != nil {
			t.Fatalf("BlockReceiver() error = %v", err)
		}
		if _, err := sink.WriteAt([]byte("lo"), 3); err != nil {
			t.Fatalf("WriteAt(lo) error = %v", err)
		}
		if _, err := sink.WriteAt([]byte("hel"), 0); err != nil {
			t.Fatalf("WriteAt(hel) error = %v", err)
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("sink.Close() error = %v", err)
		}
		cfg.TokenSink <- "raw-stream-token"
		return "raw-stream-token", nil
	}

	code := runListen(nil, telemetry.LevelQuiet, file, io.Discard)
	if code != 0 {
		t.Fatalf("runListen() code = %d, want 0", code)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("output file = %q, want hello", string(got))
	}
}
