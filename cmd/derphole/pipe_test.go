// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestRunHelpPipeShowsPipeHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "pipe"}, {"pipe", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), pipeHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestPipeHelpMentionsRawStreamAndParallelFlag(t *testing.T) {
	help := pipeHelpText()
	for _, want := range []string{
		"direct-path promotion",
		"Send stdin as a raw byte stream to a derphole listener.",
		"cat file | derphole pipe <token>",
		"printf 'hello' | derphole pipe <token>",
		"-P",
		"--parallel",
		"auto",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("pipeHelpText() = %q, want %q", help, want)
		}
	}
}

func TestRunPipePassesTransferTraceFromEnvironment(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_TRACE_CSV", filepath.Join(t.TempDir(), "pipe.csv"))
	prev := sendSession
	t.Cleanup(func() {
		sendSession = prev
	})

	var got *transfertrace.Recorder
	sendSession = func(_ context.Context, cfg session.SendConfig) error {
		got = cfg.Trace
		return nil
	}

	code := runPipe([]string{"token"}, telemetry.LevelQuiet, strings.NewReader("payload"), io.Discard, io.Discard)
	if code != 0 {
		t.Fatalf("runPipe() code = %d, want 0", code)
	}
	if got == nil {
		t.Fatal("Trace was nil")
	}
}
