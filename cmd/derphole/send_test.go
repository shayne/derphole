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
	"time"

	pkgderphole "github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestRunHelpSendShowsSendHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "send"}, {"send", "--help"}, {"tx", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), sendHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
		})
	}
}

func TestSendHelpIncludesHideProgress(t *testing.T) {
	if !strings.Contains(sendHelpText(), "--hide-progress") {
		t.Fatalf("sendHelpText() missing --hide-progress:\n%s", sendHelpText())
	}
}

func TestSendHelpIncludesQR(t *testing.T) {
	if !strings.Contains(sendHelpText(), "--qr") {
		t.Fatalf("sendHelpText() missing --qr:\n%s", sendHelpText())
	}
}

func TestRunSendPassesQRFlag(t *testing.T) {
	prev := runSendTransfer
	t.Cleanup(func() {
		runSendTransfer = prev
	})

	called := false
	runSendTransfer = func(_ context.Context, cfg pkgderphole.SendConfig) error {
		called = true
		if !cfg.QR {
			t.Fatal("cfg.QR = false, want true")
		}
		if cfg.What != "photo.jpg" {
			t.Fatalf("cfg.What = %q, want photo.jpg", cfg.What)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--qr", "photo.jpg"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runSendTransfer was not called")
	}
}

func TestRunSendPassesTransferTraceFromEnvironment(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_TRACE_CSV", filepath.Join(t.TempDir(), "send.csv"))
	prev := runSendTransfer
	defer func() { runSendTransfer = prev }()
	var got *transfertrace.Recorder
	runSendTransfer = func(_ context.Context, cfg pkgderphole.SendConfig) error {
		got = cfg.Trace
		return nil
	}
	if code := runSend([]string{"hello", "--hide-progress"}, telemetry.LevelQuiet, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
		t.Fatalf("runSend() code = %d, want 0", code)
	}
	if got == nil {
		t.Fatal("Trace was nil")
	}
}

func TestRunSendTransferTraceSamplesAtInterval(t *testing.T) {
	tracePath := filepath.Join(t.TempDir(), "send.csv")
	t.Setenv("DERPHOLE_TRANSFER_TRACE_CSV", tracePath)
	prevRun := runSendTransfer
	prevInterval := transferTraceSampleInterval
	t.Cleanup(func() {
		runSendTransfer = prevRun
		transferTraceSampleInterval = prevInterval
	})
	transferTraceSampleInterval = 10 * time.Millisecond
	runSendTransfer = func(_ context.Context, cfg pkgderphole.SendConfig) error {
		cfg.Trace.Update(func(snap *transfertrace.Snapshot) {
			snap.Phase = transfertrace.PhaseRelay
			snap.LocalSentBytes = 4096
			snap.LastState = "connected-relay"
		})
		time.Sleep(30 * time.Millisecond)
		return nil
	}

	if code := runSend([]string{"hello", "--hide-progress"}, telemetry.LevelQuiet, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
		t.Fatalf("runSend() code = %d, want 0", code)
	}
	body, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), ",send,relay,") ||
		!strings.Contains(string(body), ",4096,") {
		t.Fatalf("sampled transfer trace missing current snapshot:\n%s", body)
	}
}

func TestRunSendInvokesTransfer(t *testing.T) {
	prev := runSendTransfer
	t.Cleanup(func() {
		runSendTransfer = prev
	})

	called := false
	runSendTransfer = func(_ context.Context, cfg pkgderphole.SendConfig) error {
		called = true
		if cfg.What != "hello" {
			t.Fatalf("cfg.What = %q, want %q", cfg.What, "hello")
		}
		if !cfg.UsePublicDERP {
			t.Fatal("cfg.UsePublicDERP = false, want true")
		}
		if got, want := cfg.ParallelPolicy, session.DefaultParallelPolicy(); got != want {
			t.Fatalf("cfg.ParallelPolicy = %#v, want %#v", got, want)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "hello"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runSendTransfer was not called")
	}
}
