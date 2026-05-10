// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

func TestRunListenPrintsTokenToStderrByDefault(t *testing.T) {
	prev := listenSession
	t.Cleanup(func() { listenSession = prev })
	listenSession = func(_ context.Context, cfg session.ListenConfig) (string, error) {
		cfg.TokenSink <- "listen-token"
		return "listen-token", nil
	}

	var stdout, stderr bytes.Buffer
	code := runListen(nil, telemetry.LevelDefault, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runListen() = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
	if got := stderr.String(); !strings.Contains(got, "listen-token\n") {
		t.Fatalf("stderr = %q, want token", got)
	}
}

func TestRunListenPrintTokenOnlyUsesStdout(t *testing.T) {
	prev := listenSession
	t.Cleanup(func() { listenSession = prev })
	listenSession = func(_ context.Context, cfg session.ListenConfig) (string, error) {
		if !cfg.ForceRelay {
			t.Fatal("ForceRelay = false, want true")
		}
		cfg.TokenSink <- "only-token"
		return "only-token", nil
	}

	var stdout, stderr bytes.Buffer
	code := runListen([]string{"--print-token-only", "--force-relay"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runListen() = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got := stdout.String(); got != "only-token\n" {
		t.Fatalf("stdout = %q, want token", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

func TestRunListenReportsSessionErrorBeforeToken(t *testing.T) {
	prev := listenSession
	t.Cleanup(func() { listenSession = prev })
	listenSession = func(context.Context, session.ListenConfig) (string, error) {
		return "", errors.New("listen failed")
	}

	var stdout, stderr bytes.Buffer
	code := runListen(nil, telemetry.LevelDefault, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runListen() = %d, want 1", code)
	}
	if got := stderr.String(); !strings.Contains(got, "listen failed") {
		t.Fatalf("stderr = %q, want listen error", got)
	}
}

func TestRunSharePrintsTokenAndPassesTarget(t *testing.T) {
	prev := shareSession
	t.Cleanup(func() { shareSession = prev })
	shareSession = func(_ context.Context, cfg session.ShareConfig) (string, error) {
		if cfg.TargetAddr != "127.0.0.1:3000" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:3000", cfg.TargetAddr)
		}
		cfg.TokenSink <- "share-token"
		return "share-token", nil
	}

	var stdout, stderr bytes.Buffer
	code := runShare([]string{"127.0.0.1:3000"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runShare() = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got := stderr.String(); !strings.Contains(got, "share-token\n") {
		t.Fatalf("stderr = %q, want share token", got)
	}
}

func TestRunShareCanceledBeforeTokenIsCleanExit(t *testing.T) {
	prev := shareSession
	t.Cleanup(func() { shareSession = prev })
	shareSession = func(context.Context, session.ShareConfig) (string, error) {
		return "", context.Canceled
	}

	var stdout, stderr bytes.Buffer
	code := runShare([]string{"127.0.0.1:3000"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runShare() = %d, want 0; stderr=%q", code, stderr.String())
	}
}

func TestRunOpenPrintsBindAndWaitsForCleanExit(t *testing.T) {
	prev := openSession
	t.Cleanup(func() { openSession = prev })
	openSession = func(_ context.Context, cfg session.OpenConfig) error {
		if cfg.Token != "open-token" || cfg.BindAddr != "127.0.0.1:8080" {
			t.Fatalf("OpenConfig token/bind = %q/%q", cfg.Token, cfg.BindAddr)
		}
		if cfg.ParallelPolicy.Mode != session.ParallelModeFixed || cfg.ParallelPolicy.Initial != 2 {
			t.Fatalf("ParallelPolicy = %+v, want fixed 2", cfg.ParallelPolicy)
		}
		cfg.BindAddrSink <- "127.0.0.1:8080"
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := runOpen([]string{"--parallel", "2", "open-token", "127.0.0.1:8080"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOpen() = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got := stderr.String(); !strings.Contains(got, "listening on 127.0.0.1:8080") {
		t.Fatalf("stderr = %q, want bind address", got)
	}
}

func TestRunOpenReportsSessionErrorBeforeBind(t *testing.T) {
	prev := openSession
	t.Cleanup(func() { openSession = prev })
	openSession = func(context.Context, session.OpenConfig) error {
		return errors.New("open failed")
	}

	var stdout, stderr bytes.Buffer
	code := runOpen([]string{"open-token"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runOpen() = %d, want 1", code)
	}
	if got := stderr.String(); !strings.Contains(got, "open failed") {
		t.Fatalf("stderr = %q, want open error", got)
	}
}

func TestRunPipeInvokesSessionSend(t *testing.T) {
	prev := sendSession
	t.Cleanup(func() { sendSession = prev })
	sendSession = func(_ context.Context, cfg session.SendConfig) error {
		if cfg.Token != "pipe-token" {
			t.Fatalf("Token = %q, want pipe-token", cfg.Token)
		}
		if cfg.ParallelPolicy.Mode != session.ParallelModeAuto {
			t.Fatalf("ParallelPolicy = %+v, want auto", cfg.ParallelPolicy)
		}
		body, err := io.ReadAll(cfg.StdioIn)
		if err != nil {
			t.Fatalf("ReadAll(StdioIn) error = %v", err)
		}
		if string(body) != "payload" {
			t.Fatalf("StdioIn = %q, want payload", body)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := runPipe([]string{"--parallel", "auto", "pipe-token"}, telemetry.LevelDefault, strings.NewReader("payload"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runPipe() = %d, want 0; stderr=%q", code, stderr.String())
	}
}

func TestRunPipeReportsInvalidParallelPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPipe([]string{"--parallel", "nope", "pipe-token"}, telemetry.LevelDefault, strings.NewReader("payload"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runPipe() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, "parallel must be 1-16 or auto") {
		t.Fatalf("stderr = %q, want invalid parallel error", got)
	}
}

func TestListenHelpLLMTextAndDoneStatus(t *testing.T) {
	if got := listenHelpLLMText(); !strings.Contains(got, "Listen for one incoming raw byte stream") {
		t.Fatalf("listenHelpLLMText() = %q, want listen help", got)
	}

	done := make(chan error, 1)
	done <- errors.New("listen done failed")
	var stderr bytes.Buffer
	if code := waitListenDone(done, &stderr); code != 1 {
		t.Fatalf("waitListenDone(error) = %d, want 1", code)
	}
	if got := stderr.String(); !strings.Contains(got, "listen done failed") {
		t.Fatalf("stderr = %q, want wait error", got)
	}

	done = make(chan error, 1)
	done <- nil
	if code := waitListenDone(done, io.Discard); code != 0 {
		t.Fatalf("waitListenDone(nil) = %d, want 0", code)
	}
}
