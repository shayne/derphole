// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	derpsshsession "github.com/shayne/derphole/pkg/derpssh/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

type shareSessionConfig = derpsshsession.ShareConfig

var runShareSession = derpsshsession.Share

var commandSignalReset = signal.Reset
var commandSignalSelf = func(sig os.Signal) error {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return proc.Signal(sig)
}

var commandContext = func() (context.Context, context.CancelFunc) {
	baseCtx, baseStop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(baseCtx)
	sigquitCh := make(chan os.Signal, 1)
	signal.Notify(sigquitCh, syscall.SIGQUIT)

	var sigquit atomic.Bool
	go func() {
		select {
		case <-sigquitCh:
			sigquit.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			baseStop()
			signal.Stop(sigquitCh)
			if sigquit.Load() {
				commandSignalReset(syscall.SIGQUIT)
				_ = commandSignalSelf(syscall.SIGQUIT)
			}
		})
	}
	return ctx, stop
}

func runShare(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		_, _ = fmt.Fprintln(stderr, "Usage: derpssh share [--force-relay]")
		return 0
	}
	forceRelay, ok := parseShareArgs(args, stderr)
	if !ok {
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := runShareSession(ctx, shareSessionConfig{
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		ForceRelay: forceRelay,
		Emitter:    telemetry.New(stderr, commandSessionTelemetryLevel(level)),
	}); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseShareArgs(args []string, stderr io.Writer) (bool, bool) {
	var forceRelay bool
	for _, arg := range args {
		switch arg {
		case "--force-relay":
			forceRelay = true
		default:
			if len(arg) > 0 && arg[0] == '-' {
				_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
			}
			_, _ = fmt.Fprintln(stderr, "Usage: derpssh share [--force-relay]")
			return false, false
		}
	}
	return forceRelay, true
}

func commandSessionTelemetryLevel(level telemetry.Level) telemetry.Level {
	if level == telemetry.LevelDefault {
		return telemetry.LevelQuiet
	}
	return level
}
