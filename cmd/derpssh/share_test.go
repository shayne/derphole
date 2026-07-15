// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/endpointlookup"
	"github.com/shayne/derphole/pkg/telemetry"
)

func TestRunShareHelpPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runShare([]string{"--help"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runShare(--help) = %d, want 0", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Usage: derpssh share [--auto-accept read|write]") {
		t.Fatalf("stderr = %q, want usage", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunSharePassesAutoAcceptRole(t *testing.T) {
	old := runShareSession
	defer func() { runShareSession = old }()

	tests := []struct {
		name string
		args []string
		want protocol.Role
	}{
		{name: "interactive default", want: ""},
		{name: "read separate", args: []string{"--auto-accept", "read"}, want: protocol.RoleRead},
		{name: "write equals", args: []string{"--auto-accept=write"}, want: protocol.RoleWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got protocol.Role
			runShareSession = func(_ context.Context, cfg shareSessionConfig) error {
				got = cfg.AutoAcceptRole
				return nil
			}
			var stderr bytes.Buffer
			if code := runShare(tt.args, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr); code != 0 {
				t.Fatalf("runShare(%v) = %d stderr=%s", tt.args, code, stderr.String())
			}
			if got != tt.want {
				t.Fatalf("AutoAcceptRole = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunShareRejectsInvalidAutoAcceptRole(t *testing.T) {
	old := runShareSession
	defer func() { runShareSession = old }()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing", args: []string{"--auto-accept"}, want: "--auto-accept requires a value"},
		{name: "empty", args: []string{"--auto-accept="}, want: "invalid --auto-accept value"},
		{name: "unknown", args: []string{"--auto-accept", "admin"}, want: "invalid --auto-accept value"},
		{name: "case sensitive", args: []string{"--auto-accept", "Read"}, want: "invalid --auto-accept value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			runShareSession = func(context.Context, shareSessionConfig) error {
				called = true
				return nil
			}
			var stderr bytes.Buffer
			if code := runShare(tt.args, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr); code != 2 {
				t.Fatalf("runShare(%v) = %d, want 2", tt.args, code)
			}
			if called {
				t.Fatal("runShareSession called for invalid auto-accept role")
			}
			if got := stderr.String(); !strings.Contains(got, tt.want) || !strings.Contains(got, shareUsage()) {
				t.Fatalf("stderr = %q, want %q and usage", got, tt.want)
			}
		})
	}
}

func TestParseShareArgsCombinesAutoAcceptWithExistingFlags(t *testing.T) {
	var stderr bytes.Buffer
	parsed, ok := parseShareArgs([]string{
		"--force-relay",
		"--auto-accept", "read",
		"--register", "ops-shell",
		"--registry", "registry.json",
	}, &stderr)
	if !ok {
		t.Fatalf("parseShareArgs() failed: %s", stderr.String())
	}
	if !parsed.forceRelay || parsed.autoAccept != protocol.RoleRead || parsed.register != "ops-shell" || parsed.registry != "registry.json" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestRunSharePrintsConnectCommand(t *testing.T) {
	old := runShareSession
	defer func() { runShareSession = old }()
	runShareSession = func(ctx context.Context, cfg shareSessionConfig) error {
		_ = ctx
		_, _ = fmt.Fprintln(cfg.Stderr, "npx -y derpssh@latest connect DSH1test")
		return nil
	}
	var stderr bytes.Buffer
	code := runShare(nil, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("runShare() = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "npx -y derpssh@latest connect DSH1test") {
		t.Fatalf("stderr missing connect command:\n%s", stderr.String())
	}
}

func TestRunShareDoesNotRegisterByDefault(t *testing.T) {
	invite := newDerpsshInvite(t)
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	old := runShareSession
	defer func() { runShareSession = old }()
	runShareSession = func(ctx context.Context, cfg shareSessionConfig) error {
		_ = ctx
		_, _ = fmt.Fprintf(cfg.Stderr, "npx -y derpssh@latest connect %s\n", invite)
		return nil
	}

	var stderr bytes.Buffer
	code := runShare([]string{"--registry", registryPath}, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("runShare() = %d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(registryPath); !os.IsNotExist(err) {
		t.Fatalf("registry stat error = %v, want not exist", err)
	}
}

func TestRunShareRegisterWritesInviteRecord(t *testing.T) {
	invite := newDerpsshInvite(t)
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	old := runShareSession
	defer func() { runShareSession = old }()
	runShareSession = func(ctx context.Context, cfg shareSessionConfig) error {
		_ = ctx
		_, _ = fmt.Fprintf(cfg.Stderr, "npx -y derpssh@latest connect %s\n", invite)
		return nil
	}

	var stderr bytes.Buffer
	code := runShare([]string{"--register", "ops-shell", "--registry", registryPath}, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("runShare() = %d stderr=%s", code, stderr.String())
	}
	got, err := (endpointlookup.FileRegistry{Path: registryPath}).Resolve(context.Background(), "ops-shell", endpointlookup.KindDerpsshInvite)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Value != invite {
		t.Fatalf("registered invite = %q, want invite printed by share", got.Value)
	}
}

func TestCommandContextCancelsOnSIGQUIT(t *testing.T) {
	oldReset := commandSignalReset
	oldSelf := commandSignalSelf
	defer func() {
		commandSignalReset = oldReset
		commandSignalSelf = oldSelf
	}()

	resetCh := make(chan os.Signal, 1)
	reraiseCh := make(chan os.Signal, 1)
	commandSignalReset = func(sig ...os.Signal) {
		for _, s := range sig {
			resetCh <- s
		}
	}
	commandSignalSelf = func(sig os.Signal) error {
		reraiseCh <- sig
		return nil
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGQUIT)
	defer signal.Stop(sigCh)

	ctx, stop := commandContext()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess() error = %v", err)
	}
	if err := proc.Signal(syscall.SIGQUIT); err != nil {
		t.Fatalf("signal SIGQUIT: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(300 * time.Millisecond):
		t.Fatal("commandContext did not cancel on SIGQUIT")
	}

	stop()

	select {
	case got := <-resetCh:
		if got != syscall.SIGQUIT {
			t.Fatalf("reset signal = %v, want SIGQUIT", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("commandContext stop did not reset SIGQUIT")
	}
	select {
	case got := <-reraiseCh:
		if got != syscall.SIGQUIT {
			t.Fatalf("reraised signal = %v, want SIGQUIT", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("commandContext stop did not reraise SIGQUIT")
	}
}

func TestCommandContextStopDoesNotReraiseWithoutSIGQUIT(t *testing.T) {
	oldReset := commandSignalReset
	oldSelf := commandSignalSelf
	defer func() {
		commandSignalReset = oldReset
		commandSignalSelf = oldSelf
	}()

	resetCh := make(chan os.Signal, 1)
	reraiseCh := make(chan os.Signal, 1)
	commandSignalReset = func(sig ...os.Signal) {
		for _, s := range sig {
			resetCh <- s
		}
	}
	commandSignalSelf = func(sig os.Signal) error {
		reraiseCh <- sig
		return nil
	}

	_, stop := commandContext()
	stop()

	select {
	case sig := <-resetCh:
		t.Fatalf("unexpected reset for signal %v", sig)
	default:
	}
	select {
	case sig := <-reraiseCh:
		t.Fatalf("unexpected reraise for signal %v", sig)
	default:
	}
}
