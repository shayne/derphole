// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/telemetry"
)

func TestRunConnectHelpPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConnect([]string{"--help"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runConnect(--help) = %d, want 0", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Usage: derpssh connect [--name NAME] <invite>") {
		t.Fatalf("stderr = %q, want usage", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunConnectNamePassesDisplayName(t *testing.T) {
	old := runConnectSession
	defer func() { runConnectSession = old }()
	var got connectSessionConfig
	runConnectSession = func(ctx context.Context, cfg connectSessionConfig) error {
		_ = ctx
		got = cfg
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := runConnect([]string{"--name", "Alex", "DSH1test"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runConnect() = %d, want 0; stderr:\n%s", code, stderr.String())
	}
	if got.DisplayName != "Alex" {
		t.Fatalf("DisplayName = %q, want Alex", got.DisplayName)
	}
	if got.Invite != "DSH1test" {
		t.Fatalf("Invite = %q, want DSH1test", got.Invite)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
