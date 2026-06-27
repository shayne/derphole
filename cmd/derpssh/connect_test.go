// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
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

func TestRunConnectReturnsNotWired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConnect([]string{"invite"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runConnect() = %d, want 1", code)
	}
	if got := stderr.String(); !strings.Contains(got, "derpssh connect is not wired yet") {
		t.Fatalf("stderr = %q, want not wired error", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}
