// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/telemetry"
)

func TestRunShareHelpPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runShare([]string{"--help"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runShare(--help) = %d, want 0", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Usage: derpssh share [--force-relay]") {
		t.Fatalf("stderr = %q, want usage", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
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
