// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunHelpSSHInviteShowsSSHHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ssh", "invite", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "Add a public key to authorized_keys") {
		t.Fatalf("stderr = %q, want ssh invite help", stderr.String())
	}
}

func TestRunHelpSSHAcceptShowsSSHAcceptHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ssh", "accept", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "Accept an SSH key invite") {
		t.Fatalf("stderr = %q, want ssh accept help", stderr.String())
	}
}

func TestRunSSHInviteInvokesWorkflow(t *testing.T) {
	prev := runSSHInviteCommand
	t.Cleanup(func() {
		runSSHInviteCommand = prev
	})

	called := false
	runSSHInviteCommand = func(_ context.Context, cfg sshInviteCommandConfig) error {
		called = true
		if cfg.User != "deploy" {
			t.Fatalf("cfg.User = %q, want %q", cfg.User, "deploy")
		}
		if !cfg.UsePublicDERP {
			t.Fatal("cfg.UsePublicDERP = false, want true")
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"ssh", "invite", "--user", "deploy"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runSSHInviteCommand was not called")
	}
}

func TestRunSSHAcceptInvokesWorkflow(t *testing.T) {
	prev := runSSHAcceptCommand
	t.Cleanup(func() {
		runSSHAcceptCommand = prev
	})

	called := false
	runSSHAcceptCommand = func(_ context.Context, cfg sshAcceptCommandConfig) error {
		called = true
		if cfg.Token != "token-123" {
			t.Fatalf("cfg.Token = %q, want %q", cfg.Token, "token-123")
		}
		if cfg.KeyFile != "/tmp/key.pub" {
			t.Fatalf("cfg.KeyFile = %q, want %q", cfg.KeyFile, "/tmp/key.pub")
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"ssh", "accept", "--key-file", "/tmp/key.pub", "token-123"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runSSHAcceptCommand was not called")
	}
}
