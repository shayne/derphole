// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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

func TestRunSSHRootHelpAndUnknownCommand(t *testing.T) {
	for _, args := range [][]string{{"ssh"}, {"ssh", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, strings.NewReader("ignored"), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got := stderr.String(); !strings.Contains(got, "SSH invite and accept workflows") {
				t.Fatalf("stderr = %q, want SSH help", got)
			}
		})
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"ssh", "bogus"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, "unknown ssh command: bogus") {
		t.Fatalf("stderr = %q, want unknown ssh command", got)
	}
}

func TestConfirmSSHSendAcceptsYesAndRejectsDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  bool
	}{
		{name: "yes", input: "yes\n", want: true},
		{name: "short", input: "y\n", want: true},
		{name: "default", input: "\n", want: false},
		{name: "no", input: "no\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got, err := confirmSSHSend(strings.NewReader(tc.input), &stderr, "key-id")
			if err != nil {
				t.Fatalf("confirmSSHSend() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("confirmSSHSend() = %v, want %v", got, tc.want)
			}
			if !strings.Contains(stderr.String(), "Really send public key") {
				t.Fatalf("stderr = %q, want prompt", stderr.String())
			}
		})
	}
}

func TestConfirmSSHAcceptRequiresInputUnlessYes(t *testing.T) {
	if err := confirmSSHAccept(sshAcceptCommandConfig{Yes: true}, "key-id"); err != nil {
		t.Fatalf("confirmSSHAccept(yes) error = %v", err)
	}
	err := confirmSSHAccept(sshAcceptCommandConfig{Stdin: strings.NewReader("\n"), Stderr: io.Discard}, "key-id")
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("confirmSSHAccept() error = %v, want aborted", err)
	}
	err = confirmSSHAccept(sshAcceptCommandConfig{Stderr: io.Discard}, "key-id")
	if err == nil || !strings.Contains(err.Error(), "confirmation required") {
		t.Fatalf("confirmSSHAccept(nil stdin) error = %v, want confirmation required", err)
	}
}

func TestSSHHelpTextHelpers(t *testing.T) {
	if got := sshInviteHelpText(); !strings.Contains(got, "Add a public key to authorized_keys") {
		t.Fatalf("sshInviteHelpText() = %q, want invite help", got)
	}
	if got := sshAcceptHelpText(); !strings.Contains(got, "Accept an SSH key invite") {
		t.Fatalf("sshAcceptHelpText() = %q, want accept help", got)
	}
}

func TestExecuteSSHCommandsValidateLocalInputsBeforeNetwork(t *testing.T) {
	missingKey := filepath.Join(t.TempDir(), "missing.pub")
	err := executeSSHAcceptCommand(context.Background(), sshAcceptCommandConfig{
		Token:   "token",
		KeyFile: missingKey,
		Stdin:   strings.NewReader("yes\n"),
		Stderr:  io.Discard,
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("executeSSHAcceptCommand() error = %v, want missing key", err)
	}

	err = executeSSHInviteCommand(context.Background(), sshInviteCommandConfig{
		User:   "__derphole_missing_user__",
		Stderr: io.Discard,
	})
	if err == nil {
		t.Fatal("executeSSHInviteCommand() error = nil, want unknown user")
	}
}
