package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	pkgderphole "github.com/shayne/derpcat/pkg/derphole"
	"github.com/shayne/derpcat/pkg/session"
)

func TestRunHelpReceiveAliasesShowReceiveHelp(t *testing.T) {
	for _, args := range [][]string{{"receive", "--help"}, {"rx", "--help"}, {"recv", "--help"}, {"recieve", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), receiveHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
		})
	}
}

func TestReceiveHelpIncludesHideProgress(t *testing.T) {
	if !strings.Contains(receiveHelpText(), "--hide-progress") {
		t.Fatalf("receiveHelpText() missing --hide-progress:\n%s", receiveHelpText())
	}
}

func TestRunReceiveWithoutCodeAllocatesTransfer(t *testing.T) {
	prev := runReceiveTransfer
	t.Cleanup(func() {
		runReceiveTransfer = prev
	})

	called := false
	runReceiveTransfer = func(_ context.Context, cfg pkgderphole.ReceiveConfig) error {
		called = true
		if !cfg.Allocate {
			t.Fatal("cfg.Allocate = false, want true")
		}
		if cfg.Token != "" {
			t.Fatalf("cfg.Token = %q, want empty", cfg.Token)
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
	code := run([]string{"receive"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runReceiveTransfer was not called")
	}
}

func TestRunReceiveWithCodeInvokesTransfer(t *testing.T) {
	prev := runReceiveTransfer
	t.Cleanup(func() {
		runReceiveTransfer = prev
	})

	called := false
	runReceiveTransfer = func(_ context.Context, cfg pkgderphole.ReceiveConfig) error {
		called = true
		if cfg.Allocate {
			t.Fatal("cfg.Allocate = true, want false")
		}
		if cfg.Token != "7-purple-sausages" {
			t.Fatalf("cfg.Token = %q, want %q", cfg.Token, "7-purple-sausages")
		}
		if got, want := cfg.ParallelPolicy, session.DefaultParallelPolicy(); got != want {
			t.Fatalf("cfg.ParallelPolicy = %#v, want %#v", got, want)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"receive", "7-purple-sausages"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runReceiveTransfer was not called")
	}
}
