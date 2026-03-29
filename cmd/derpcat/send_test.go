package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shayne/derpcat/pkg/telemetry"
)

func TestSendRejectsMissingTokenArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{}, telemetry.LevelDefault, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runSend() = %d, want 2", code)
	}
	assertSendHelpText(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestSendHelpTargetsCanonicalUsage(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runSend(args, telemetry.LevelDefault, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runSend() = %d, want 0", code)
			}
			assertSendHelpText(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestSendAllowsTokenBeforeFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{"token-value", "-h"}, telemetry.LevelDefault, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runSend() = %d, want 0", code)
	}
	assertSendHelpText(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestSendPreservesIntentionalHelpEdgeCases(t *testing.T) {
	for _, args := range [][]string{
		{"--", "--help"},
		{"token-value", "--help"},
		{"--bogus", "--", "--help"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runSend(args, telemetry.LevelDefault, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runSend() = %d, want 0", code)
			}
			assertSendHelpText(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func assertSendHelpText(t *testing.T, got string) {
	t.Helper()
	for _, want := range []string{
		"Send data to a derpcat listener using its token.",
		"USAGE:",
		"ARGUMENTS:",
		"TOKEN",
		"--force-relay",
		"--tcp-listen",
		"--tcp-connect",
		"cat file | derpcat send <token>",
		"derpcat send <token> --tcp-listen 127.0.0.1:7000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr = %q, want help mentioning %q", got, want)
		}
	}
}
