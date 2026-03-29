package main

import (
	"bytes"
	"testing"
)

func TestSendRejectsMissingTokenArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runSend() = %d, want 2", code)
	}
	if got := stderr.String(); got != "usage: derpcat send <token> [flags...]\n" {
		t.Fatalf("stderr = %q, want usage text", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestSendHelpTargetsCanonicalUsage(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runSend(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runSend() = %d, want 0", code)
			}
			if got := stderr.String(); got != "usage: derpcat send <token> [flags...]\n" {
				t.Fatalf("stderr = %q, want exact send usage", got)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestSendAllowsTokenBeforeFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{"token-value", "-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runSend() = %d, want 0", code)
	}
	if got := stderr.String(); got != "usage: derpcat send <token> [flags...]\n" {
		t.Fatalf("stderr = %q, want exact send usage", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}
