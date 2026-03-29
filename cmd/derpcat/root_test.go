package main

import (
	"bytes"
	"testing"
)

func TestRunRejectsMissingSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); got != "usage: derpcat <listen|send> [flags]\n" {
		t.Fatalf("stderr = %q, want exact usage text", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunRejectsUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); got != "unknown subcommand \"bogus\"\n" {
		t.Fatalf("stderr = %q, want exact unknown subcommand message", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunPlaceholderSubcommandsReturnRuntimeFailure(t *testing.T) {
	cases := []string{"listen", "send"}

	for _, subcommand := range cases {
		t.Run(subcommand, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{subcommand}, nil, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("run() = %d, want 1", code)
			}
			if got := stderr.String(); got != subcommand+" not implemented\n" {
				t.Fatalf("stderr = %q, want exact placeholder message", got)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}
