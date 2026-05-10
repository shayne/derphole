// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunWithoutArgsShowsRootHelpAndSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got, want := stderr.String(), rootHelpText(); got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRootHelpIncludesRawStreamAndShareCommands(t *testing.T) {
	help := rootHelpText()
	for _, want := range []string{
		"derphole listen",
		"derphole pipe <token>",
		"derphole share 127.0.0.1:3000",
		"derphole open <token>",
		"derphole netcheck",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("rootHelpText() = %q, want %q", help, want)
		}
	}
}

func TestRunHelpReceiveShowsReceiveHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "receive"}, {"receive", "--help"}, {"rx", "--help"}, {"recv", "--help"}, {"recieve", "--help"}} {
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

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got, want := stderr.String(), "unknown command: bogus\nRun 'derphole --help' for usage\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunMainRoutesVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"version"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMain() = %d, want 0", code)
	}
	if got := stdout.String(); got != versionString()+"\n" {
		t.Fatalf("stdout = %q, want version", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

func TestRunShowsLLMHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help-llm"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got := stderr.String(); !strings.Contains(got, "derphole") || !strings.Contains(got, "send") {
		t.Fatalf("stderr = %q, want LLM root help", got)
	}
}

func TestRunRejectsConflictingTelemetryFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--verbose", "--quiet", "version"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, "only one of --verbose, --quiet, or --silent") {
		t.Fatalf("stderr = %q, want telemetry conflict", got)
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--not-a-flag"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, "unknown flag") {
		t.Fatalf("stderr = %q, want unknown flag", got)
	}
}
