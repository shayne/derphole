// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpShowsDerptunCommands(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := stderr.String()
	for _, want := range []string{"derptun", "token", "serve", "open", "connect", "netcheck"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q in:\n%s", want, out)
		}
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

func TestRunRejectsUnknownCommandAndFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "command", args: []string{"bogus"}, want: "unknown command: bogus"},
		{name: "flag", args: []string{"--bogus"}, want: "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, strings.NewReader("ignored"), &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}
			if got := stderr.String(); !strings.Contains(got, tc.want) {
				t.Fatalf("stderr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenHelpTextDescribesTokenSources(t *testing.T) {
	help := openHelpText()
	for _, want := range []string{"Listen locally and forward", "--token-file", "--token-stdin", "--listen"} {
		if !strings.Contains(help, want) {
			t.Fatalf("openHelpText() = %q, want %q", help, want)
		}
	}
}
