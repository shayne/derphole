// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpOpenShowsOpenHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "open"}, {"open", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), openHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestOpenHelpMentionsServiceOpenUsage(t *testing.T) {
	help := openHelpText()
	for _, want := range []string{
		"Open a shared service locally until Ctrl-C.",
		"derphole open <token>",
		"derphole open <token> 127.0.0.1:8080",
		"-P",
		"--parallel",
		"auto",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("openHelpText() = %q, want %q", help, want)
		}
	}
}
