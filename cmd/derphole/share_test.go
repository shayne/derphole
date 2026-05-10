// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpShareShowsShareHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "share"}, {"share", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), shareHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestShareHelpMentionsServiceSharingUsage(t *testing.T) {
	help := shareHelpText()
	for _, want := range []string{
		"Share a local TCP service until Ctrl-C.",
		"derphole share 127.0.0.1:3000",
		"derphole share 127.0.0.1:8080 --print-token-only",
		"--force-relay",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("shareHelpText() = %q, want %q", help, want)
		}
	}
}
