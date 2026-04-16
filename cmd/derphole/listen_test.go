package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpListenShowsListenHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "listen"}, {"listen", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), listenHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestListenHelpMentionsRawStreamUsage(t *testing.T) {
	help := listenHelpText()
	for _, want := range []string{
		"Listen for one incoming raw byte stream and write it to stdout.",
		"derphole listen",
		"derphole listen --print-token-only",
		"--force-relay",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("listenHelpText() = %q, want %q", help, want)
		}
	}
}
