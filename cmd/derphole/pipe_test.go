package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpPipeShowsPipeHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "pipe"}, {"pipe", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), pipeHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestPipeHelpMentionsRawStreamAndParallelFlag(t *testing.T) {
	help := pipeHelpText()
	for _, want := range []string{
		"Send stdin as a raw byte stream to a derphole listener.",
		"cat file | derphole pipe <token>",
		"printf 'hello' | derphole pipe <token>",
		"-P",
		"--parallel",
		"auto",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("pipeHelpText() = %q, want %q", help, want)
		}
	}
}
