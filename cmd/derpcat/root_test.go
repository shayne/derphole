package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRunRejectsMissingSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	got := stderr.String()
	for _, want := range []string{"listen", "send", "version"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr = %q, want help mentioning %q", got, want)
		}
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

func TestRunRootHelpSucceeds(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			got := stderr.String()
			for _, want := range []string{"listen", "send", "version"} {
				if !strings.Contains(got, want) {
					t.Fatalf("stderr = %q, want help mentioning %q", got, want)
				}
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunHelpListenShowsListenHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "listen"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got := stderr.String(); got != listenUsage+"\n" {
		t.Fatalf("stderr = %q, want exact listen usage", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpBogusRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "bogus"}, nil, &stdout, &stderr)
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

func TestRunRootVersionCommandSucceeds(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = origVersion, origCommit, origBuildDate
	})

	version = "v0.0.1"
	commit = "abc1234"
	buildDate = "2026-03-29T12:00:00Z"

	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got := stdout.String(); got != "v0.0.1\n" {
		t.Fatalf("stdout = %q, want version output", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

func TestRunVersionHelpShowsHelp(t *testing.T) {
	for _, args := range [][]string{{"version", "--help"}, {"help", "version"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got := stderr.String(); got != versionUsage+"\n" {
				t.Fatalf("stderr = %q, want exact version usage", got)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunVersionRejectsExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version", "garbage"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); got != versionUsage+"\n" {
		t.Fatalf("stderr = %q, want exact version usage", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunVersionRejectsRootFlagAfterCommand(t *testing.T) {
	for _, args := range [][]string{{"version", "-v"}, {"version", "--quiet"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}
			if got := stderr.String(); !strings.Contains(got, versionUsage+"\n") {
				t.Fatalf("stderr = %q, want version usage", got)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunHelpVersionRejectsExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "version", "garbage"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	assertRootHelp(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpSendRejectsExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "send", "garbage"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	assertRootHelp(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpListenRejectsExtraArgs(t *testing.T) {
	for _, args := range [][]string{
		{"help", "listen", "--tcp-listen", "127.0.0.1:7000"},
		{"help", "listen", "-v"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}
			assertRootHelp(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func assertRootHelp(t *testing.T, got string) {
	t.Helper()
	for _, want := range []string{"listen", "send", "version"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr = %q, want root help mentioning %q", got, want)
		}
	}
}

func TestRunRootRejectsVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); got == "" {
		t.Fatal("stderr = empty, want usage or parse error")
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunListenDispatchesToListenBehavior(t *testing.T) {
	listenerStdoutBuf := &lockedBuffer{}
	listenerStderrBuf := &lockedBuffer{}
	listenerDone := make(chan int, 1)
	go func() {
		listenerDone <- run([]string{"listen"}, nil, listenerStdoutBuf, listenerStderrBuf)
	}()

	issuedToken := waitForIssuedToken(t, listenerStderrBuf)

	var senderStdout, senderStderr bytes.Buffer
	code := run([]string{"send", issuedToken, "--force-relay"}, strings.NewReader("hello through root"), &senderStdout, &senderStderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, senderStderr.String())
	}
	if got := senderStdout.String(); got != "" {
		t.Fatalf("sender stdout = %q, want empty", got)
	}

	select {
	case code := <-listenerDone:
		if code != 0 {
			t.Fatalf("run() = %d, want 0, stderr=%q", code, listenerStderrBuf.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listen subcommand did not complete after sender finished")
	}

	if got := listenerStdoutBuf.String(); got != "hello through root" {
		t.Fatalf("listener stdout = %q, want payload", got)
	}
	if !strings.Contains(listenerStderrBuf.String(), issuedToken+"\n") {
		t.Fatalf("listener stderr = %q, want issued token", listenerStderrBuf.String())
	}
}

func TestRunVerbosityFlagsBeforeListen(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantPrefix string
	}{
		{name: "quiet", args: []string{"-q", "listen"}, wantPrefix: ""},
		{name: "quiet equals true", args: []string{"--quiet=true", "listen"}, wantPrefix: ""},
		{name: "silent", args: []string{"-s", "listen"}, wantPrefix: ""},
		{name: "silent equals true", args: []string{"--silent=true", "listen"}, wantPrefix: ""},
		{name: "verbose", args: []string{"-v", "listen"}, wantPrefix: "waiting-for-claim\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listenerStdoutBuf := &lockedBuffer{}
			listenerStderrBuf := &lockedBuffer{}
			listenerDone := make(chan int, 1)
			go func() {
				listenerDone <- run(tc.args, nil, listenerStdoutBuf, listenerStderrBuf)
			}()

			issuedToken := waitForIssuedToken(t, listenerStderrBuf)

			var senderStdout, senderStderr bytes.Buffer
			code := run([]string{"send", issuedToken, "--force-relay"}, strings.NewReader("payload"), &senderStdout, &senderStderr)
			if code != 0 {
				t.Fatalf("send run() = %d, want 0, stderr=%q", code, senderStderr.String())
			}

			select {
			case code := <-listenerDone:
				if code != 0 {
					t.Fatalf("listen run() = %d, want 0, stderr=%q", code, listenerStderrBuf.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("listen subcommand did not complete after sender finished")
			}

			if got := listenerStderrBuf.String(); !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("stderr = %q, want prefix %q", got, tc.wantPrefix)
			}
			if !strings.Contains(listenerStderrBuf.String(), issuedToken+"\n") {
				t.Fatalf("stderr = %q, want token on stderr", listenerStderrBuf.String())
			}
		})
	}
}

func TestRunListenHelpSucceeds(t *testing.T) {
	for _, args := range [][]string{{"listen", "-h"}, {"listen", "--help"}} {
		t.Run(args[1], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got := stderr.String(); got != listenUsage+"\n" {
				t.Fatalf("stderr = %q, want exact listen usage", got)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunVerbosityFlagsBeforeSend(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{name: "quiet usage", args: []string{"-q", "send"}, wantCode: 2, wantStderr: sendUsage + "\n"},
		{name: "silent help", args: []string{"-s", "send", "token-value", "-h"}, wantCode: 0, wantStderr: sendUsage + "\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, nil, &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("run() = %d, want %d", code, tc.wantCode)
			}
			if got := stderr.String(); got != tc.wantStderr {
				t.Fatalf("stderr = %q, want %q", got, tc.wantStderr)
			}
			if tc.wantCode == 0 && stdout.String() != "" {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestRunSendDispatchesToSendUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"send"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); got != sendUsage+"\n" {
		t.Fatalf("stderr = %q, want usage text", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunSendGrammarAllowsTokenBeforeFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "token-value", "-h"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got := stderr.String(); got != sendUsage+"\n" {
		t.Fatalf("stderr = %q, want exact send usage", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunSendRejectsMutuallyExclusiveTCPFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "token-value", "--tcp-listen", "127.0.0.1:7000", "--tcp-connect", "127.0.0.1:9000"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if got := stderr.String(); got != "send: --tcp-listen and --tcp-connect are mutually exclusive\n" {
		t.Fatalf("stderr = %q, want mutual exclusion error", got)
	}
}
