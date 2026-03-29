package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/yargs"
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
			assertRootHelp(t, got)
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunRootHelpLLMSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help-llm"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got, want := stderr.String(), yargs.GenerateGlobalHelpLLM(rootHelpConfig, rootGlobalFlags{}); got != want {
		t.Fatalf("stderr = %q, want exact LLM help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpListenShowsListenHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "listen"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
		listenHelpConfig,
		"listen",
		struct{}{},
		listenFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want exact listen help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpListenHelpShowsListenHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "listen", "--help"}, {"help", "listen", "--help-llm"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			want := yargs.GenerateSubCommandHelp(
				listenHelpConfig,
				"listen",
				struct{}{},
				listenFlags{},
				struct{}{},
			)
			if args[2] == "--help-llm" {
				want = yargs.GenerateSubCommandHelpLLM(
					listenHelpConfig,
					"listen",
					struct{}{},
					listenFlags{},
					struct{}{},
				)
			}
			if got := stderr.String(); got != want {
				t.Fatalf("stderr = %q, want exact listen help %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunHelpListenPreservesLegacyHelpSpellings(t *testing.T) {
	for _, args := range [][]string{
		{"help", "listen", "-h"},
		{"help", "listen", "-help"},
		{"help", "listen", "--help=0"},
		{"help", "listen", "--help", "extra"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
				listenHelpConfig,
				"listen",
				struct{}{},
				listenFlags{},
				struct{}{},
			); got != want {
				t.Fatalf("stderr = %q, want exact listen help %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunHelpListenDelegatesNonRuntimeFailures(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{
			name:       "double dash positional",
			args:       []string{"help", "listen", "--", "--help"},
			wantCode:   2,
			wantStderr: yargs.GenerateSubCommandHelp(listenHelpConfig, "listen", struct{}{}, listenFlags{}, struct{}{}),
		},
		{
			name:       "unknown flag remains authoritative",
			args:       []string{"help", "listen", "--bogus", "--", "--help"},
			wantCode:   2,
			wantStderr: "unknown flag: --bogus\n" + yargs.GenerateSubCommandHelp(listenHelpConfig, "listen", struct{}{}, listenFlags{}, struct{}{}),
		},
		{
			name:       "positional before help",
			args:       []string{"help", "listen", "extra", "--help"},
			wantCode:   2,
			wantStderr: yargs.GenerateSubCommandHelp(listenHelpConfig, "listen", struct{}{}, listenFlags{}, struct{}{}),
		},
		{
			name:       "unknown flag",
			args:       []string{"help", "listen", "--bogus"},
			wantCode:   2,
			wantStderr: "unknown flag: --bogus\n" + yargs.GenerateSubCommandHelp(listenHelpConfig, "listen", struct{}{}, listenFlags{}, struct{}{}),
		},
		{
			name:       "stray positional",
			args:       []string{"help", "listen", "extra"},
			wantCode:   2,
			wantStderr: yargs.GenerateSubCommandHelp(listenHelpConfig, "listen", struct{}{}, listenFlags{}, struct{}{}),
		},
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
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
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
			assertVersionHelp(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunVersionHelpRejectsExtraArgs(t *testing.T) {
	for _, args := range [][]string{{"version", "--help", "extra"}, {"version", "-h", "extra"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}
			assertVersionHelp(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunVersionHelpLLMSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version", "--help-llm"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelpLLMFromConfig(rootHelpConfig, "version", rootGlobalFlags{}); got != want {
		t.Fatalf("stderr = %q, want exact LLM version help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpVersionHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "version", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	assertVersionHelp(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunVersionHelpLLMRejectsExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version", "--help-llm", "extra"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	assertVersionHelp(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunHelpVersionHelpLLMSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help", "version", "--help-llm"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelpLLMFromConfig(rootHelpConfig, "version", rootGlobalFlags{}); got != want {
		t.Fatalf("stderr = %q, want exact LLM version help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestParseRootArgsResetsVerbosityToDefaultOnFalseNegation(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantLevel     telemetry.Level
		wantRemaining []string
	}{
		{name: "quiet", args: []string{"-q", "--quiet=false", "listen"}, wantLevel: telemetry.LevelDefault, wantRemaining: []string{"listen"}},
		{name: "silent", args: []string{"-s", "--silent=false", "listen"}, wantLevel: telemetry.LevelDefault, wantRemaining: []string{"listen"}},
		{name: "verbose", args: []string{"-v", "--verbose=false", "listen"}, wantLevel: telemetry.LevelDefault, wantRemaining: []string{"listen"}},
		{name: "quiet preserved across verbose false", args: []string{"-q", "--verbose=false", "listen"}, wantLevel: telemetry.LevelQuiet, wantRemaining: []string{"listen"}},
		{name: "silent preserved across quiet false", args: []string{"-s", "--quiet=false", "listen"}, wantLevel: telemetry.LevelSilent, wantRemaining: []string{"listen"}},
		{name: "verbose preserved across quiet false", args: []string{"-v", "--quiet=false", "listen"}, wantLevel: telemetry.LevelVerbose, wantRemaining: []string{"listen"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLevel, gotRemaining, err := parseRootArgs(tc.args)
			if err != nil {
				t.Fatalf("parseRootArgs() error = %v", err)
			}
			if gotLevel != tc.wantLevel {
				t.Fatalf("parseRootArgs() level = %v, want %v", gotLevel, tc.wantLevel)
			}
			if len(gotRemaining) != len(tc.wantRemaining) {
				t.Fatalf("parseRootArgs() remaining = %v, want %v", gotRemaining, tc.wantRemaining)
			}
			for i := range tc.wantRemaining {
				if gotRemaining[i] != tc.wantRemaining[i] {
					t.Fatalf("parseRootArgs() remaining = %v, want %v", gotRemaining, tc.wantRemaining)
				}
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

func TestRunHelpSendDelegatesNonRuntimeArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{name: "plain help", args: []string{"help", "send"}, wantCode: 0},
		{name: "legacy short help", args: []string{"help", "send", "-h"}, wantCode: 0},
		{name: "token before help", args: []string{"help", "send", "token-value", "-h"}, wantCode: 0},
		{name: "unknown flag", args: []string{"help", "send", "--bogus"}, wantCode: 2, wantStderr: "unknown flag: --bogus\n"},
		{name: "double dash before help", args: []string{"help", "send", "--", "--help"}, wantCode: 0},
		{name: "unknown flag before double dash help", args: []string{"help", "send", "--bogus", "--", "--help"}, wantCode: 0},
		{name: "token with trailing double dash args", args: []string{"help", "send", "token-value", "--", "extra"}, wantCode: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, nil, &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("run() = %d, want %d", code, tc.wantCode)
			}
			if tc.wantStderr != "" {
				if !strings.HasPrefix(stderr.String(), tc.wantStderr) {
					t.Fatalf("stderr = %q, want prefix %q", stderr.String(), tc.wantStderr)
				}
			}
			assertSendHelpText(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestRunHelpListenRejectsExtraArgs(t *testing.T) {
	for _, args := range [][]string{
		{"help", "listen", "--tcp-listen", "127.0.0.1:7000"},
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
	for _, want := range []string{
		"GLOBAL OPTIONS:",
		"-v, --verbose",
		"-q, --quiet",
		"-s, --silent",
		"EXAMPLES:",
		"derpcat listen",
		"derpcat send <token>",
		"derpcat version",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr = %q, want root help mentioning %q", got, want)
		}
	}
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
	if got := stderr.String(); !strings.HasPrefix(got, "flag provided but not defined: --version\n") {
		t.Fatalf("stderr = %q, want parse error prefix for --version", got)
	}
	assertRootHelp(t, stderr.String())
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
		{name: "quiet equals false resets to default", args: []string{"-q", "--quiet=false", "listen"}, wantPrefix: "waiting-for-claim\n"},
		{name: "silent", args: []string{"-s", "listen"}, wantPrefix: ""},
		{name: "silent equals true", args: []string{"--silent=true", "listen"}, wantPrefix: ""},
		{name: "silent equals false resets to default", args: []string{"-s", "--silent=false", "listen"}, wantPrefix: "waiting-for-claim\n"},
		{name: "verbose", args: []string{"-v", "listen"}, wantPrefix: "waiting-for-claim\n"},
		{name: "last verbose wins", args: []string{"-s", "-v", "listen"}, wantPrefix: "waiting-for-claim\n"},
		{name: "last silent wins", args: []string{"-v", "-s", "listen"}, wantPrefix: ""},
		{name: "quiet preserved across verbose false", args: []string{"-q", "--verbose=false", "listen"}, wantPrefix: ""},
		{name: "silent preserved across quiet false", args: []string{"-s", "--quiet=false", "listen"}, wantPrefix: ""},
		{name: "verbose preserved across quiet false", args: []string{"-v", "--quiet=false", "listen"}, wantPrefix: "waiting-for-claim\n"},
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
			if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
				listenHelpConfig,
				"listen",
				struct{}{},
				listenFlags{},
				struct{}{},
			); got != want {
				t.Fatalf("stderr = %q, want exact listen help %q", got, want)
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
		wantPrefix string
	}{
		{name: "quiet", args: []string{"-q", "send"}, wantPrefix: ""},
		{name: "silent", args: []string{"-s", "send"}, wantPrefix: ""},
		{name: "verbose", args: []string{"-v", "send"}, wantPrefix: "probing-direct\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listenerStdoutBuf := &lockedBuffer{}
			listenerStderrBuf := &lockedBuffer{}
			listenerDone := make(chan int, 1)
			go func() {
				listenerDone <- run([]string{"listen"}, nil, listenerStdoutBuf, listenerStderrBuf)
			}()

			issuedToken := waitForIssuedToken(t, listenerStderrBuf)

			senderArgs := append(append([]string(nil), tc.args...), issuedToken, "--force-relay")
			var senderStdout, senderStderr bytes.Buffer
			code := run(senderArgs, strings.NewReader("payload"), &senderStdout, &senderStderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0, stderr=%q", code, senderStderr.String())
			}
			if got := senderStdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}

			select {
			case code := <-listenerDone:
				if code != 0 {
					t.Fatalf("listen run() = %d, want 0, stderr=%q", code, listenerStderrBuf.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("listen subcommand did not complete after sender finished")
			}

			if tc.wantPrefix == "" {
				if got := senderStderr.String(); got != "" {
					t.Fatalf("stderr = %q, want empty", got)
				}
				return
			}
			if got := senderStderr.String(); !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("stderr = %q, want prefix %q", got, tc.wantPrefix)
			}
		})
	}
}

func assertVersionHelp(t *testing.T, got string) {
	t.Helper()
	if got != "usage: derpcat version\n" {
		t.Fatalf("stderr = %q, want exact version usage %q", got, "usage: derpcat version\\n")
	}
}

func TestRunRejectsUnknownRootFlagBeforeVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--bogus", "version"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	assertRootHelp(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunRejectsUnknownRootFlagBeforeListen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--bogus", "listen"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	assertRootHelp(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunSendDispatchesToSendUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"send"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	assertSendHelpText(t, stderr.String())
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
	assertSendHelpText(t, stderr.String())
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
