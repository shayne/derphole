package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/yargs"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func runRelayListenAndSend(
	t *testing.T,
	listenArgs []string,
	level telemetry.Level,
	tokenSource func(stdout, stderr *lockedBuffer) *lockedBuffer,
	payload string,
) (listenerStdout string, listenerStderr string, senderStderr string, issuedToken string) {
	t.Helper()

	listenerStdoutBuf := &lockedBuffer{}
	listenerStderrBuf := &lockedBuffer{}
	listenerDone := make(chan int, 1)
	go func() {
		listenerDone <- runListen(listenArgs, level, listenerStdoutBuf, listenerStderrBuf)
	}()

	issuedToken = waitForIssuedToken(t, tokenSource(listenerStdoutBuf, listenerStderrBuf))

	var senderStdout bytes.Buffer
	var senderStderrBuf bytes.Buffer
	sendCode := runSend([]string{issuedToken, "--force-relay"}, level, strings.NewReader(payload), &senderStdout, &senderStderrBuf)
	if sendCode != 0 {
		t.Fatalf("runSend() = %d, want 0, stderr=%q", sendCode, senderStderrBuf.String())
	}
	if got := senderStdout.String(); got != "" {
		t.Fatalf("sender stdout = %q, want empty", got)
	}

	select {
	case code := <-listenerDone:
		if code != 0 {
			t.Fatalf("runListen() = %d, want 0, stderr=%q", code, listenerStderrBuf.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runListen() did not return after sender completed")
	}

	return listenerStdoutBuf.String(), listenerStderrBuf.String(), senderStderrBuf.String(), issuedToken
}

func waitForIssuedToken(t *testing.T, buf *lockedBuffer) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(buf.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, err := token.Decode(line, time.Now()); err == nil {
				return line
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("no issued token found in output %q", buf.String())
	return ""
}

func TestListenPrintTokenOnlyTargetsStdout(t *testing.T) {
	listenerStdout, listenerStderr, senderStderr, issuedToken := runRelayListenAndSend(
		t,
		[]string{"--print-token-only"},
		telemetry.LevelDefault,
		func(stdout, stderr *lockedBuffer) *lockedBuffer { return stdout },
		"hello over derp",
	)

	if !strings.HasPrefix(listenerStdout, issuedToken+"\n") {
		t.Fatalf("listener stdout = %q, want token prefix", listenerStdout)
	}
	if !strings.HasSuffix(listenerStdout, "hello over derp") {
		t.Fatalf("listener stdout = %q, want payload suffix", listenerStdout)
	}
	if strings.Contains(listenerStderr, issuedToken) {
		t.Fatalf("listener stderr = %q, want token only on stdout", listenerStderr)
	}
	if got := listenerStderr; got != "waiting-for-claim\nconnected-relay\nstream-complete\n" {
		t.Fatalf("listener stderr = %q, want status-only stderr", got)
	}
	if got := senderStderr; got != "probing-direct\nconnected-relay\nstream-complete\n" {
		t.Fatalf("sender stderr = %q, want relay status sequence", got)
	}
}

func TestListenWithoutFlagsUsesStderrForTokenAndStdoutForPayload(t *testing.T) {
	listenerStdout, listenerStderr, senderStderr, issuedToken := runRelayListenAndSend(
		t,
		nil,
		telemetry.LevelDefault,
		func(stdout, stderr *lockedBuffer) *lockedBuffer { return stderr },
		"hello over derp",
	)

	if got := listenerStdout; got != "hello over derp" {
		t.Fatalf("listener stdout = %q, want payload", got)
	}
	if !strings.Contains(listenerStderr, "waiting-for-claim\n"+issuedToken+"\nconnected-relay\nstream-complete\n") {
		t.Fatalf("listener stderr = %q, want token and statuses on stderr", listenerStderr)
	}
	if got := senderStderr; got != "probing-direct\nconnected-relay\nstream-complete\n" {
		t.Fatalf("sender stderr = %q, want relay status sequence", got)
	}
}

func TestListenHelpTargetsCanonicalUsage(t *testing.T) {
	for _, args := range [][]string{{"listen", "-h"}, {"listen", "--help"}} {
		t.Run(args[1], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
				testListenHelpConfig(),
				"listen",
				struct{}{},
				listenHelpFlags{},
				struct{}{},
			); got != want {
				t.Fatalf("stderr = %q, want yargs help %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestListenHelpEqualsFalseTargetsCanonicalUsage(t *testing.T) {
	for _, args := range [][]string{{"listen", "-h=false"}, {"listen", "--help=false"}} {
		t.Run(args[1], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- run(args, nil, &stdout, &stderr)
			}()

			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("run() = %d, want 0", code)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("run() did not return help output for explicit false help flag")
			}

			if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
				testListenHelpConfig(),
				"listen",
				struct{}{},
				listenHelpFlags{},
				struct{}{},
			); got != want {
				t.Fatalf("stderr = %q, want yargs help %q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestListenHelpLLMTargetsCanonicalOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"listen", "--help-llm"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelpLLM(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want yargs LLM help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenRejectsStrayPositionalArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"extra"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want yargs help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenRejectsStrayPositionalArgsEvenWithHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"extra", "--help"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want yargs help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenRejectsStrayPositionalArgsBeforeLateFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"extra", "--bogus"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	got := stderr.String()
	if strings.Contains(got, "unknown flag: --bogus") || strings.Contains(got, "flag provided but not defined") {
		t.Fatalf("stderr = %q, want stray positional handling rather than parse error", got)
	}
	if got, want := got, yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want yargs help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenUnknownFlagShowsParseErrorAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"--bogus"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	wantHelp := yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	)
	got := stderr.String()
	if got != "unknown flag: --bogus\n"+wantHelp {
		t.Fatalf("stderr = %q, want yargs parse error plus help %q", got, "unknown flag: --bogus\n"+wantHelp)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenUnknownFlagBeforeHelpShowsParseErrorAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"--bogus", "--help"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	wantHelp := yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	)
	got := stderr.String()
	if got != "unknown flag: --bogus\n"+wantHelp {
		t.Fatalf("stderr = %q, want yargs parse error plus help %q", got, "unknown flag: --bogus\n"+wantHelp)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenTreatsHelpAfterDoubleDashAsPositional(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"--", "extra", "--help"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want yargs help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenTreatsBareHelpAfterDoubleDashAsPositional(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"--", "--help"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got, want := stderr.String(), yargs.GenerateSubCommandHelp(
		testListenHelpConfig(),
		"listen",
		struct{}{},
		listenHelpFlags{},
		struct{}{},
	); got != want {
		t.Fatalf("stderr = %q, want yargs help %q", got, want)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestListenRequestedHelpIgnoresConsumedStringFlagValue(t *testing.T) {
	helpLLM, help := listenRequestedHelp([]string{"--tcp-listen", "--help"})
	if helpLLM || help {
		t.Fatalf("listenRequestedHelp() = (%t, %t), want no help request when --help is consumed as a string flag value", helpLLM, help)
	}
}

func TestListenRejectsMutuallyExclusiveTCPFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"--tcp-listen", "127.0.0.1:7000", "--tcp-connect", "127.0.0.1:9000"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got := stderr.String(); got != "listen: --tcp-listen and --tcp-connect are mutually exclusive\n" {
		t.Fatalf("stderr = %q, want mutual exclusion error", got)
	}
}

func TestListenHonorsVerbosityLevel(t *testing.T) {
	tests := []struct {
		name       string
		level      telemetry.Level
		wantStderr string
	}{
		{name: "default", level: telemetry.LevelDefault, wantStderr: "waiting-for-claim\n"},
		{name: "quiet", level: telemetry.LevelQuiet, wantStderr: ""},
		{name: "silent", level: telemetry.LevelSilent, wantStderr: ""},
		{name: "verbose", level: telemetry.LevelVerbose, wantStderr: "waiting-for-claim\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, listenerStderr, _, issuedToken := runRelayListenAndSend(
				t,
				nil,
				tc.level,
				func(stdout, stderr *lockedBuffer) *lockedBuffer { return stderr },
				"payload",
			)
			if tc.wantStderr == "" {
				if got, want := listenerStderr, issuedToken+"\n"; got != want {
					t.Fatalf("listener stderr = %q, want token only on stderr %q", got, want)
				}
				return
			}
			if !strings.Contains(listenerStderr, issuedToken+"\n") {
				t.Fatalf("listener stderr = %q, want token on stderr", listenerStderr)
			}
			if !strings.HasPrefix(listenerStderr, tc.wantStderr) {
				t.Fatalf("listener stderr = %q, want prefix %q", listenerStderr, tc.wantStderr)
			}
		})
	}
}

func testListenHelpConfig() yargs.HelpConfig {
	return yargs.HelpConfig{
		Command: yargs.CommandInfo{
			Name:        "derpcat",
			Description: "Move one byte stream between hosts over public DERP with direct UDP promotion when available.",
			Examples: []string{
				"derpcat listen",
				"cat file | derpcat send <token>",
				"derpcat version",
			},
		},
		SubCommands: map[string]yargs.SubCommandInfo{
			"listen": {
				Name:        "listen",
				Description: "Listen for one incoming derpcat session and receive data.",
				Usage:       "[--print-token-only] [--tcp-listen addr | --tcp-connect addr] [--force-relay]",
				Examples: []string{
					"derpcat listen",
					"derpcat listen --tcp-connect 127.0.0.1:9000",
				},
			},
		},
	}
}

type listenHelpFlags struct {
	PrintTokenOnly bool   `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool   `flag:"force-relay" help:"Disable direct probing"`
	TCPListen      string `flag:"tcp-listen" help:"Accept one local TCP connection and forward its bytes to the session sink"`
	TCPConnect     string `flag:"tcp-connect" help:"Connect to a local TCP service and forward session bytes to it"`
}
