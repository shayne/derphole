package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shayne/derpcat/pkg/telemetry"
)

func TestSendRejectsMissingTokenArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{}, telemetry.LevelDefault, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runSend() = %d, want 2", code)
	}
	assertSendHelpText(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestSendHelpTargetsCanonicalUsage(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runSend(args, telemetry.LevelDefault, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runSend() = %d, want 0", code)
			}
			assertSendHelpText(t, stderr.String())
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestSendAllowsTokenBeforeHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{"token-value", "-h"}, telemetry.LevelDefault, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runSend() = %d, want 0", code)
	}
	assertSendHelpText(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestSendRejectsTrailingArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSend([]string{"token-value", "extra"}, telemetry.LevelDefault, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runSend() = %d, want 2", code)
	}
	assertSendHelpText(t, stderr.String())
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestSendReportsRelayThenDirectWhenTransportUpgrades(t *testing.T) {
	listenerStderr, senderStderr := runUpgradingExternalListenAndSend(t)

	assertStatusLinesExact(t, listenerStderr, "listener stderr", "waiting-for-claim", "connected-relay", "connected-direct", "stream-complete")
	assertStatusLinesPrefix(t, senderStderr, "sender stderr", "probing-direct", "connected-relay", "connected-direct")
}

func assertSendHelpText(t *testing.T, got string) {
	t.Helper()
	for _, want := range []string{
		"Send data to a derpcat listener using its token.",
		"USAGE:",
		"ARGUMENTS:",
		"TOKEN",
		"--force-relay",
		"cat file | derpcat send <token>",
		"printf 'hello' | derpcat send <token>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr = %q, want help mentioning %q", got, want)
		}
	}
}
