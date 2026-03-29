package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
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
			if got := stderr.String(); got != "usage: derpcat listen [--print-token-only]\n" {
				t.Fatalf("stderr = %q, want exact listen usage", got)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
		})
	}
}

func TestListenRejectsStrayPositionalArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"extra"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.HasPrefix(got, "usage: derpcat listen") {
		t.Fatalf("stderr = %q, want usage text", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
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
			if !strings.Contains(listenerStderr, issuedToken+"\n") {
				t.Fatalf("listener stderr = %q, want token on stderr", listenerStderr)
			}
			if !strings.HasPrefix(listenerStderr, tc.wantStderr) {
				t.Fatalf("listener stderr = %q, want prefix %q", listenerStderr, tc.wantStderr)
			}
		})
	}
}
