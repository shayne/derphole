package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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

func TestListenReportsRelayThenDirectWhenTransportUpgrades(t *testing.T) {
	listenerStderr, senderStderr := runUpgradingExternalListenAndSend(t)

	assertStatusLinesExact(t, listenerStderr, "listener stderr", "waiting-for-claim", "connected-relay", "connected-direct", "stream-complete")
	assertStatusLinesPrefix(t, senderStderr, "sender stderr", "probing-direct", "connected-relay", "connected-direct")
}

func TestListenHelpTargetsCanonicalUsage(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runListen(args, telemetry.LevelDefault, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runListen() = %d, want 0", code)
			}
			if got, want := stderr.String(), listenHelpText(); got != want {
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
	code := runListen([]string{"--help-llm"}, telemetry.LevelDefault, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runListen() = %d, want 0", code)
	}
	if got, want := stderr.String(), listenHelpLLMText(); got != want {
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
	if got, want := stderr.String(), listenHelpText(); got != want {
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
	got := stderr.String()
	if got != "unknown flag: --bogus\n"+listenHelpText() {
		t.Fatalf("stderr = %q, want yargs parse error plus help %q", got, "unknown flag: --bogus\n"+listenHelpText())
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

func runUpgradingExternalListenAndSend(t *testing.T) (listenerStderr string, senderStderr string) {
	t.Helper()

	srv := newCommandTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))
	t.Setenv("DERPCAT_TEST_LOCAL_RELAY", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withCommandContext(t, ctx)

	listenerStdoutBuf := &lockedBuffer{}
	listenerStderrBuf := &lockedBuffer{}
	listenerDone := make(chan int, 1)
	go func() {
		listenerDone <- runListen(nil, telemetry.LevelDefault, listenerStdoutBuf, listenerStderrBuf)
	}()

	issuedToken := waitForIssuedToken(t, listenerStderrBuf)

	var senderStdout bytes.Buffer
	var senderStderrBuf lockedBuffer
	releaseEOF := make(chan struct{})
	senderDone := make(chan int, 1)
	go func() {
		senderDone <- runSend([]string{issuedToken}, telemetry.LevelDefault, &directGateReader{
			ctx:        ctx,
			payload:    []byte("upgrade-me"),
			releaseEOF: releaseEOF,
		}, &senderStdout, &senderStderrBuf)
	}()

	waitForStatusPrefix(t, listenerStderrBuf, 10*time.Second, "waiting-for-claim", "connected-relay")
	waitForStatusPrefix(t, &senderStderrBuf, 10*time.Second, "probing-direct", "connected-relay")

	if err := os.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0"); err != nil {
		t.Fatalf("Setenv(enable direct) error = %v", err)
	}

	waitForStatusPrefix(t, listenerStderrBuf, 10*time.Second, "waiting-for-claim", "connected-relay", "connected-direct")
	waitForStatusPrefix(t, &senderStderrBuf, 10*time.Second, "probing-direct", "connected-relay", "connected-direct")
	close(releaseEOF)

	select {
	case code := <-listenerDone:
		if code != 0 {
			t.Fatalf("runListen() = %d, want 0, stderr=%q", code, listenerStderrBuf.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runListen() did not return after sender completed")
	}

	if got := listenerStdoutBuf.String(); got != "upgrade-me" {
		t.Fatalf("listener stdout = %q, want %q", got, "upgrade-me")
	}

	sendGrace := time.NewTimer(3 * time.Second)
	defer sendGrace.Stop()
	select {
	case code := <-senderDone:
		if code != 0 {
			t.Fatalf("runSend() = %d, want 0, stderr=%q", code, senderStderrBuf.String())
		}
	case <-sendGrace.C:
		cancel()
		code := <-senderDone
		if code != 1 {
			t.Fatalf("runSend() after cancel = %d, want 1, stderr=%q", code, senderStderrBuf.String())
		}
		if !strings.Contains(senderStderrBuf.String(), "context canceled\n") {
			t.Fatalf("sender stderr = %q, want cancellation after listener completion", senderStderrBuf.String())
		}
	}

	if got := senderStdout.String(); got != "" {
		t.Fatalf("sender stdout = %q, want empty", got)
	}

	return listenerStderrBuf.String(), senderStderrBuf.String()
}

func withCommandContext(t *testing.T, ctx context.Context) {
	t.Helper()

	prev := commandContext
	commandContext = func() context.Context { return ctx }
	t.Cleanup(func() {
		commandContext = prev
	})
}

type outputBuffer interface {
	String() string
}

type directGateReader struct {
	ctx        context.Context
	payload    []byte
	releaseEOF <-chan struct{}
	sent       bool
}

func (r *directGateReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.payload), nil
	}
	select {
	case <-r.releaseEOF:
		return 0, io.EOF
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}

func waitForStatusPrefix(t *testing.T, buf outputBuffer, timeout time.Duration, want ...string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hasStatusPrefix(statusLines(buf.String()), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("statuses = %q, want prefix %v", buf.String(), want)
}

func assertStatusLinesExact(t *testing.T, got, label string, want ...string) {
	t.Helper()

	lines := statusLines(got)
	if len(lines) != len(want) {
		t.Fatalf("%s statuses = %q, want exact %v", label, lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("%s statuses = %q, want exact %v", label, lines, want)
		}
	}
}

func assertStatusLinesPrefix(t *testing.T, got, label string, want ...string) {
	t.Helper()

	lines := statusLines(got)
	if !hasStatusPrefix(lines, want) {
		t.Fatalf("%s statuses = %q, want prefix %v", label, lines, want)
	}
}

func hasStatusPrefix(got, want []string) bool {
	if len(got) < len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func statusLines(got string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case string(sessionStatusWaiting), string(sessionStatusProbing), string(sessionStatusRelay), string(sessionStatusDirect), string(sessionStatusComplete):
			lines = append(lines, line)
		}
	}
	return lines
}

const (
	sessionStatusWaiting  = "waiting-for-claim"
	sessionStatusProbing  = "probing-direct"
	sessionStatusRelay    = "connected-relay"
	sessionStatusDirect   = "connected-direct"
	sessionStatusComplete = "stream-complete"
)

type commandTestDERPServer struct {
	MapURL  string
	DERPURL string
}

func newCommandTestDERPServer(t *testing.T) *commandTestDERPServer {
	t.Helper()

	server := derpserver.New(key.NewNode(), t.Logf)
	t.Cleanup(func() {
		_ = server.Close()
	})

	derpHTTP := httptest.NewServer(derpserver.Handler(server))
	t.Cleanup(derpHTTP.Close)

	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Command Test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "command-test-1",
						RegionID: 1,
						HostName: "127.0.0.1",
						IPv4:     "127.0.0.1",
						STUNPort: -1,
						DERPPort: 0,
					},
				},
			},
		},
	}

	mapHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(dm)
	}))
	t.Cleanup(mapHTTP.Close)

	return &commandTestDERPServer{
		MapURL:  mapHTTP.URL,
		DERPURL: derpHTTP.URL + "/derp",
	}
}
