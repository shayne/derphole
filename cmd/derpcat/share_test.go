package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
)

func TestRunShareHelpShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"share", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	for _, want := range []string{
		"Share a local TCP service until Ctrl-C.",
		"derpcat share",
		"127.0.0.1:3000",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestShareReportsRelayThenDirectWhenTransportUpgrades(t *testing.T) {
	shareStderr, _ := runUpgradingExternalShareAndOpen(t)

	assertStatusLinesPrefix(t, shareStderr, "share stderr", "waiting-for-claim", "connected-relay", "connected-direct")
}

func runUpgradingExternalShareAndOpen(t *testing.T) (shareStderr string, openStderr string) {
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

	backendAddr := startCommandEchoServer(t, ctx)

	var shareStdout bytes.Buffer
	shareStderrBuf := &lockedBuffer{}
	shareDone := make(chan int, 1)
	go func() {
		shareDone <- runShare([]string{backendAddr}, telemetry.LevelDefault, &shareStdout, shareStderrBuf)
	}()

	issuedToken := waitForIssuedToken(t, shareStderrBuf)

	var openStdout bytes.Buffer
	openStderrBuf := &lockedBuffer{}
	openDone := make(chan int, 1)
	go func() {
		openDone <- runOpen([]string{issuedToken}, telemetry.LevelDefault, &openStdout, openStderrBuf)
	}()

	openAddr := waitForOpenBindAddr(t, openStderrBuf)
	reply, err := roundTripCommandTCP(ctx, openAddr, "relay-first")
	if err != nil {
		t.Fatalf("roundTripCommandTCP() relay error = %v", err)
	}
	if reply != "relay-first" {
		t.Fatalf("relay reply = %q, want %q", reply, "relay-first")
	}

	waitForStatusPrefix(t, shareStderrBuf, 10*time.Second, "waiting-for-claim", "connected-relay")
	waitForStatusPrefix(t, openStderrBuf, 10*time.Second, "probing-direct", "connected-relay")

	if err := os.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0"); err != nil {
		t.Fatalf("Setenv(enable direct) error = %v", err)
	}

	waitForStatusPrefix(t, shareStderrBuf, 10*time.Second, "waiting-for-claim", "connected-relay", "connected-direct")
	waitForStatusPrefix(t, openStderrBuf, 10*time.Second, "probing-direct", "connected-relay", "connected-direct")

	for _, payload := range []string{"direct-one", "direct-two", "direct-three"} {
		reply, err := roundTripCommandTCP(ctx, openAddr, payload)
		if err != nil {
			t.Fatalf("roundTripCommandTCP(%q) error = %v", payload, err)
		}
		if reply != payload {
			t.Fatalf("reply = %q, want %q", reply, payload)
		}
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("Kill(SIGINT) error = %v", err)
	}

	select {
	case code := <-openDone:
		if code != 0 {
			t.Fatalf("runOpen() = %d, want 0, stderr=%q", code, openStderrBuf.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runOpen() did not exit after cancellation")
	}

	select {
	case code := <-shareDone:
		if code != 0 {
			t.Fatalf("runShare() = %d, want 0, stderr=%q", code, shareStderrBuf.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runShare() did not exit after cancellation")
	}

	if got := shareStdout.String(); got != "" {
		t.Fatalf("share stdout = %q, want empty", got)
	}
	if got := openStdout.String(); got != "" {
		t.Fatalf("open stdout = %q, want empty", got)
	}

	cancel()
	return shareStderrBuf.String(), openStderrBuf.String()
}

func startCommandEchoServer(t *testing.T, ctx context.Context) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func waitForOpenBindAddr(t *testing.T, buf *lockedBuffer) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(buf.String(), "\n") {
			line = strings.TrimSpace(line)
			if after, ok := strings.CutPrefix(line, "listening on "); ok {
				return after
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("no open bind address found in output %q", buf.String())
	return ""
}

func roundTripCommandTCP(ctx context.Context, addr, payload string) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, payload); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
