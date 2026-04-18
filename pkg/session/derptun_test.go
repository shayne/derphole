package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
)

func TestDerptunOpenForwardsTCPToServedTarget(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{Token: tokenValue, TargetAddr: backend})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{Token: tokenValue, ListenAddr: "127.0.0.1:0", BindAddrSink: bindCh})
	}()
	bindAddr := <-bindCh
	conn, err := net.Dial("tcp", bindAddr)
	if err != nil {
		t.Fatalf("Dial(open listener) error = %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if line != "echo: ping\n" {
		t.Fatalf("line = %q, want echo: ping", line)
	}
	cancel()
	<-serveErr
	<-openErr
}

func TestDerptunConnectBridgesStdio(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{Token: tokenValue, TargetAddr: backend})
	}()
	var out strings.Builder
	err = DerptunConnect(ctx, DerptunConnectConfig{
		Token:    tokenValue,
		StdioIn:  strings.NewReader("hello\n"),
		StdioOut: &out,
	})
	if err != nil {
		t.Fatalf("DerptunConnect() error = %v", err)
	}
	if out.String() != "echo: hello\n" {
		t.Fatalf("stdout = %q, want echo: hello", out.String())
	}
	cancel()
	<-serveErr
}

func TestDerptunServeAcceptsRepeatedConnectRestarts(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{Token: tokenValue, TargetAddr: backend, ForceRelay: true})
	}()

	for _, line := range []string{"first\n", "second\n"} {
		var out strings.Builder
		connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
		err := DerptunConnect(connectCtx, DerptunConnectConfig{
			Token:      tokenValue,
			StdioIn:    strings.NewReader(line),
			StdioOut:   &out,
			ForceRelay: true,
		})
		connectCancel()
		if err != nil {
			t.Fatalf("DerptunConnect(%q) error = %v", strings.TrimSpace(line), err)
		}
		if got, want := out.String(), "echo: "+line; got != want {
			t.Fatalf("DerptunConnect(%q) stdout = %q, want %q", strings.TrimSpace(line), got, want)
		}
	}

	cancel()
	<-serveErr
}

func TestDerptunServeRejectsConcurrentConnector(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend, accepted := startHoldingTCPServer(t)
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{Token: tokenValue, TargetAddr: backend, ForceRelay: true})
	}()

	firstInput, firstInputWriter := io.Pipe()
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- DerptunConnect(ctx, DerptunConnectConfig{
			Token:      tokenValue,
			StdioIn:    firstInput,
			StdioOut:   io.Discard,
			ForceRelay: true,
		})
	}()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("first connector did not reach backend")
	}

	secondCtx, secondCancel := context.WithTimeout(ctx, time.Second)
	defer secondCancel()
	err = DerptunConnect(secondCtx, DerptunConnectConfig{
		Token:      tokenValue,
		StdioIn:    strings.NewReader("second\n"),
		StdioOut:   io.Discard,
		ForceRelay: true,
	})
	if err == nil {
		t.Fatal("second DerptunConnect() error = nil, want claimed rejection")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("second DerptunConnect() error = %v, want deterministic claimed rejection", err)
	}
	if !strings.Contains(err.Error(), "session already claimed") {
		t.Fatalf("second DerptunConnect() error = %v, want session already claimed", err)
	}

	cancel()
	_ = firstInputWriter.Close()
	<-firstErr
	<-serveErr
}

func TestServeDerptunMuxTargetAllowsOneActiveStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend, accepted := startHoldingTCPServer(t)
	clientCarrier, serverCarrier := net.Pipe()
	clientMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: time.Second})
	serverMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: time.Second})
	defer clientMux.Close()
	defer serverMux.Close()
	clientMux.ReplaceCarrier(clientCarrier)
	serverMux.ReplaceCarrier(serverCarrier)

	var debug bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveDerptunMuxTarget(ctx, serverMux, backend, telemetry.New(&debug, telemetry.LevelVerbose))
	}()

	firstConn, err := clientMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("first OpenStream() error = %v", err)
	}
	defer firstConn.Close()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("first stream did not reach backend")
	}

	secondConn, err := clientMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("second OpenStream() error = %v, want accepted then closed by server stream limit", err)
	}
	defer secondConn.Close()
	waitForBufferContains(t, &debug, "derptun-stream-limit-reached")
	select {
	case <-accepted:
		t.Fatal("second stream reached backend while first stream was still active")
	default:
	}

	if err := firstConn.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	thirdConn := openStreamUntilBackendAccepted(t, ctx, clientMux, accepted)
	defer thirdConn.Close()

	cancel()
	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serveDerptunMuxTarget() error = %v", err)
	}
}

func TestDerptunQUICConfigDetectsDeadPeersPromptly(t *testing.T) {
	cfg := derptunQUICConfig()
	if cfg.KeepAlivePeriod > 2*time.Second {
		t.Fatalf("KeepAlivePeriod = %v, want <= 2s", cfg.KeepAlivePeriod)
	}
	if cfg.MaxIdleTimeout > 10*time.Second {
		t.Fatalf("MaxIdleTimeout = %v, want <= 10s", cfg.MaxIdleTimeout)
	}
}

func TestBridgeDerptunStdioClosesInputWhenRemoteEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	local, remote := net.Pipe()
	input, inputWriter := io.Pipe()
	defer inputWriter.Close()

	done := make(chan error, 1)
	go func() {
		done <- bridgeDerptunStdio(ctx, local, input, io.Discard)
	}()

	if err := remote.Close(); err != nil {
		t.Fatalf("remote Close() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bridgeDerptunStdio() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("bridgeDerptunStdio() did not return after remote close")
	}
	if _, err := inputWriter.Write([]byte("still-open")); err == nil {
		t.Fatal("input writer remained open after bridge returned")
	}
}

func startLineEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					_, _ = io.WriteString(conn, "echo: "+line)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func startHoldingTCPServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan struct{}, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String(), accepted
}

func waitForBufferContains(t *testing.T, buf *bytes.Buffer, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("debug output = %q, want %q", buf.String(), want)
}

func openStreamUntilBackendAccepted(t *testing.T, ctx context.Context, mux *derptun.Mux, accepted <-chan struct{}) net.Conn {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := mux.OpenStream(ctx)
		if err != nil {
			t.Fatalf("OpenStream() error = %v", err)
		}
		select {
		case <-accepted:
			return conn
		case <-time.After(25 * time.Millisecond):
			_ = conn.Close()
		case <-ctx.Done():
			t.Fatal("stream did not reach backend before context expired")
		}
	}
	t.Fatal("stream did not reach backend after previous stream closed")
	return nil
}
