package session

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
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
