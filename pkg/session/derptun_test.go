package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
)

func derptunServerAndClientTokens(t *testing.T) (string, string) {
	t.Helper()
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		Now:         now,
		ServerToken: server,
		Days:        1,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return server, client
}

func TestDerptunOpenForwardsTCPToServedTarget(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{ClientToken: clientToken, ListenAddr: "127.0.0.1:0", BindAddrSink: bindCh})
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
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend})
	}()
	var out strings.Builder
	err := DerptunConnect(ctx, DerptunConnectConfig{
		ClientToken: clientToken,
		StdioIn:     strings.NewReader("hello\n"),
		StdioOut:    &out,
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
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()

	for _, line := range []string{"first\n", "second\n"} {
		var out strings.Builder
		connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
		err := DerptunConnect(connectCtx, DerptunConnectConfig{
			ClientToken: clientToken,
			StdioIn:     strings.NewReader(line),
			StdioOut:    &out,
			ForceRelay:  true,
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
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()

	firstInput, firstInputWriter := io.Pipe()
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- DerptunConnect(ctx, DerptunConnectConfig{
			ClientToken: clientToken,
			StdioIn:     firstInput,
			StdioOut:    io.Discard,
			ForceRelay:  true,
		})
	}()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("first connector did not reach backend")
	}

	secondCtx, secondCancel := context.WithTimeout(ctx, 5*time.Second)
	defer secondCancel()
	err := DerptunConnect(secondCtx, DerptunConnectConfig{
		ClientToken: clientToken,
		StdioIn:     strings.NewReader("second\n"),
		StdioOut:    io.Discard,
		ForceRelay:  true,
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

func TestDerptunRejectsWrongTokenRoles(t *testing.T) {
	serverToken, clientToken := derptunServerAndClientTokens(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := DerptunServe(ctx, DerptunServeConfig{ServerToken: clientToken, TargetAddr: "127.0.0.1:22"}); !errors.Is(err, derptun.ErrInvalidToken) {
		t.Fatalf("DerptunServe(client) error = %v, want ErrInvalidToken", err)
	}
	if err := DerptunConnect(ctx, DerptunConnectConfig{ClientToken: serverToken, StdioIn: strings.NewReader("x"), StdioOut: io.Discard}); !errors.Is(err, derptun.ErrInvalidToken) {
		t.Fatalf("DerptunConnect(server) error = %v, want ErrInvalidToken", err)
	}
}

func TestRecoverStaleDerptunActiveReleasesUnresponsiveClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	now := time.Now()
	tok := derptunTestToken(now.Add(time.Minute))
	gate := &derptunClientGate{}
	first := derptunTestClaim(tok, 11)
	if _, err := gate.Accept(now, tok, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: time.Second})
	defer mux.Close()
	mux.ReplaceCarrier(newSessionNoReplyCarrier())

	activeCtx, activeCancel := context.WithCancel(ctx)
	active := &derptunServeActive{
		claim:  first,
		mux:    mux,
		cancel: activeCancel,
		done:   make(chan error, 1),
	}
	go func() {
		<-activeCtx.Done()
		active.done <- activeCtx.Err()
	}()

	second := derptunTestClaim(tok, 22)
	if _, err := gate.Accept(now, tok, second); !errors.Is(err, rendezvous.ErrClaimed) {
		t.Fatalf("second Accept() error = %v, want %v", err, rendezvous.ErrClaimed)
	}

	recovered, err := recoverStaleDerptunActive(ctx, nil, gate, active, 50*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("recoverStaleDerptunActive() error = %v", err)
	}
	if !recovered {
		t.Fatal("recoverStaleDerptunActive() recovered = false, want true")
	}

	decision, err := gate.Accept(now, tok, second)
	if err != nil {
		t.Fatalf("second Accept() after recovery error = %v", err)
	}
	if !decision.Accepted {
		t.Fatal("second Accept() after recovery rejected, want accepted")
	}
}

func TestRecoverStaleDerptunActiveKeepsResponsiveClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	now := time.Now()
	tok := derptunTestToken(now.Add(time.Minute))
	gate := &derptunClientGate{}
	first := derptunTestClaim(tok, 33)
	if _, err := gate.Accept(now, tok, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	clientMux, serverMux := newSessionMuxPair(t, time.Second)
	defer clientMux.Close()
	defer serverMux.Close()
	active := &derptunServeActive{
		claim:  first,
		mux:    serverMux,
		cancel: func() {},
		done:   make(chan error, 1),
	}

	recovered, err := recoverStaleDerptunActive(ctx, nil, gate, active, 200*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("recoverStaleDerptunActive() error = %v", err)
	}
	if recovered {
		t.Fatal("recoverStaleDerptunActive() recovered = true, want false")
	}

	second := derptunTestClaim(tok, 44)
	if _, err := gate.Accept(now, tok, second); !errors.Is(err, rendezvous.ErrClaimed) {
		t.Fatalf("second Accept() error = %v, want %v", err, rendezvous.ErrClaimed)
	}
}

func TestRecoverStaleDerptunActiveReleasesClosedTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	now := time.Now()
	tok := derptunTestToken(now.Add(time.Minute))
	gate := &derptunClientGate{}
	first := derptunTestClaim(tok, 77)
	if _, err := gate.Accept(now, tok, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	quicDone := make(chan struct{})
	close(quicDone)
	active := &derptunServeActive{
		claim:    first,
		quicDone: quicDone,
		cancel:   func() {},
		done:     make(chan error, 1),
	}
	active.done <- context.Canceled

	recovered, err := recoverStaleDerptunActive(ctx, nil, gate, active, 200*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("recoverStaleDerptunActive() error = %v", err)
	}
	if !recovered {
		t.Fatal("recoverStaleDerptunActive() recovered = false, want true")
	}

	second := derptunTestClaim(tok, 88)
	decision, err := gate.Accept(now, tok, second)
	if err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatal("second Accept() rejected after closed transport recovery")
	}
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

func TestServeDerptunMuxTargetRemovesStreamWhenBackendCloses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := startCountingEchoServer(t, 3)
	clientCarrier, serverCarrier := net.Pipe()
	clientMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: time.Second})
	serverMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: time.Second})
	defer clientMux.Close()
	defer serverMux.Close()
	clientMux.ReplaceCarrier(clientCarrier)
	serverMux.ReplaceCarrier(serverCarrier)

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveDerptunMuxTarget(ctx, serverMux, backend, nil)
	}()

	conn, err := clientMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	reader := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		if _, err := io.WriteString(conn, "ping\n"); err != nil {
			t.Fatalf("WriteString(%d) error = %v", i, err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("ReadString(%d) error = %v", i, err)
		}
		if line != "pong\n" {
			t.Fatalf("line(%d) = %q, want pong", i, line)
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() error = nil, want backend close")
	}
	waitForMuxStreamCount(t, serverMux, 0)

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

func startCountingEchoServer(t *testing.T, closeAfter int) string {
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
				scanner := bufio.NewScanner(conn)
				for count := 1; scanner.Scan(); count++ {
					_, _ = io.WriteString(conn, "pong\n")
					if count >= closeAfter {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
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

func waitForMuxStreamCount(t *testing.T, mux *derptun.Mux, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := mux.ActiveStreamCount(); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ActiveStreamCount() = %d, want %d", mux.ActiveStreamCount(), want)
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

func derptunTestToken(expires time.Time) token.Token {
	return token.Token{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8},
		ExpiresUnix:  expires.Unix(),
		BearerSecret: [32]byte{9, 8, 7, 6, 5, 4, 3, 2},
		Capabilities: token.CapabilityDerptunTCP,
	}
}

func derptunTestClaim(tok token.Token, marker byte) rendezvous.Claim {
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   [32]byte{marker},
		QUICPublic:   [32]byte{marker + 1},
		Candidates:   []string{"udp4:203.0.113.10:12345"},
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}

func newSessionMuxPair(t *testing.T, reconnectTimeout time.Duration) (*derptun.Mux, *derptun.Mux) {
	t.Helper()

	clientCarrier, serverCarrier := net.Pipe()
	clientMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: reconnectTimeout})
	serverMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: reconnectTimeout})
	clientMux.ReplaceCarrier(clientCarrier)
	serverMux.ReplaceCarrier(serverCarrier)
	return clientMux, serverMux
}

type sessionNoReplyCarrier struct {
	closed chan struct{}
	once   sync.Once
}

func newSessionNoReplyCarrier() *sessionNoReplyCarrier {
	return &sessionNoReplyCarrier{closed: make(chan struct{})}
}

func (c *sessionNoReplyCarrier) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *sessionNoReplyCarrier) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *sessionNoReplyCarrier) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}
