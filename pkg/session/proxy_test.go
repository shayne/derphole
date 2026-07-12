// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
)

const sessionProxyTarget = "derp.proxy-test.invalid:80"

type sessionProxyFixture struct {
	mapURL   string
	proxyURL string
	connects atomic.Int64

	mu      sync.Mutex
	tunnels map[net.Conn]struct{}
}

func newSessionProxyFixture(t *testing.T) *sessionProxyFixture {
	t.Helper()

	srv := newSessionTestDERPServer(t)
	derpURL, err := url.Parse(srv.DERPURL)
	if err != nil {
		t.Fatalf("url.Parse(DERPURL) error = %v", err)
	}

	fixture := &sessionProxyFixture{
		mapURL:  srv.MapURL,
		tunnels: make(map[net.Conn]struct{}),
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.serveCONNECT(w, r, derpURL.Host)
	}))
	fixture.proxyURL = proxy.URL
	t.Cleanup(func() {
		fixture.closeTunnels()
		proxy.Close()
	})
	return fixture
}

func (f *sessionProxyFixture) serveCONNECT(w http.ResponseWriter, r *http.Request, upstreamAddr string) {
	if r.Method != http.MethodConnect || r.Host != sessionProxyTarget {
		http.Error(w, "unexpected CONNECT target", http.StatusBadGateway)
		return
	}
	upstream, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	f.trackTunnels(client, upstream)
	closeTunnel := sync.OnceFunc(func() {
		_ = client.Close()
		_ = upstream.Close()
		f.untrackTunnels(client, upstream)
	})
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		closeTunnel()
		return
	}
	if err := rw.Flush(); err != nil {
		closeTunnel()
		return
	}
	f.connects.Add(1)
	go func() {
		_, _ = io.Copy(upstream, rw)
		closeTunnel()
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		closeTunnel()
	}()
}

func (f *sessionProxyFixture) trackTunnels(conns ...net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, conn := range conns {
		f.tunnels[conn] = struct{}{}
	}
}

func (f *sessionProxyFixture) untrackTunnels(conns ...net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, conn := range conns {
		delete(f.tunnels, conn)
	}
}

func (f *sessionProxyFixture) closeTunnels() {
	f.mu.Lock()
	conns := make([]net.Conn, 0, len(f.tunnels))
	for conn := range f.tunnels {
		conns = append(conns, conn)
	}
	f.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (f *sessionProxyFixture) ConnectCount() int64 {
	return f.connects.Load()
}

func TestPublicRelayRoundTripThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	runSessionProxySubprocess(t, fixture, "public-relay")
	if got := fixture.ConnectCount(); got < 2 {
		t.Fatalf("CONNECT count = %d, want at least 2", got)
	}
}

func TestDerptunAppStreamRoundTripThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	runSessionProxySubprocess(t, fixture, "derptun-app")
	if got := fixture.ConnectCount(); got < 2 {
		t.Fatalf("CONNECT count = %d, want at least 2", got)
	}
}

func TestExternalV2OfferReceivePromotesToDirectWhenBothSidesReadyThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	runSessionProxySubprocess(t, fixture, "direct-promotion")
	if got := fixture.ConnectCount(); got < 2 {
		t.Fatalf("CONNECT count = %d, want at least 2", got)
	}
}

func runSessionProxySubprocess(t *testing.T, fixture *sessionProxyFixture, scenario string) {
	t.Helper()

	updates := map[string]string{
		"DERPHOLE_SESSION_PROXY_SCENARIO":          scenario,
		"DERPHOLE_TEST_DERP_MAP_URL":               fixture.mapURL,
		"DERPHOLE_TEST_DERP_SERVER_URL":            "http://" + sessionProxyTarget + "/derp",
		"DERPHOLE_FAKE_TRANSPORT":                  "",
		"DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT": "",
		"HTTP_PROXY":     fixture.proxyURL,
		"http_proxy":     fixture.proxyURL,
		"HTTPS_PROXY":    "",
		"https_proxy":    "",
		"NO_PROXY":       "",
		"no_proxy":       "",
		"REQUEST_METHOD": "",
	}
	if scenario == "direct-promotion" {
		updates["DERPHOLE_FAKE_TRANSPORT"] = "1"
		updates["DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT"] = "0"
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSessionProxySubprocess$", "-test.v", "-test.timeout=45s")
	cmd.Env = sessionProxySubprocessEnv(os.Environ(), updates)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("session proxy subprocess %q failed: %v\n%s", scenario, err, output)
	}
}

func sessionProxySubprocessEnv(base []string, updates map[string]string) []string {
	env := make([]string, 0, len(base)+len(updates))
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		if _, replace := updates[key]; !replace {
			env = append(env, item)
		}
	}
	for key, value := range updates {
		env = append(env, key+"="+value)
	}
	return env
}

func TestSessionProxySubprocess(t *testing.T) {
	switch os.Getenv("DERPHOLE_SESSION_PROXY_SCENARIO") {
	case "public-relay":
		testPublicRelayThroughProxy(t)
	case "derptun-app":
		testDerptunAppThroughProxy(t)
	case "direct-promotion":
		testExternalV2OfferReceivePromotesToDirectWhenBothSidesReady(t)
	default:
		t.Skip("subprocess helper")
	}
}

func testPublicRelayThroughProxy(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerDebug, senderDebug syncBuffer
	tokens := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerDebug, telemetry.LevelVerbose),
			TokenSink:     tokens,
			StdioOut:      &listenerOut,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var tok string
	select {
	case tok = <-tokens:
	case err := <-listenErr:
		t.Fatalf("Listen() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}
	if err := Send(ctx, SendConfig{
		Token:         tok,
		Emitter:       telemetry.New(&senderDebug, telemetry.LevelVerbose),
		StdioIn:       strings.NewReader("through proxy"),
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if got := listenerOut.String(); got != "through proxy" {
		t.Fatalf("output = %q, want %q", got, "through proxy")
	}
	assertProxyDebug(t, "listener", listenerDebug.String())
	assertProxyDebug(t, "sender", senderDebug.String())
}

func assertProxyDebug(t *testing.T, name, got string) {
	t.Helper()
	if !strings.Contains(got, "derp-proxy=http://") || !strings.Contains(got, "target="+sessionProxyTarget) {
		t.Fatalf("%s diagnostics missing proxy details: %q", name, got)
	}
	if strings.Contains(got, "@") {
		t.Fatalf("%s diagnostics contain proxy userinfo: %q", name, got)
	}
}

func testDerptunAppThroughProxy(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverToken, clientToken := derptunServerAndClientTokens(t)
	accepted := make(chan struct{})
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunAppServe(ctx, DerptunAppServeConfig{
			ServerToken: serverToken,
			ForceRelay:  true,
			OnMux: func(ctx context.Context, mux *derptun.Mux) error {
				conn, err := mux.Accept(ctx)
				if err != nil {
					return err
				}
				defer conn.Close()
				close(accepted)
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					return err
				}
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return err
				}
				if _, err := io.WriteString(conn, "echo: "+line); err != nil {
					return err
				}
				<-ctx.Done()
				return ctx.Err()
			},
		})
	}()

	conn, cleanup, err := DerptunAppDialStream(ctx, DerptunAppDialConfig{
		ClientToken: clientToken,
		ForceRelay:  true,
	})
	if err != nil {
		t.Fatalf("DerptunAppDialStream() error = %v", err)
	}
	defer cleanup()
	defer conn.Close()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatalf("app stream not accepted: %v", ctx.Err())
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "derpssh transport\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "echo: derpssh transport\n" {
		t.Fatalf("line = %q, want echo response", line)
	}
	cancel()
	if err := <-serveErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serve error = %v", err)
	}
}
