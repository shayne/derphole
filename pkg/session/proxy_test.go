// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
)

const sessionProxyTarget = "derp.proxy-test.invalid:80"

type sessionProxyFixture struct {
	mapURL   string
	proxyURL string
	connects atomic.Int64
	mapGets  atomic.Int64

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
		tunnels: make(map[net.Conn]struct{}),
	}
	mapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mapGets.Add(1)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(srv.Map)
	}))
	fixture.mapURL = mapServer.URL
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.serveCONNECT(w, r, derpURL.Host)
	}))
	fixture.proxyURL = proxy.URL
	t.Cleanup(func() {
		fixture.closeTunnels()
		proxy.Close()
		mapServer.Close()
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

func (f *sessionProxyFixture) MapRequestCount() int64 {
	return f.mapGets.Load()
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

func TestCustomRelayRoundTripThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	runSessionProxySubprocess(t, fixture, "custom-relay")
	if got := fixture.ConnectCount(); got < 2 {
		t.Fatalf("CONNECT count = %d, want at least 2", got)
	}
	if got := fixture.MapRequestCount(); got != 0 {
		t.Fatalf("public DERP map requests = %d, want 0", got)
	}
}

func TestCustomDerptunAppStreamRoundTripThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	runSessionProxySubprocess(t, fixture, "custom-derptun-app")
	if got := fixture.ConnectCount(); got < 2 {
		t.Fatalf("CONNECT count = %d, want at least 2", got)
	}
	if got := fixture.MapRequestCount(); got != 0 {
		t.Fatalf("public DERP map requests = %d, want 0", got)
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
		derpbind.CustomDERPServerEnv:               "",
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
	if scenario == "custom-relay" || scenario == "custom-derptun-app" {
		updates[derpbind.CustomDERPServerEnv] = "https://" + sessionProxyTarget + "/derp"
		updates["HTTP_PROXY"] = sessionProxyURLWithCredentials(t, fixture.proxyURL)
		updates["http_proxy"] = updates["HTTP_PROXY"]
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

func sessionProxyURLWithCredentials(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(proxy URL) error = %v", err)
	}
	u.User = url.UserPassword("proxy-user", "proxy-secret")
	return u.String()
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
	case "custom-relay":
		testCustomRelayThroughProxy(t)
	case "custom-derptun-app":
		testCustomDerptunAppThroughProxy(t)
	case "direct-promotion":
		testExternalV2OfferReceivePromotesToDirectWhenBothSidesReady(t)
	default:
		t.Skip("subprocess helper")
	}
}

func testCustomRelayThroughProxy(t *testing.T) {
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
	assertProxyCustomProductToken(t, tok)
	t.Setenv(derpbind.CustomDERPServerEnv, "")
	if err := Send(ctx, SendConfig{
		Token:         tok,
		Emitter:       telemetry.New(&senderDebug, telemetry.LevelVerbose),
		StdioIn:       strings.NewReader("custom through proxy"),
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if got := listenerOut.String(); got != "custom through proxy" {
		t.Fatalf("output = %q, want custom through proxy", got)
	}
	assertCustomProxyDebug(t, "listener", listenerDebug.String())
	assertCustomProxyDebug(t, "sender", senderDebug.String())
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
	if strings.Contains(got, "@") || strings.Contains(got, "proxy-user") || strings.Contains(got, "proxy-secret") {
		t.Fatalf("%s diagnostics contain proxy userinfo: %q", name, got)
	}
}

func assertCustomProxyDebug(t *testing.T, name, got string) {
	t.Helper()
	assertProxyDebug(t, name, got)
	if !strings.Contains(got, "derp-route=custom derp="+sessionProxyTarget) || !strings.Contains(got, string(StateRelay)) {
		t.Fatalf("%s diagnostics missing custom relay details: %q", name, got)
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

func testCustomDerptunAppThroughProxy(t *testing.T) {
	t.Helper()
	now := time.Now()
	serverToken, err := derptun.GenerateServerTokenFromEnvironment(derptun.ServerTokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateServerTokenFromEnvironment() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: serverToken, Days: 1})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if !strings.HasPrefix(serverToken, derptun.CustomServerTokenPrefix) || !strings.HasPrefix(clientToken, derptun.CustomClientTokenPrefix) {
		t.Fatalf("custom credential prefixes = %q/%q", serverToken[:len(derptun.CustomServerTokenPrefix)], clientToken[:len(derptun.CustomClientTokenPrefix)])
	}
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	serverSession, err := serverCred.SessionToken()
	if err != nil {
		t.Fatalf("server SessionToken() error = %v", err)
	}
	assertProxyCustomProductSessionToken(t, serverSession)

	t.Setenv(derpbind.CustomDERPServerEnv, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var serverDebug, clientDebug syncBuffer
	runDerptunAppMuxStreamExchange(
		t,
		ctx,
		serverToken,
		clientToken,
		true,
		telemetry.New(&serverDebug, telemetry.LevelVerbose),
		telemetry.New(&clientDebug, telemetry.LevelVerbose),
	)
	assertCustomProxyDebug(t, "derptun app server", serverDebug.String())
	assertCustomProxyDebug(t, "derptun app client", clientDebug.String())
}

func assertProxyCustomProductToken(t *testing.T, encoded string) {
	t.Helper()
	tok, err := token.Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	assertProxyCustomProductSessionToken(t, tok)
}

func assertProxyCustomProductSessionToken(t *testing.T, tok token.Token) {
	t.Helper()
	wantRoute := derpbind.Route{Host: "derp.proxy-test.invalid", DERPPort: 80, STUNPort: derpbind.DefaultSTUNPort}
	if tok.Version != token.CustomDERPVersion || tok.DERPRoute != wantRoute {
		t.Fatalf("token version/route = %d/%+v, want v%d %+v", tok.Version, tok.DERPRoute, token.CustomDERPVersion, wantRoute)
	}
}
