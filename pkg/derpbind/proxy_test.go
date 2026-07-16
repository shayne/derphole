// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func TestDERPProxyForURLUsesStandardEnvironment(t *testing.T) {
	if os.Getenv("DERPHOLE_PROXY_TEST_HELPER") == "1" {
		target, err := url.Parse(os.Getenv("DERPHOLE_PROXY_TEST_TARGET"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := derpProxyForURL(target)
		if os.Getenv("DERPHOLE_PROXY_TEST_WANT_ERROR") == "true" {
			if err == nil {
				t.Fatal("derpProxyForURL() error = nil")
			}
			for _, notWant := range strings.Split(os.Getenv("DERPHOLE_PROXY_TEST_NOT_WANT"), ",") {
				if notWant != "" && strings.Contains(err.Error(), notWant) {
					t.Fatalf("derpProxyForURL() error = %q, must not contain %q", err, notWant)
				}
			}
			return
		}
		if err != nil {
			t.Fatalf("derpProxyForURL() unexpected error = %v", err)
		}
		gotString := ""
		if got != nil {
			gotString = got.String()
		}
		if want := os.Getenv("DERPHOLE_PROXY_TEST_WANT"); gotString != want {
			t.Fatalf("proxy = %q, want %q", gotString, want)
		}
		return
	}

	tests := []struct {
		name          string
		target        string
		httpProxy     string
		httpsProxy    string
		noProxy       string
		httpLower     string
		httpsLower    string
		noLower       string
		requestMethod string
		want          string
		wantError     bool
		notWant       []string
	}{
		{name: "no proxy", target: "https://derp.example/derp", want: ""},
		{name: "https proxy", target: "https://derp.example/derp", httpsProxy: "http://proxy.example:3128", want: "http://proxy.example:3128"},
		{name: "http proxy ignored for https", target: "https://derp.example/derp", httpProxy: "http://fallback.example:8080", want: ""},
		{name: "https precedence", target: "https://derp.example/derp", httpProxy: "http://fallback.example:8080", httpsProxy: "http://preferred.example:3128", want: "http://preferred.example:3128"},
		{name: "uppercase https precedence", target: "https://derp.example/derp", httpsProxy: "http://upper.example:3128", httpsLower: "http://lower.example:3128", want: "http://upper.example:3128"},
		{name: "lowercase https", target: "https://derp.example/derp", httpsLower: "http://lower.example:3128", want: "http://lower.example:3128"},
		{name: "lowercase no proxy", target: "https://derp.example/derp", httpsLower: "http://lower.example:3128", noLower: "derp.example", want: ""},
		{name: "no proxy exact host", target: "https://derp.example/derp", httpsProxy: "http://proxy.example:3128", noProxy: "derp.example", want: ""},
		{name: "no proxy domain", target: "https://derp.example/derp", httpsProxy: "http://proxy.example:3128", noProxy: ".example", want: ""},
		{name: "no proxy ip", target: "https://192.0.2.10/derp", httpsProxy: "http://proxy.example:3128", noProxy: "192.0.2.10", want: ""},
		{name: "no proxy cidr", target: "https://192.0.2.10/derp", httpsProxy: "http://proxy.example:3128", noProxy: "192.0.2.0/24", want: ""},
		{name: "no proxy port match", target: "https://derp.example:8443/derp", httpsProxy: "http://proxy.example:3128", noProxy: "derp.example:8443", want: ""},
		{name: "no proxy port mismatch", target: "https://derp.example:443/derp", httpsProxy: "http://proxy.example:3128", noProxy: "derp.example:8443", want: "http://proxy.example:3128"},
		{name: "loopback bypass", target: "https://127.0.0.1/derp", httpsProxy: "http://proxy.example:3128", want: ""},
		{name: "bare proxy address", target: "https://derp.example/derp", httpsProxy: "proxy.example:3128", want: "http://proxy.example:3128"},
		{name: "malformed https proxy", target: "https://derp.example/derp", httpsProxy: "http://%zz", wantError: true},
		{name: "malformed http proxy", target: "http://derp.example:3340/derp", httpProxy: "http://%zz", wantError: true},
		{name: "no proxy bypasses malformed proxy", target: "https://derp.example/derp", httpsProxy: "http://%zz", noProxy: "derp.example", want: ""},
		{name: "malformed proxy credentials are redacted", target: "https://derp.example/derp", httpsProxy: "http://alice:secret%zz@proxy.example:3128", wantError: true, notWant: []string{"alice", "secret"}},
		{name: "http target", target: "http://derp.example:3340/derp", httpProxy: "http://proxy.example:3128", want: "http://proxy.example:3128"},
		{name: "CGI refuses HTTP proxy", target: "http://derp.example:3340/derp", httpProxy: "http://proxy.example:3128", requestMethod: "GET", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestDERPProxyForURLUsesStandardEnvironment$")
			cmd.Env = proxyTestEnvironment(os.Environ())
			cmd.Env = append(cmd.Env,
				"DERPHOLE_PROXY_TEST_HELPER=1",
				"DERPHOLE_PROXY_TEST_TARGET="+tt.target,
				"DERPHOLE_PROXY_TEST_WANT="+tt.want,
				fmt.Sprintf("DERPHOLE_PROXY_TEST_WANT_ERROR=%t", tt.wantError),
				"DERPHOLE_PROXY_TEST_NOT_WANT="+strings.Join(tt.notWant, ","),
				"HTTP_PROXY="+tt.httpProxy,
				"HTTPS_PROXY="+tt.httpsProxy,
				"NO_PROXY="+tt.noProxy,
				"http_proxy="+tt.httpLower,
				"https_proxy="+tt.httpsLower,
				"no_proxy="+tt.noLower,
				"REQUEST_METHOD="+tt.requestMethod,
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("proxy test subprocess: %v\n%s", err, output)
			}
		})
	}
}

func proxyTestEnvironment(base []string) []string {
	env := make([]string, 0, len(base))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "DERPHOLE_PROXY_TEST_HELPER", "DERPHOLE_PROXY_TEST_TARGET", "DERPHOLE_PROXY_TEST_WANT",
			"DERPHOLE_PROXY_TEST_WANT_ERROR", "DERPHOLE_PROXY_TEST_NOT_WANT",
			"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "REQUEST_METHOD":
			continue
		default:
			env = append(env, entry)
		}
	}
	return env
}

func TestProxyInfoDebugStringRedactsCredentials(t *testing.T) {
	info := newProxyInfo(
		&url.URL{Scheme: "http", Host: "proxy.example:3128", User: url.UserPassword("alice", "secret")},
		"derp1.tailscale.com:443",
	)
	got := info.DebugString()
	if got != "derp-proxy=http://proxy.example:3128 target=derp1.tailscale.com:443" {
		t.Fatalf("DebugString() = %q", got)
	}
	if strings.Contains(got, "alice") || strings.Contains(got, "secret") {
		t.Fatalf("DebugString() leaked credentials: %q", got)
	}
}

func TestValidateDERPProxyURL(t *testing.T) {
	for _, raw := range []string{"socks5://proxy.example:1080", "http:///missing-host"} {
		t.Run(raw, func(t *testing.T) {
			proxyURL, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateDERPProxyURL(proxyURL); err == nil {
				t.Fatalf("validateDERPProxyURL(%q) error = nil", raw)
			}
		})
	}
}

func TestParseDERPProxy(t *testing.T) {
	tests := []struct {
		name              string
		raw               string
		want              string
		wantParseError    bool
		wantValidateError bool
	}{
		{name: "full URL", raw: "https://proxy.example:8443", want: "https://proxy.example:8443"},
		{name: "bare host", raw: "proxy.example:3128", want: "http://proxy.example:3128"},
		{name: "invalid value", raw: "http://%zz", wantParseError: true},
		{name: "unsupported scheme", raw: "socks5://proxy.example:1080", want: "socks5://proxy.example:1080", wantValidateError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyURL, err := parseDERPProxy(tt.raw)
			if tt.wantParseError {
				if err == nil {
					t.Fatalf("parseDERPProxy(%q) error = nil", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDERPProxy(%q) error = %v", tt.raw, err)
			}
			if got := proxyURL.String(); got != tt.want {
				t.Fatalf("parseDERPProxy(%q) = %q, want %q", tt.raw, got, tt.want)
			}
			if got := validateDERPProxyURL(proxyURL); (got != nil) != tt.wantValidateError {
				t.Fatalf("validateDERPProxyURL(%q) error = %v, want error %t", tt.raw, got, tt.wantValidateError)
			}
		})
	}
}

func TestDialDERPThroughHTTPProxy(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{Status: http.StatusOK})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("alice", "secret")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, info, err := dialDERPThroughProxy(ctx, proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("dialDERPThroughProxy() error = %v", err)
	}
	defer conn.Close()

	req := proxy.Request()
	if req.Method != http.MethodConnect || req.Host != "derp.example:443" {
		t.Fatalf("CONNECT request = %s %s", req.Method, req.Host)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if got := req.Header.Get("Proxy-Authorization"); got != wantAuth {
		t.Fatalf("auth = %q, want %q", got, wantAuth)
	}
	if got := info.DebugString(); strings.Contains(got, "alice") || strings.Contains(got, "secret") {
		t.Fatalf("ProxyInfo leaked: %q", got)
	}
}

func TestDialDERPThroughHTTPProxyPreservesBufferedBytes(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{
		Status:        http.StatusOK,
		AfterResponse: []byte("DERP"),
	})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}

	conn, _, err := dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("dialDERPThroughProxy() error = %v", err)
	}
	defer conn.Close()
	got := make([]byte, len("DERP"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(got) != "DERP" {
		t.Fatalf("buffered bytes = %q, want %q", got, "DERP")
	}
}

func TestDialDERPThroughHTTPSProxy(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{
		Status: http.StatusOK,
		TLS:    true,
	})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(proxy.server.Certificate())
	oldTLSConfig := proxyTLSConfig
	proxyTLSConfig = func(host string) *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: host}
	}
	defer func() { proxyTLSConfig = oldTLSConfig }()

	conn, info, err := dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("dialDERPThroughProxy() error = %v", err)
	}
	defer conn.Close()
	if req := proxy.Request(); req.Method != http.MethodConnect || req.Host != "derp.example:443" {
		t.Fatalf("CONNECT request = %s %s", req.Method, req.Host)
	}
	if info.Scheme != "https" {
		t.Fatalf("ProxyInfo.Scheme = %q, want https", info.Scheme)
	}
}

func TestDialDERPThroughProxyRejectsIncompleteCredentials(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{Status: http.StatusOK})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.User("alice")

	_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err == nil {
		t.Fatal("dialDERPThroughProxy() error = nil")
	}
	if got, want := err.Error(), "DERP proxy credentials require username and password"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestDialDERPThroughProxyResponseErrors(t *testing.T) {
	password := "secret"
	token := base64.StdEncoding.EncodeToString([]byte("alice:" + password))
	tests := []struct {
		name       string
		status     int
		body       string
		want       []string
		notWant    []string
		maxErrSize int
	}{
		{
			name:    "authentication rejected",
			status:  http.StatusProxyAuthRequired,
			body:    "credentials rejected",
			want:    []string{"rejected authentication", "407 Proxy Authentication Required", "credentials rejected"},
			notWant: []string{"alice", password, token},
		},
		{
			name:    "connect forbidden",
			status:  http.StatusForbidden,
			body:    "policy denied",
			want:    []string{"rejected CONNECT", "403 Forbidden", "policy denied"},
			notWant: []string{"alice", password, token},
		},
		{
			name:       "bounded body",
			status:     http.StatusBadGateway,
			body:       strings.Repeat("a", 4<<10) + "never-include-this-tail",
			want:       []string{"502 Bad Gateway", "..."},
			notWant:    []string{"never-include-this-tail"},
			maxErrSize: 4600,
		},
		{
			name:    "credentials and authorization redacted",
			status:  http.StatusProxyAuthRequired,
			body:    "alice secret " + token + "\nsecond\tline\x00",
			want:    []string{"[redacted] [redacted] [redacted]", "second line"},
			notWant: []string{"alice", password, token, "\n", "\t", "\x00"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestConnectProxy(t, testConnectProxyOptions{Status: tt.status, Body: tt.body})
			proxyURL, err := url.Parse(proxy.URL())
			if err != nil {
				t.Fatal(err)
			}
			proxyURL.User = url.UserPassword("alice", password)

			_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
			if err == nil {
				t.Fatal("dialDERPThroughProxy() error = nil")
			}
			got := err.Error()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("error = %q, want substring %q", got, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("error = %q, must not contain %q", got, notWant)
				}
			}
			if tt.maxErrSize > 0 && len(got) > tt.maxErrSize {
				t.Fatalf("error length = %d, want <= %d", len(got), tt.maxErrSize)
			}
		})
	}
}

func TestDialDERPThroughProxyRedactsNormalizedCredentialControls(t *testing.T) {
	tests := []struct {
		name    string
		control string
	}{
		{name: "carriage return", control: "\r"},
		{name: "line feed", control: "\n"},
		{name: "tab", control: "\t"},
		{name: "other control", control: "\x01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username := "alice" + tt.control + "admin"
			password := "secret" + tt.control + "value"
			normalizedUsername := normalizeProxyResponseSummary(username)
			normalizedPassword := normalizeProxyResponseSummary(password)
			token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			body := strings.Join([]string{username, normalizedUsername, password, normalizedPassword, token}, "|")
			proxy := newTestConnectProxy(t, testConnectProxyOptions{Status: http.StatusProxyAuthRequired, Body: body})
			proxyURL, err := url.Parse(proxy.URL())
			if err != nil {
				t.Fatal(err)
			}
			proxyURL.User = url.UserPassword(username, password)

			_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
			if err == nil {
				t.Fatal("dialDERPThroughProxy() error = nil")
			}
			got := err.Error()
			for _, secret := range []string{username, normalizedUsername, password, normalizedPassword, token} {
				if strings.Contains(got, secret) {
					t.Fatalf("error = %q, must not contain credential %q", got, secret)
				}
			}
			if count := strings.Count(got, "[redacted]"); count != 5 {
				t.Fatalf("error = %q, [redacted] count = %d, want 5", got, count)
			}
		})
	}
}

func TestDialDERPThroughProxyRedactsProxyControlledStatusReason(t *testing.T) {
	const (
		username = "alice"
		password = "secret"
	)
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	proxy := newTestConnectProxy(t, testConnectProxyOptions{
		RawResponse: fmt.Sprintf("HTTP/1.1 407 %s %s %s\r\nContent-Length: 0\r\n\r\n", username, password, token),
	})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword(username, password)

	_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err == nil {
		t.Fatal("dialDERPThroughProxy() error = nil")
	}
	got := err.Error()
	if !strings.Contains(got, "407 Proxy Authentication Required") {
		t.Fatalf("error = %q, want canonical status", got)
	}
	for _, secret := range []string{username, password, token} {
		if strings.Contains(got, secret) {
			t.Fatalf("error = %q, must not contain %q", got, secret)
		}
	}
}

func TestDialDERPThroughProxyRedactsOverlappingResponseSecrets(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		body     func(username, password, token string) string
	}{
		{
			name:     "username overlaps password",
			username: "a",
			password: "password",
			body: func(username, password, token string) string {
				return password + " " + token + " " + username
			},
		},
		{
			name:     "username overlaps Basic token",
			username: "j",
			password: "secret",
			body: func(username, password, token string) string {
				return token + " " + password + " " + username
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := base64.StdEncoding.EncodeToString([]byte(tt.username + ":" + tt.password))
			proxy := newTestConnectProxy(t, testConnectProxyOptions{
				Status: http.StatusForbidden,
				Body:   tt.body(tt.username, tt.password, token),
			})
			proxyURL, err := url.Parse(proxy.URL())
			if err != nil {
				t.Fatal(err)
			}
			proxyURL.User = url.UserPassword(tt.username, tt.password)

			_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
			if err == nil {
				t.Fatal("dialDERPThroughProxy() error = nil")
			}
			if got, want := err.Error(), ": [redacted] [redacted] [redacted]"; !strings.HasSuffix(got, want) {
				t.Fatalf("error = %q, want suffix %q", got, want)
			}
		})
	}
}

func TestDialDERPThroughProxyMalformedResponse(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{RawResponse: "not-http\r\n\r\n"})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err == nil {
		t.Fatal("dialDERPThroughProxy() error = nil")
	}
	if got := err.Error(); !strings.Contains(got, "read CONNECT from DERP proxy http://") {
		t.Fatalf("error = %q", got)
	}
}

func TestDialDERPThroughProxyPreservesResponseReadCause(t *testing.T) {
	tests := []struct {
		name       string
		options    testConnectProxyOptions
		wantCause  error
		wantDetail string
	}{
		{
			name: "empty response",
			options: testConnectProxyOptions{
				CloseWithoutResponse: map[string]bool{"derp.example:443": true},
			},
			wantCause: io.ErrUnexpectedEOF,
		},
		{
			name:      "truncated response",
			options:   testConnectProxyOptions{RawResponse: "HTTP/1.1 200"},
			wantCause: io.ErrUnexpectedEOF,
		},
		{
			name:       "malformed response",
			options:    testConnectProxyOptions{RawResponse: "not-http\r\n\r\n"},
			wantDetail: "malformed HTTP response",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestConnectProxy(t, tt.options)
			proxyURL, err := url.Parse(proxy.URL())
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
			if err == nil {
				t.Fatal("dialDERPThroughProxy() error = nil")
			}
			var responseErr *proxyConnectResponseError
			if !errors.As(err, &responseErr) {
				t.Fatalf("dialDERPThroughProxy() error = %T %v, want *proxyConnectResponseError", err, err)
			}
			if tt.wantCause != nil && !errors.Is(err, tt.wantCause) {
				t.Fatalf("dialDERPThroughProxy() error = %v, want cause %v", err, tt.wantCause)
			}
			if tt.wantDetail != "" && !strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("dialDERPThroughProxy() error = %q, want detail %q", err, tt.wantDetail)
			}
		})
	}
}

func TestRetryableProxyConnectResponseError(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "EOF", ctx: context.Background(), err: &proxyConnectResponseError{cause: io.EOF}, want: true},
		{name: "unexpected EOF", ctx: context.Background(), err: &proxyConnectResponseError{cause: io.ErrUnexpectedEOF}, want: true},
		{name: "attempt timeout", ctx: context.Background(), err: &proxyConnectResponseError{cause: context.DeadlineExceeded}, want: true},
		{name: "malformed response", ctx: context.Background(), err: &proxyConnectResponseError{cause: errors.New("malformed HTTP response")}},
		{name: "untyped EOF", ctx: context.Background(), err: io.EOF},
		{name: "caller canceled", ctx: canceledCtx, err: &proxyConnectResponseError{cause: io.EOF}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryableProxyConnectResponseError(tt.ctx, tt.err); got != tt.want {
				t.Fatalf("retryableProxyConnectResponseError() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestDialDERPThroughProxyCancellation(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{BlockResponse: true})
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := dialDERPThroughProxy(ctx, proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
		result <- err
	}()
	proxy.Request()

	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("dialDERPThroughProxy() error = nil")
		}
	case <-time.After(time.Second):
		t.Fatal("dialDERPThroughProxy() did not return after context cancellation")
	}
}

func TestDialDERPThroughProxyCancellationDuringRejectionBody(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		cancel  bool
		want    error
	}{
		{name: "canceled", context: func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, cancel: true, want: context.Canceled},
		{name: "deadline exceeded", context: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 250*time.Millisecond)
		}, want: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newTestConnectProxy(t, testConnectProxyOptions{
				Status:            http.StatusBadGateway,
				Body:              "partial rejection",
				StallResponseBody: true,
			})
			proxyURL, err := url.Parse(proxy.URL())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := tt.context()
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, _, err := dialDERPThroughProxy(ctx, proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
				result <- err
			}()
			proxy.ResponseStarted()
			if tt.cancel {
				select {
				case err := <-result:
					t.Fatalf("dialDERPThroughProxy() returned before cancellation: %v", err)
				case <-time.After(20 * time.Millisecond):
				}
				cancel()
			}

			select {
			case err := <-result:
				if !errors.Is(err, tt.want) {
					t.Fatalf("dialDERPThroughProxy() error = %v, want %v", err, tt.want)
				}
			case <-time.After(time.Second):
				t.Fatal("dialDERPThroughProxy() did not return after rejection-body cancellation")
			}
		})
	}
}

func TestSelectedProxyFailureDoesNotDialDERPDirectly(t *testing.T) {
	oldDial := derpDialContext
	defer func() { derpDialContext = oldDial }()
	var dials []string
	derpDialContext = func(_ context.Context, _ logger.Logf, _ *netmon.Monitor, _ string, addr string) (net.Conn, error) {
		dials = append(dials, addr)
		return nil, errors.New("blocked")
	}
	proxyURL, err := url.Parse("http://proxy.example:3128")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err == nil {
		t.Fatal("error = nil")
	}
	if len(dials) != 1 || dials[0] != "proxy.example:3128" {
		t.Fatalf("dials = %q, want %q", dials, []string{"proxy.example:3128"})
	}
}

type testConnectProxyOptions struct {
	Status               int
	Body                 string
	RawResponse          string
	AfterResponse        []byte
	CloseWithoutResponse map[string]bool
	BlockResponse        bool
	BlockResponseFor     map[string]bool
	StallResponseBody    bool
	TLS                  bool
	ForwardTarget        string
}

type testConnectProxy struct {
	t               *testing.T
	server          *httptest.Server
	options         testConnectProxyOptions
	reqs            chan *http.Request
	responseStarted chan struct{}
	releaseBody     chan struct{}
	mu              sync.Mutex
	conns           map[net.Conn]struct{}
	connects        int
}

func newTestConnectProxy(t *testing.T, options testConnectProxyOptions) *testConnectProxy {
	t.Helper()
	p := &testConnectProxy{
		t:               t,
		options:         options,
		reqs:            make(chan *http.Request, 64),
		responseStarted: make(chan struct{}, 64),
		releaseBody:     make(chan struct{}),
		conns:           make(map[net.Conn]struct{}),
	}
	handler := http.HandlerFunc(p.serveHTTP)
	if options.TLS {
		p.server = httptest.NewTLSServer(handler)
	} else {
		p.server = httptest.NewServer(handler)
	}
	t.Cleanup(p.close)
	return p
}

func newForwardingConnectProxy(t *testing.T, target string) *testConnectProxy {
	t.Helper()
	return newTestConnectProxy(t, testConnectProxyOptions{
		Status:        http.StatusOK,
		ForwardTarget: target,
	})
}

func (p *testConnectProxy) URL() string {
	return p.server.URL
}

func (p *testConnectProxy) Request() *http.Request {
	p.t.Helper()
	select {
	case req := <-p.reqs:
		return req
	case <-time.After(time.Second):
		p.t.Fatal("proxy did not receive CONNECT request")
		return nil
	}
}

func (p *testConnectProxy) ResponseStarted() {
	p.t.Helper()
	select {
	case <-p.responseStarted:
	case <-time.After(time.Second):
		p.t.Fatal("proxy did not start the response")
	}
}

func (p *testConnectProxy) ConnectCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connects
}

func (p *testConnectProxy) CloseConnections() {
	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.conns))
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (p *testConnectProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	req := r.Clone(context.Background())
	req.Header = r.Header.Clone()
	p.reqs <- req
	p.mu.Lock()
	p.connects++
	p.mu.Unlock()
	if p.options.CloseWithoutResponse[r.Host] {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			p.t.Errorf("ResponseWriter does not implement http.Hijacker")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			p.t.Errorf("Hijack() error = %v", err)
			return
		}
		_ = conn.Close()
		return
	}
	if p.options.BlockResponse || p.options.BlockResponseFor[r.Host] {
		<-r.Context().Done()
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.t.Errorf("ResponseWriter does not implement http.Hijacker")
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		p.t.Errorf("Hijack() error = %v", err)
		return
	}
	p.mu.Lock()
	p.conns[conn] = struct{}{}
	p.mu.Unlock()
	var targetConn net.Conn
	if p.options.ForwardTarget != "" {
		targetConn, err = net.Dial("tcp", p.options.ForwardTarget)
		if err != nil {
			_, _ = fmt.Fprintf(rw, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", http.StatusBadGateway, http.StatusText(http.StatusBadGateway))
			_ = rw.Flush()
			_ = conn.Close()
			return
		}
		p.mu.Lock()
		p.conns[targetConn] = struct{}{}
		p.mu.Unlock()
	}

	if p.options.StallResponseBody {
		status := p.options.Status
		if status == 0 {
			status = http.StatusBadGateway
		}
		_, err = fmt.Fprintf(rw, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(p.options.Body)+1, p.options.Body)
		if err == nil {
			err = rw.Flush()
		}
		if err != nil {
			p.t.Errorf("write stalled proxy response: %v", err)
			_ = conn.Close()
			return
		}
		p.responseStarted <- struct{}{}
		<-p.releaseBody
		_ = conn.Close()
		return
	}
	if p.options.RawResponse != "" {
		_, err = rw.WriteString(p.options.RawResponse)
	} else {
		status := p.options.Status
		if status == 0 {
			status = http.StatusOK
		}
		_, err = fmt.Fprintf(rw, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(p.options.Body), p.options.Body)
		if err == nil && len(p.options.AfterResponse) > 0 {
			_, err = rw.Write(p.options.AfterResponse)
		}
	}
	if err == nil {
		err = rw.Flush()
	}
	if err != nil {
		p.t.Errorf("write proxy response: %v", err)
	}
	if err == nil && targetConn != nil {
		go proxyCopy(conn, targetConn, targetConn)
		proxyCopy(targetConn, rw, conn)
	}
	if p.options.Status != http.StatusOK {
		_ = conn.Close()
	}
}

func proxyCopy(dst io.Writer, src io.Reader, closeConn net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = closeConn.Close()
}

func (p *testConnectProxy) close() {
	close(p.releaseBody)
	p.server.Close()
	p.CloseConnections()
}
