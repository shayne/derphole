package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derphole/qrpayload"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/session"
)

func TestRunServePassesServerTokenAndTCP(t *testing.T) {
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		if cfg.ServerToken != "dts1_test" {
			t.Fatalf("ServerToken = %q, want dts1_test", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:22" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:22", cfg.TargetAddr)
		}
		if !cfg.UsePublicDERP {
			t.Fatal("UsePublicDERP = false, want true")
		}
		return nil
	}

	code := run([]string{"serve", "--token", "dts1_test", "--tcp", "127.0.0.1:22"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunServeReadsServerTokenFromFile(t *testing.T) {
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		if cfg.ServerToken != "dts1_file" {
			t.Fatalf("ServerToken = %q, want dts1_file", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:22" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:22", cfg.TargetAddr)
		}
		return nil
	}
	tokenPath := filepath.Join(t.TempDir(), "server.dts")
	if err := os.WriteFile(tokenPath, []byte("dts1_file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	code := run([]string{"serve", "--token-file", tokenPath, "--tcp", "127.0.0.1:22"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunServeQREmitsTCPPayloadAndServesWithServerToken(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	called := false
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		called = true
		if cfg.ServerToken != serverToken {
			t.Fatalf("ServerToken = %q, want original server token", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:8080" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:8080", cfg.TargetAddr)
		}
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"serve", "--token", serverToken, "--tcp", "127.0.0.1:8080", "--qr"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !called {
		t.Fatal("derptunServe was not called")
	}
	payload := extractDerptunQRPayload(t, stderr.String())
	if payload.Kind != qrpayload.KindTCP {
		t.Fatalf("payload.Kind = %q, want %q", payload.Kind, qrpayload.KindTCP)
	}
	assertDerivedDerptunClientToken(t, serverToken, payload.Token)
}

func TestRunServeQRWebEmitsWebPayloadAndHint(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	called := false
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		called = true
		if cfg.ServerToken != serverToken {
			t.Fatalf("ServerToken = %q, want original server token", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:8080" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:8080", cfg.TargetAddr)
		}
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"serve", "--token", serverToken, "--tcp", "127.0.0.1:8080", "--qr", "--web"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !called {
		t.Fatal("derptunServe was not called")
	}
	payload := extractDerptunQRPayload(t, stderr.String())
	if payload.Kind != qrpayload.KindWeb {
		t.Fatalf("payload.Kind = %q, want %q", payload.Kind, qrpayload.KindWeb)
	}
	if payload.Scheme != "http" || payload.Path != "/" {
		t.Fatalf("payload = %#v, want http / web payload", payload)
	}
	assertDerivedDerptunClientToken(t, serverToken, payload.Token)
	if !strings.Contains(stderr.String(), "http://127.0.0.1:8080/") {
		t.Fatalf("stderr = %q, want web URL hint", stderr.String())
	}
}

func TestRunServeWebWithoutQRReturnsUsageError(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	var stderr bytes.Buffer
	code := run([]string{"serve", "--token", serverToken, "--tcp", "127.0.0.1:8080", "--web"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--web requires --qr") {
		t.Fatalf("stderr = %q, want --web requires --qr", stderr.String())
	}
}

func TestRunOpenPrintsBindAddress(t *testing.T) {
	oldOpen := derptunOpen
	defer func() { derptunOpen = oldOpen }()
	derptunOpen = func(ctx context.Context, cfg session.DerptunOpenConfig) error {
		if cfg.ClientToken != "dtc1_test" {
			t.Fatalf("ClientToken = %q, want dtc1_test", cfg.ClientToken)
		}
		if cfg.ListenAddr != "127.0.0.1:2222" {
			t.Fatalf("ListenAddr = %q, want 127.0.0.1:2222", cfg.ListenAddr)
		}
		cfg.BindAddrSink <- "127.0.0.1:2222"
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"open", "--token", "dtc1_test", "--listen", "127.0.0.1:2222"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "listening on 127.0.0.1:2222") {
		t.Fatalf("stderr = %q, want bind address", stderr.String())
	}
}

func TestRunOpenReadsClientTokenFromStdin(t *testing.T) {
	oldOpen := derptunOpen
	defer func() { derptunOpen = oldOpen }()
	derptunOpen = func(ctx context.Context, cfg session.DerptunOpenConfig) error {
		if cfg.ClientToken != "dtc1_stdin" {
			t.Fatalf("ClientToken = %q, want dtc1_stdin", cfg.ClientToken)
		}
		cfg.BindAddrSink <- "127.0.0.1:2222"
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"open", "--token-stdin", "--listen", "127.0.0.1:2222"}, strings.NewReader("dtc1_stdin\n"), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
}

func TestRunConnectReadsClientTokenFromFile(t *testing.T) {
	oldConnect := derptunConnect
	defer func() { derptunConnect = oldConnect }()
	derptunConnect = func(ctx context.Context, cfg session.DerptunConnectConfig) error {
		if cfg.ClientToken != "dtc1_file" {
			t.Fatalf("ClientToken = %q, want dtc1_file", cfg.ClientToken)
		}
		return nil
	}
	tokenPath := filepath.Join(t.TempDir(), "client.dtc")
	if err := os.WriteFile(tokenPath, []byte("dtc1_file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	code := run([]string{"connect", "--token-file", tokenPath, "--stdio"}, strings.NewReader("payload"), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunConnectRejectsMultipleTokenSources(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"connect", "--token", "dtc1_inline", "--token-stdin", "--stdio"}, strings.NewReader("dtc1_stdin\n"), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "exactly one of --token, --token-file, or --token-stdin") {
		t.Fatalf("stderr = %q, want token source error", stderr.String())
	}
}

func TestRunConnectRequiresStdio(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"connect", "--token", "dtc1_test"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--stdio") {
		t.Fatalf("stderr = %q, want stdio usage", stderr.String())
	}
}

func newDerptunServerToken(t *testing.T) string {
	t.Helper()
	token, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	return token
}

func extractDerptunQRPayload(t *testing.T, output string) qrpayload.Payload {
	t.Helper()
	for _, field := range strings.Fields(output) {
		if !strings.HasPrefix(field, qrpayload.Scheme+"://") {
			continue
		}
		payload, err := qrpayload.Parse(strings.TrimSpace(field))
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", field, err)
		}
		return payload
	}
	t.Fatalf("QR payload not found in output %q", output)
	return qrpayload.Payload{}
}

func assertDerivedDerptunClientToken(t *testing.T, serverToken, clientToken string) {
	t.Helper()
	if clientToken == serverToken {
		t.Fatal("payload token reused server token, want derived client token")
	}
	if !strings.HasPrefix(clientToken, derptun.ClientTokenPrefix) {
		t.Fatalf("payload token = %q, want %s prefix", clientToken, derptun.ClientTokenPrefix)
	}
	now := time.Now()
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if clientCred.SessionID != serverCred.SessionID {
		t.Fatalf("client SessionID = %x, want server SessionID %x", clientCred.SessionID, serverCred.SessionID)
	}
}
