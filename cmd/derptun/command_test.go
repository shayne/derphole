// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/session"
)

func TestRunServePassesServerTokenAndTCP(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		if cfg.ServerToken != serverToken {
			t.Fatalf("ServerToken = %q, want supplied server token", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:22" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:22", cfg.TargetAddr)
		}
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"serve", "--token", serverToken, "--tcp", "127.0.0.1:22"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	clientToken := extractDerptunOpenCommandToken(t, stderr.String())
	cred, err := derptun.DecodeClientToken(clientToken, time.Now())
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	assertDerivedDerptunClientCredential(t, serverToken, cred)
}

func TestRunServeWithoutTokenGeneratesEphemeralServerTokenAndPrintsOpenCommand(t *testing.T) {
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		if !strings.HasPrefix(cfg.ServerToken, derptun.ServerTokenPrefix) {
			t.Fatalf("ServerToken = %q, want %s prefix", cfg.ServerToken, derptun.ServerTokenPrefix)
		}
		if cfg.TargetAddr != "127.0.0.1:8080" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:8080", cfg.TargetAddr)
		}
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"serve", "--tcp", "127.0.0.1:8080"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	clientToken := extractDerptunOpenCommandToken(t, stderr.String())
	if _, err := derptun.DecodeClientToken(clientToken, time.Now()); err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
}

func TestRunServeReadsServerTokenFromFile(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		if cfg.ServerToken != serverToken {
			t.Fatalf("ServerToken = %q, want supplied server token", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:22" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:22", cfg.TargetAddr)
		}
		return nil
	}
	tokenPath := filepath.Join(t.TempDir(), "server.dts")
	if err := os.WriteFile(tokenPath, []byte(serverToken+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	code := run([]string{"serve", "--token-file", tokenPath, "--tcp", "127.0.0.1:22"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if _, err := derptun.DecodeClientToken(extractDerptunOpenCommandToken(t, stderr.String()), time.Now()); err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
}

func TestRunServeQREmitsClientTokenAndServesWithServerToken(t *testing.T) {
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
	clientToken := extractDerptunOpenCommandToken(t, stderr.String())
	cred, err := derptun.DecodeClientToken(clientToken, time.Now())
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	assertDerivedDerptunClientCredential(t, serverToken, cred)
	if !strings.Contains(stderr.String(), "Token: "+clientToken) {
		t.Fatalf("stderr = %q, want QR token to match open command token %q", stderr.String(), clientToken)
	}
	if strings.Contains(stderr.String(), "derphole://") {
		t.Fatalf("stderr contains removed URL payload: %q", stderr.String())
	}
}

func TestRunServeRejectsRemovedWebFlag(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	var stderr bytes.Buffer
	code := run([]string{"serve", "--token", serverToken, "--tcp", "127.0.0.1:8080", "--web"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown flag") && !strings.Contains(stderr.String(), "unsupported flag") {
		t.Fatalf("stderr = %q, want unknown or unsupported flag error", stderr.String())
	}
	if strings.Contains(stderr.String(), "--web requires --qr") {
		t.Fatalf("stderr = %q, contains removed --web requires --qr behavior", stderr.String())
	}
}

func TestRunServeHelpOmitsRemovedWebFlag(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"serve", "--help"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "--web") {
		t.Fatalf("serve help mentions removed --web flag:\n%s", stderr.String())
	}
}

func TestRunOpenPrintsBindAddress(t *testing.T) {
	clientToken := newDerptunClientToken(t)
	oldOpen := derptunOpen
	defer func() { derptunOpen = oldOpen }()
	derptunOpen = func(ctx context.Context, cfg session.DerptunOpenConfig) error {
		if cfg.ClientToken != clientToken {
			t.Fatalf("ClientToken = %q, want supplied client token", cfg.ClientToken)
		}
		if cfg.ListenAddr != "127.0.0.1:2222" {
			t.Fatalf("ListenAddr = %q, want 127.0.0.1:2222", cfg.ListenAddr)
		}
		cfg.BindAddrSink <- "127.0.0.1:2222"
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"open", "--token", clientToken, "--listen", "127.0.0.1:2222"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "listening on 127.0.0.1:2222") {
		t.Fatalf("stderr = %q, want bind address", stderr.String())
	}
}

func TestRunOpenReadsClientTokenFromStdin(t *testing.T) {
	clientToken := newDerptunClientToken(t)
	oldOpen := derptunOpen
	defer func() { derptunOpen = oldOpen }()
	derptunOpen = func(ctx context.Context, cfg session.DerptunOpenConfig) error {
		if cfg.ClientToken != clientToken {
			t.Fatalf("ClientToken = %q, want supplied client token", cfg.ClientToken)
		}
		cfg.BindAddrSink <- "127.0.0.1:2222"
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"open", "--token-stdin", "--listen", "127.0.0.1:2222"}, strings.NewReader(clientToken+"\n"), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
}

func TestRunOpenRejectsServerTokenWithRoleError(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	var stderr bytes.Buffer
	code := run([]string{"open", "--token", serverToken}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "server tokens are for derptun serve") {
		t.Fatalf("stderr = %q, want server-token role error", stderr.String())
	}
}

func TestRunConnectReadsClientTokenFromFile(t *testing.T) {
	clientToken := newDerptunClientToken(t)
	oldConnect := derptunConnect
	defer func() { derptunConnect = oldConnect }()
	derptunConnect = func(ctx context.Context, cfg session.DerptunConnectConfig) error {
		if cfg.ClientToken != clientToken {
			t.Fatalf("ClientToken = %q, want supplied client token", cfg.ClientToken)
		}
		return nil
	}
	tokenPath := filepath.Join(t.TempDir(), "client.dt1")
	if err := os.WriteFile(tokenPath, []byte(clientToken+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	code := run([]string{"connect", "--token-file", tokenPath, "--stdio"}, strings.NewReader("payload"), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunConnectRejectsMultipleTokenSources(t *testing.T) {
	clientToken := newDerptunClientToken(t)
	var stderr bytes.Buffer
	code := run([]string{"connect", "--token", clientToken, "--token-stdin", "--stdio"}, strings.NewReader(clientToken+"\n"), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "exactly one of --token, --token-file, or --token-stdin") {
		t.Fatalf("stderr = %q, want token source error", stderr.String())
	}
}

func TestRunConnectRejectsRemovedClientTokenFormat(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"connect", "--token", "dtc1_legacy", "--stdio"}, strings.NewReader("payload"), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "invalid derptun token") {
		t.Fatalf("stderr = %q, want invalid token error", stderr.String())
	}
	if strings.Contains(stderr.String(), "dtc1") || strings.Contains(stderr.String(), "legacy") {
		t.Fatalf("stderr = %q, should not mention removed format", stderr.String())
	}
}

func TestRunConnectRequiresStdio(t *testing.T) {
	clientToken := newDerptunClientToken(t)
	var stderr bytes.Buffer
	code := run([]string{"connect", "--token", clientToken}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
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

func newDerptunClientToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return client
}

func extractDerptunOpenCommandToken(t *testing.T, output string) string {
	t.Helper()
	fields := strings.Fields(output)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--token" && strings.HasPrefix(fields[i+1], derptun.ClientTokenPrefix) {
			return fields[i+1]
		}
	}
	t.Fatalf("open command token not found in output %q", output)
	return ""
}

func assertDerivedDerptunClientCredential(t *testing.T, serverToken string, clientCred derptun.ClientCredential) {
	t.Helper()
	now := time.Now()
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	if err := derptun.VerifyClientCredential(serverCred.SigningSecret, clientCred, now); err != nil {
		t.Fatalf("VerifyClientCredential() error = %v", err)
	}
}
