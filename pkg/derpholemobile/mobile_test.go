// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpholemobile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/session"
)

type testCallbacks struct {
	statuses []string
	traces   []string
	progress [][2]int64
}

func (c *testCallbacks) Status(status string) { c.statuses = append(c.statuses, status) }
func (c *testCallbacks) Trace(trace string)   { c.traces = append(c.traces, trace) }
func (c *testCallbacks) Progress(current int64, total int64) {
	c.progress = append(c.progress, [2]int64{current, total})
}

type recordingTunnelCallbacks struct {
	statuses  []string
	traces    []string
	boundAddr string
}

func (c *recordingTunnelCallbacks) Status(status string)  { c.statuses = append(c.statuses, status) }
func (c *recordingTunnelCallbacks) Trace(trace string)    { c.traces = append(c.traces, trace) }
func (c *recordingTunnelCallbacks) BoundAddr(addr string) { c.boundAddr = addr }

func TestParsePayloadClassifiesModes(t *testing.T) {
	for _, tt := range []struct {
		name   string
		raw    string
		kind   string
		token  string
		scheme string
		path   string
	}{
		{name: "file", raw: "derphole://file?v=1&token=file-token", kind: "file", token: "file-token"},
		{name: "web", raw: "derphole://web?path=%2Fadmin&scheme=http&token=dtc1_test&v=1", kind: "web", token: "dtc1_test", scheme: "http", path: "/admin"},
		{name: "tcp", raw: "derphole://tcp?v=1&token=dtc1_test", kind: "tcp", token: "dtc1_test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParsePayload(tt.raw)
			if err != nil {
				t.Fatalf("ParsePayload() error = %v", err)
			}
			if parsed.Kind() != tt.kind {
				t.Fatalf("Kind() = %q, want %q", parsed.Kind(), tt.kind)
			}
			if parsed.Token() != tt.token {
				t.Fatalf("Token() = %q, want %q", parsed.Token(), tt.token)
			}
			if parsed.Scheme() != tt.scheme {
				t.Fatalf("Scheme() = %q, want %q", parsed.Scheme(), tt.scheme)
			}
			if parsed.Path() != tt.path {
				t.Fatalf("Path() = %q, want %q", parsed.Path(), tt.path)
			}
		})
	}
}

func TestParsePayloadClassifiesCompactInviteAsTCP(t *testing.T) {
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	invite, err := derptun.EncodeClientInvite(client)
	if err != nil {
		t.Fatalf("EncodeClientInvite() error = %v", err)
	}

	parsed, err := ParsePayload(invite)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	if parsed.Kind() != "tcp" {
		t.Fatalf("Kind() = %q, want tcp", parsed.Kind())
	}
	if parsed.Token() == "" {
		t.Fatal("Token() is empty")
	}
}

func TestParseFileTokenReturnsFileToken(t *testing.T) {
	payload, err := qrpayload.EncodeFileToken("token-123")
	if err != nil {
		t.Fatalf("EncodeFileToken() error = %v", err)
	}
	got, err := ParseFileToken(payload)
	if err != nil {
		t.Fatalf("ParseFileToken() error = %v", err)
	}
	if got != "token-123" {
		t.Fatalf("ParseFileToken() = %q, want token-123", got)
	}
}

func TestParseFileTokenRejectsNonFilePayload(t *testing.T) {
	payload, err := qrpayload.EncodeTCPToken("dtc1_test")
	if err != nil {
		t.Fatalf("EncodeTCPToken() error = %v", err)
	}
	_, err = ParseFileToken(payload)
	if !errors.Is(err, qrpayload.ErrUnsupportedPayload) {
		t.Fatalf("ParseFileToken() error = %v, want %v", err, qrpayload.ErrUnsupportedPayload)
	}
}

func TestTunnelClientOpenUsesDerptunOpen(t *testing.T) {
	oldOpen := derptunOpen
	t.Cleanup(func() { derptunOpen = oldOpen })

	canceled := make(chan struct{})
	called := false
	derptunOpen = func(ctx context.Context, cfg session.DerptunOpenConfig) error {
		called = true
		if cfg.ClientToken != "dtc1_test" {
			t.Fatalf("ClientToken = %q, want dtc1_test", cfg.ClientToken)
		}
		if cfg.ListenAddr != "127.0.0.1:0" {
			t.Fatalf("ListenAddr = %q, want 127.0.0.1:0", cfg.ListenAddr)
		}
		if cfg.Emitter == nil {
			t.Fatal("Emitter is nil")
		}
		cfg.Emitter.Status("connected-direct")
		cfg.BindAddrSink <- "127.0.0.1:54321"
		<-ctx.Done()
		close(canceled)
		return nil
	}

	client := NewTunnelClient()
	callbacks := &recordingTunnelCallbacks{}
	if err := client.Open("dtc1_test", "127.0.0.1:0", callbacks); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !called {
		t.Fatal("derptunOpen was not called")
	}
	if callbacks.boundAddr != "127.0.0.1:54321" {
		t.Fatalf("boundAddr = %q, want 127.0.0.1:54321", callbacks.boundAddr)
	}
	if len(callbacks.statuses) != 1 || callbacks.statuses[0] != "connected-direct" {
		t.Fatalf("statuses = %#v, want connected-direct", callbacks.statuses)
	}

	client.Cancel()
	<-canceled
}

func TestTunnelClientOpenInviteUsesDerptunOpen(t *testing.T) {
	oldOpen := derptunOpen
	t.Cleanup(func() { derptunOpen = oldOpen })

	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	invite, err := derptun.EncodeClientInvite(clientToken)
	if err != nil {
		t.Fatalf("EncodeClientInvite() error = %v", err)
	}

	derptunOpen = func(ctx context.Context, cfg session.DerptunOpenConfig) error {
		if cfg.ClientToken == "" {
			t.Fatal("ClientToken is empty")
		}
		if cfg.ListenAddr != "127.0.0.1:0" {
			t.Fatalf("ListenAddr = %q, want 127.0.0.1:0", cfg.ListenAddr)
		}
		cfg.BindAddrSink <- "127.0.0.1:54322"
		<-ctx.Done()
		return nil
	}

	callbacks := &recordingTunnelCallbacks{}
	client := NewTunnelClient()
	if err := client.OpenInvite(invite, "127.0.0.1:0", callbacks); err != nil {
		t.Fatalf("OpenInvite() error = %v", err)
	}
	if callbacks.boundAddr != "127.0.0.1:54322" {
		t.Fatalf("boundAddr = %q, want 127.0.0.1:54322", callbacks.boundAddr)
	}
	client.Cancel()
}

func TestTunnelClientOpenReturnsFirstError(t *testing.T) {
	oldOpen := derptunOpen
	t.Cleanup(func() { derptunOpen = oldOpen })

	sentinel := errors.New("open failed")
	derptunOpen = func(context.Context, session.DerptunOpenConfig) error {
		return sentinel
	}

	err := NewTunnelClient().Open("dtc1_test", "127.0.0.1:0", &recordingTunnelCallbacks{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Open() error = %v, want %v", err, sentinel)
	}
}

func TestSingleReceivedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	got, err := singleReceivedFile(dir)
	if err != nil {
		t.Fatalf("singleReceivedFile() error = %v", err)
	}
	if got != path {
		t.Fatalf("singleReceivedFile() = %q, want %q", got, path)
	}
}

func TestReceiverCancelBeforeReceive(t *testing.T) {
	r := NewReceiver()
	r.Cancel()
	if r == nil {
		t.Fatal("NewReceiver() returned nil")
	}
}

func TestStatusWriterForwardsLines(t *testing.T) {
	cb := &testCallbacks{}
	w := callbackLineWriter{line: cb.Status}
	_, _ = w.Write([]byte("connected-relay\nconnected-direct\n"))
	if len(cb.statuses) != 2 || cb.statuses[0] != "connected-relay" || cb.statuses[1] != "connected-direct" {
		t.Fatalf("statuses = %#v", cb.statuses)
	}
}

func TestSingleReceivedFileRejectsAmbiguousDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("WriteFile(a) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("WriteFile(b) error = %v", err)
	}
	_, err := singleReceivedFile(dir)
	if !errors.Is(err, errAmbiguousReceiveOutput) {
		t.Fatalf("singleReceivedFile() error = %v, want %v", err, errAmbiguousReceiveOutput)
	}
}

func TestReceiverContextCanBeCanceled(t *testing.T) {
	r := NewReceiver()
	ctx, cancel := r.context()
	r.Cancel()
	cancel()
	if ctx.Err() == nil {
		t.Fatal("receiver context was not canceled")
	}
}

func TestReceiverUsesPerTransferDirectory(t *testing.T) {
	prev := derpholeReceive
	t.Cleanup(func() { derpholeReceive = prev })

	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, ".DS_Store"), []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile(old) error = %v", err)
	}

	var receiveDir string
	derpholeReceive = func(_ context.Context, cfg derphole.ReceiveConfig) error {
		receiveDir = cfg.OutputPath
		if receiveDir == "" || filepath.Dir(receiveDir) != parent {
			t.Fatalf("OutputPath = %q, want temp dir under %q", receiveDir, parent)
		}
		return os.WriteFile(filepath.Join(receiveDir, "payload.txt"), []byte("hello"), 0o644)
	}

	got, err := NewReceiver().Receive("token-123", parent, nil)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	want := filepath.Join(receiveDir, "payload.txt")
	if got != want {
		t.Fatalf("Receive() = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(parent, ".DS_Store")); err != nil {
		t.Fatalf("old parent file missing after receive: %v", err)
	}
}

func TestReceiverRemovesTransferDirectoryOnReceiveError(t *testing.T) {
	prev := derpholeReceive
	t.Cleanup(func() { derpholeReceive = prev })

	parent := t.TempDir()
	sentinel := errors.New("receive failed")
	var receiveDir string
	derpholeReceive = func(_ context.Context, cfg derphole.ReceiveConfig) error {
		receiveDir = cfg.OutputPath
		if err := os.WriteFile(filepath.Join(receiveDir, "partial.txt"), []byte("partial"), 0o644); err != nil {
			t.Fatalf("WriteFile(partial) error = %v", err)
		}
		return sentinel
	}

	_, err := NewReceiver().Receive("token-123", parent, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Receive() error = %v, want %v", err, sentinel)
	}
	if receiveDir == "" {
		t.Fatal("stub did not capture receive output directory")
	}
	if _, err := os.Stat(receiveDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transfer dir stat error = %v, want not exist", err)
	}
}

func TestReceiveAcceptsCanceledContext(t *testing.T) {
	r := NewReceiver()
	ctx, cancel := r.context()
	cancel()
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx.Err() = %v, want %v", err, context.Canceled)
	}
}
