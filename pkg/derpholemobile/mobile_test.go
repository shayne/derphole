package derpholemobile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
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

func TestParsePayloadReturnsToken(t *testing.T) {
	payload, err := qrpayload.EncodeReceiveToken("token-123")
	if err != nil {
		t.Fatalf("EncodeReceiveToken() error = %v", err)
	}
	got, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	if got != "token-123" {
		t.Fatalf("ParsePayload() = %q, want token-123", got)
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
