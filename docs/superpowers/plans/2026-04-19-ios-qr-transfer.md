# iOS QR Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a proof-of-concept Derphole iOS app that scans a terminal QR code, receives a file through the same direct-preferred Go session path as the CLI, and exports the file on iOS.

**Architecture:** Add a small versioned QR payload helper, wire `derphole send --qr` to render that payload, and expose the existing `pkg/derphole.Receive` path through a gomobile-bound `pkg/derpholemobile` adapter. SwiftUI handles scanning, receive state, permissions, and document export; Go remains responsible for token validation, transfer protocol, direct negotiation, relay fallback, and file writing.

**Tech Stack:** Go 1.26, existing Derphole `session`/`pkg/derphole` transfer code, `github.com/mdp/qrterminal/v3`, `gomobile bind`, SwiftUI, AVFoundation, UIKit document picker, `mise` tasks, Xcode iOS simulator and physical-device verification.

---

## File Structure

- Create `pkg/derphole/qrpayload/payload.go`
  - Encode and parse payloads shaped like `derphole://receive?v=1&token=TOKEN`.
  - Accept raw tokens for simulator/test support.
- Create `pkg/derphole/qrpayload/payload_test.go`
  - Unit coverage for encode, parse, raw token fallback, and malformed payloads.
- Modify `pkg/derphole/transfer.go`
  - Add `QR bool` to `SendConfig`.
  - Reject non-file QR sends before creating a receive instruction.
  - Call QR instruction output when `SendConfig.QR` is true.
  - Add optional receive progress callback plumbing for the mobile bridge.
- Modify `pkg/derphole/ui.go`
  - Add `WriteSendQRInstruction`.
- Modify `pkg/derphole/ui_test.go`
  - Test QR instruction output does not print the npm receive command.
- Modify `pkg/derphole/transfer_test.go`
  - Test file-only QR validation.
  - Test QR mode calls QR instruction output after offer token allocation.
  - Test receive progress callback wiring for file receives.
- Modify `cmd/derphole/send.go`
  - Add `--qr` flag and pass it into `pkgderphole.Send`.
- Modify `cmd/derphole/send_test.go`
  - Test help includes `--qr`.
  - Test the CLI passes `QR: true`.
- Create `pkg/derpholemobile/mobile.go`
  - Gomobile exported adapter around `pkg/derphole.Receive`.
  - Expose payload validation, blocking receive, cancellation, and callbacks.
- Create `pkg/derpholemobile/mobile_test.go`
  - Test payload validation, cancellation, callback writer behavior, and single-file result discovery.
- Modify `.mise.toml`
  - Add `apple:mobile-tools` and `apple:mobile-framework`.
  - Make `apple:build` and `apple:test` build the mobile framework first.
- Modify `apple/Derphole/Derphole.xcodeproj/project.pbxproj`
  - Reference and link the generated `dist/apple/DerpholeMobile.xcframework`.
  - Add generated Info.plist keys for camera and local-network usage.
- Create `apple/Derphole/Derphole/TransferState.swift`
  - Main app state model and gomobile callback adapter.
- Create `apple/Derphole/Derphole/QRScannerView.swift`
  - SwiftUI wrapper around AVFoundation QR scanning.
- Create `apple/Derphole/Derphole/DocumentExporter.swift`
  - SwiftUI/UIKit export wrapper for received files.
- Modify `apple/Derphole/Derphole/ContentView.swift`
  - Replace placeholder app with QR-first transfer UI and simulator payload injection.
- Modify `apple/Derphole/DerpholeTests/DerpholeTests.swift`
  - Unit tests for state transitions and invalid payload behavior.
- Modify `apple/Derphole/DerpholeUITests/DerpholeUITests.swift`
  - UI test for simulator payload entry and idle/validation states.

## Task 1: QR Payload Helper

**Files:**
- Create: `pkg/derphole/qrpayload/payload_test.go`
- Create: `pkg/derphole/qrpayload/payload.go`

- [ ] **Step 1: Write failing payload tests**

Create `pkg/derphole/qrpayload/payload_test.go`:

```go
package qrpayload

import (
	"errors"
	"strings"
	"testing"
)

func TestEncodeReceiveToken(t *testing.T) {
	got, err := EncodeReceiveToken("abc-123_DEF")
	if err != nil {
		t.Fatalf("EncodeReceiveToken() error = %v", err)
	}
	const want = "derphole://receive?v=1&token=abc-123_DEF"
	if got != want {
		t.Fatalf("EncodeReceiveToken() = %q, want %q", got, want)
	}
}

func TestEncodeReceiveTokenRejectsEmpty(t *testing.T) {
	_, err := EncodeReceiveToken(" ")
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("EncodeReceiveToken() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestParseReceivePayload(t *testing.T) {
	got, err := ParseReceivePayload("derphole://receive?v=1&token=abc-123_DEF")
	if err != nil {
		t.Fatalf("ParseReceivePayload() error = %v", err)
	}
	if got != "abc-123_DEF" {
		t.Fatalf("ParseReceivePayload() = %q, want token", got)
	}
}

func TestParseReceivePayloadAcceptsRawToken(t *testing.T) {
	got, err := ParseReceivePayload("  raw-token-123  ")
	if err != nil {
		t.Fatalf("ParseReceivePayload(raw token) error = %v", err)
	}
	if got != "raw-token-123" {
		t.Fatalf("ParseReceivePayload(raw token) = %q, want trimmed token", got)
	}
}

func TestParseReceivePayloadRejectsUnsupportedVersion(t *testing.T) {
	_, err := ParseReceivePayload("derphole://receive?v=2&token=abc")
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ParseReceivePayload() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestParseReceivePayloadRejectsInvalidURLPayloads(t *testing.T) {
	for _, input := range []string{
		"",
		"derphole://receive?v=1",
		"derphole://send?v=1&token=abc",
		"https://example.com/receive?v=1&token=abc",
		"derphole://receive?token=abc",
	} {
		t.Run(strings.ReplaceAll(input, "/", "_"), func(t *testing.T) {
			_, err := ParseReceivePayload(input)
			if err == nil {
				t.Fatalf("ParseReceivePayload(%q) succeeded, want error", input)
			}
		})
	}
}
```

- [ ] **Step 2: Run payload tests and verify failure**

Run:

```bash
go test ./pkg/derphole/qrpayload -count=1
```

Expected: FAIL because `pkg/derphole/qrpayload` does not exist.

- [ ] **Step 3: Implement payload helper**

Create `pkg/derphole/qrpayload/payload.go`:

```go
package qrpayload

import (
	"errors"
	"net/url"
	"strings"
)

const (
	Scheme         = "derphole"
	ReceiveHost    = "receive"
	ReceiveVersion = "1"
)

var (
	ErrMissingToken       = errors.New("missing receive token")
	ErrUnsupportedVersion = errors.New("unsupported derphole QR payload version")
	ErrUnsupportedPayload = errors.New("unsupported derphole QR payload")
)

func EncodeReceiveToken(receiveToken string) (string, error) {
	receiveToken = strings.TrimSpace(receiveToken)
	if receiveToken == "" {
		return "", ErrMissingToken
	}
	values := url.Values{}
	values.Set("v", ReceiveVersion)
	values.Set("token", receiveToken)
	return (&url.URL{Scheme: Scheme, Host: ReceiveHost, RawQuery: values.Encode()}).String(), nil
}

func ParseReceivePayload(payload string) (string, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", ErrMissingToken
	}
	if !strings.Contains(payload, "://") {
		return payload, nil
	}

	parsed, err := url.Parse(payload)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != Scheme || parsed.Host != ReceiveHost {
		return "", ErrUnsupportedPayload
	}
	values := parsed.Query()
	if got := values.Get("v"); got != ReceiveVersion {
		return "", ErrUnsupportedVersion
	}
	token := strings.TrimSpace(values.Get("token"))
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}
```

- [ ] **Step 4: Run payload tests and verify pass**

Run:

```bash
go test ./pkg/derphole/qrpayload -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit payload helper**

```bash
git add pkg/derphole/qrpayload
git commit -m "feat: add iOS QR payload helper"
```

## Task 2: CLI QR Output

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `pkg/derphole/transfer.go`
- Modify: `pkg/derphole/ui.go`
- Modify: `pkg/derphole/ui_test.go`
- Modify: `pkg/derphole/transfer_test.go`
- Modify: `cmd/derphole/send.go`
- Modify: `cmd/derphole/send_test.go`

- [ ] **Step 1: Add QR CLI tests**

In `cmd/derphole/send_test.go`, add tests after `TestSendHelpIncludesHideProgress`:

```go
func TestSendHelpIncludesQR(t *testing.T) {
	if !strings.Contains(sendHelpText(), "--qr") {
		t.Fatalf("sendHelpText() missing --qr:\n%s", sendHelpText())
	}
}

func TestRunSendPassesQRFlag(t *testing.T) {
	prev := runSendTransfer
	t.Cleanup(func() {
		runSendTransfer = prev
	})

	called := false
	runSendTransfer = func(_ context.Context, cfg pkgderphole.SendConfig) error {
		called = true
		if !cfg.QR {
			t.Fatal("cfg.QR = false, want true")
		}
		if cfg.What != "photo.jpg" {
			t.Fatalf("cfg.What = %q, want photo.jpg", cfg.What)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--qr", "photo.jpg"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, stderr.String())
	}
	if !called {
		t.Fatal("runSendTransfer was not called")
	}
}
```

- [ ] **Step 2: Add UI and transfer tests**

In `pkg/derphole/ui_test.go`, add:

```go
func TestWriteSendQRInstructionUsesAppPayload(t *testing.T) {
	var stderr bytes.Buffer
	WriteSendQRInstruction(&stderr, "token-123")

	got := stderr.String()
	if strings.Contains(got, "npx -y derphole@latest receive") {
		t.Fatalf("QR instruction printed npm command: %q", got)
	}
	for _, want := range []string{"Scan this QR code", "Derphole iOS app"} {
		if !strings.Contains(got, want) {
			t.Fatalf("QR instruction missing %q in %q", want, got)
		}
	}
}
```

Also add `strings` to the import block:

```go
import (
	"bytes"
	"strings"
	"testing"
)
```

In `pkg/derphole/transfer_test.go`, add:

```go
func TestSendQRRejectsNonFileTransfer(t *testing.T) {
	for _, cfg := range []SendConfig{
		{QR: true, Text: "hello"},
		{QR: true, What: "hello"},
		{QR: true, Stdin: strings.NewReader("hello")},
	} {
		err := Send(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "--qr only supports file sends") {
			t.Fatalf("Send(%#v) error = %v, want QR file-only error", cfg, err)
		}
	}
}

func TestSendQROfferPrintsQRInstruction(t *testing.T) {
	prev := derpholeSessionOffer
	t.Cleanup(func() {
		derpholeSessionOffer = prev
	})

	derpholeSessionOffer = func(_ context.Context, cfg session.OfferConfig) (string, error) {
		if cfg.TokenSink != nil {
			cfg.TokenSink <- "token-123"
		}
		if rc, ok := cfg.StdioIn.(io.ReadCloser); ok {
			_ = rc.Close()
		}
		return "", nil
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "photo.jpg")
	if err := os.WriteFile(path, []byte("image"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	err := Send(context.Background(), SendConfig{QR: true, What: path, Stderr: &stderr})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	got := stderr.String()
	if strings.Contains(got, "npx -y derphole@latest receive") {
		t.Fatalf("stderr contains npm receive command in QR mode: %q", got)
	}
	if !strings.Contains(got, "Scan this QR code") {
		t.Fatalf("stderr = %q, want QR instruction", got)
	}
}
```

- [ ] **Step 3: Run QR tests and verify failure**

Run:

```bash
go test ./cmd/derphole ./pkg/derphole -run 'QR|WriteSendQR|RunSendPassesQR|SendHelpIncludesQR' -count=1
```

Expected: FAIL because `SendConfig.QR`, `WriteSendQRInstruction`, and the `--qr` flag do not exist.

- [ ] **Step 4: Implement QR flag and instruction**

In `cmd/derphole/send.go`, change `sendFlags` to:

```go
type sendFlags struct {
	ForceRelay   bool `flag:"force-relay" help:"Disable direct probing"`
	HideProgress bool `flag:"hide-progress" help:"Suppress progress-bar display"`
	QR           bool `flag:"qr" help:"Render a QR code for the receive token"`
}
```

Change the send usage string:

```go
Usage: "[--force-relay] [--qr] [what]",
```

Pass the flag into `pkgderphole.SendConfig`:

```go
QR:             parsed.SubCommandFlags.QR,
ParallelPolicy: session.DefaultParallelPolicy(),
```

In `pkg/derphole/transfer.go`, add `QR bool` to `SendConfig`:

```go
type SendConfig struct {
	Token          string
	Text           string
	What           string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	ProgressOutput io.Writer
	Emitter        *telemetry.Emitter
	UsePublicDERP  bool
	ForceRelay     bool
	QR             bool
	ParallelPolicy session.ParallelPolicy
}
```

After `prepareSendTransfer(cfg)` succeeds in `Send`, add:

```go
if cfg.QR && tx.header.Kind != protocol.KindFile {
	return errors.New("--qr only supports file sends")
}
```

In `offerTransfer`, replace:

```go
WriteSendInstruction(cfg.Stderr, token)
```

with:

```go
if cfg.QR {
	WriteSendQRInstruction(cfg.Stderr, token)
} else {
	WriteSendInstruction(cfg.Stderr, token)
}
```

In `pkg/derphole/ui.go`, add imports and function:

```go
import (
	"fmt"
	"io"

	"github.com/mdp/qrterminal/v3"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
)

func WriteSendQRInstruction(stderr io.Writer, token string) {
	if stderr == nil {
		return
	}
	payload, err := qrpayload.EncodeReceiveToken(token)
	if err != nil {
		fmt.Fprintf(stderr, "Could not render QR payload: %v\n", err)
		return
	}
	fmt.Fprintln(stderr, "Scan this QR code with the Derphole iOS app:")
	qrterminal.GenerateHalfBlock(payload, qrterminal.M, stderr)
}
```

Preserve the existing `WriteSendInstruction` behavior.

- [ ] **Step 5: Add QR terminal dependency**

Run:

```bash
go get github.com/mdp/qrterminal/v3@latest
```

Expected: `go.mod` and `go.sum` include `github.com/mdp/qrterminal/v3` and its QR encoder dependency.

- [ ] **Step 6: Run QR tests and verify pass**

Run:

```bash
go test ./cmd/derphole ./pkg/derphole ./pkg/derphole/qrpayload -run 'QR|WriteSendQR|RunSendPassesQR|SendHelpIncludesQR' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit CLI QR support**

```bash
git add go.mod go.sum cmd/derphole/send.go cmd/derphole/send_test.go pkg/derphole/transfer.go pkg/derphole/transfer_test.go pkg/derphole/ui.go pkg/derphole/ui_test.go
git commit -m "feat: render iOS receive QR codes"
```

## Task 3: Receive Progress Callback And Mobile Bridge

**Files:**
- Modify: `pkg/derphole/progress.go`
- Modify: `pkg/derphole/progress_test.go`
- Modify: `pkg/derphole/transfer.go`
- Modify: `pkg/derphole/transfer_test.go`
- Create: `pkg/derpholemobile/mobile.go`
- Create: `pkg/derpholemobile/mobile_test.go`

- [ ] **Step 1: Add progress callback tests**

In `pkg/derphole/progress_test.go`, add:

```go
func TestProgressReporterCallbackRunsWithoutWriter(t *testing.T) {
	var events [][2]int64
	progress := NewProgressReporterWithCallback(nil, 10, func(current, total int64) {
		events = append(events, [2]int64{current, total})
	})
	if progress == nil {
		t.Fatal("progress = nil, want reporter when callback is set")
	}
	progress.Add(4)
	progress.Finish()

	if len(events) == 0 {
		t.Fatal("progress callback was not called")
	}
	if got := events[len(events)-1]; got != [2]int64{10, 10} {
		t.Fatalf("last progress event = %v, want [10 10]", got)
	}
}
```

In `pkg/derphole/transfer_test.go`, add:

```go
func TestReceiveFileReportsProgressCallback(t *testing.T) {
	var buf bytes.Buffer
	header := protocol.Header{Version: 1, Kind: protocol.KindFile, Name: "payload.txt", Size: 5}
	if err := protocol.WriteHeader(&buf, header); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	buf.WriteString("hello")

	var events [][2]int64
	err := readTransfer(&buf, "", io.Discard, t.TempDir(), io.Discard, nil, func(current, total int64) {
		events = append(events, [2]int64{current, total})
	})
	if err != nil {
		t.Fatalf("readTransfer() error = %v", err)
	}
	if len(events) == 0 {
		t.Fatal("progress callback was not called")
	}
	if got := events[len(events)-1]; got != [2]int64{5, 5} {
		t.Fatalf("last progress event = %v, want [5 5]", got)
	}
}
```

- [ ] **Step 2: Run progress tests and verify failure**

Run:

```bash
go test ./pkg/derphole -run 'ProgressCallback|ReceiveFileReportsProgressCallback' -count=1
```

Expected: FAIL because `NewProgressReporterWithCallback` and the extra `readTransfer` argument do not exist.

- [ ] **Step 3: Implement progress callback plumbing**

In `pkg/derphole/progress.go`, add an `onProgress` field:

```go
onProgress func(current, total int64)
```

Replace `NewProgressReporter` with:

```go
func NewProgressReporter(out io.Writer, total int64) *ProgressReporter {
	return NewProgressReporterWithCallback(out, total, nil)
}

func NewProgressReporterWithCallback(out io.Writer, total int64, onProgress func(current, total int64)) *ProgressReporter {
	if (out == nil && onProgress == nil) || total < 0 {
		return nil
	}
	now := progressNow()
	return &ProgressReporter{
		out:          out,
		total:        total,
		start:        now,
		lastRender:   now,
		lastRateTime: now,
		rateBytes:    newProgressEMA(progressRateSmoothing),
		rateSeconds:  newProgressEMA(progressRateSmoothing),
		onProgress:   onProgress,
	}
}
```

In `Add`, after `p.current += int64(n)`, call:

```go
if p.onProgress != nil {
	p.onProgress(p.current, p.total)
}
```

In `Finish`, after updating `p.current`, call:

```go
if p.onProgress != nil {
	p.onProgress(p.current, p.total)
}
```

In `renderLocked`, guard terminal writes:

```go
if p.out == nil {
	return
}
```

before `fmt.Fprintf`.

In `pkg/derphole/transfer.go`, add to `ReceiveConfig`:

```go
Progress func(current, total int64)
```

Thread `cfg.Progress` through `readTransfer`, `receiveFile`, `receiveDirectory`, and `newNativeWebFileSink`. The final signatures should be:

```go
func readTransfer(r io.Reader, token string, stdout io.Writer, outputPath string, stderr, progressOut io.Writer, progress func(current, total int64)) error
func receiveFile(r io.Reader, header protocol.Header, outputPath string, stderr, progressOut io.Writer, progress func(current, total int64)) error
func receiveDirectory(r io.Reader, header protocol.Header, outputPath string, stderr, progressOut io.Writer, progress func(current, total int64)) error
func newNativeWebFileSink(outputPath string, stderr, progressOut io.Writer, progress func(current, total int64)) *nativeWebFileSink
```

Use:

```go
progressReporter := NewProgressReporterWithCallback(progressOut, header.Size, progress)
```

and:

```go
s.progress = NewProgressReporterWithCallback(s.progressOut, meta.Size, s.onProgress)
```

Update all existing `readTransfer` call sites by passing `cfg.Progress` or `nil`.

- [ ] **Step 4: Run package tests and verify pass**

Run:

```bash
go test ./pkg/derphole -run 'ProgressCallback|ReceiveFileReportsProgressCallback|Receive|Send' -count=1
```

Expected: PASS.

- [ ] **Step 5: Write mobile bridge tests**

Create `pkg/derpholemobile/mobile_test.go`:

```go
package derpholemobile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
```

- [ ] **Step 6: Run mobile bridge tests and verify failure**

Run:

```bash
go test ./pkg/derpholemobile -count=1
```

Expected: FAIL because `pkg/derpholemobile` does not exist.

- [ ] **Step 7: Implement mobile bridge**

Create `pkg/derpholemobile/mobile.go`:

```go
package derpholemobile

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

var errAmbiguousReceiveOutput = errors.New("received output directory contains more than one file")

type Callbacks interface {
	Status(status string)
	Trace(trace string)
	Progress(current int64, total int64)
}

type Receiver struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func NewReceiver() *Receiver {
	return &Receiver{}
}

func ParsePayload(payload string) (string, error) {
	return qrpayload.ParseReceivePayload(payload)
}

func (r *Receiver) Receive(payloadOrToken string, outputDir string, callbacks Callbacks) (string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return "", errors.New("output directory is required")
	}
	token, err := ParsePayload(payloadOrToken)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	ctx, cancel := r.context()
	defer cancel()
	defer r.clearCancel(cancel)

	statusWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Status(line)
		}
	}}
	traceWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Trace(line)
		}
	}}

	err = derphole.Receive(ctx, derphole.ReceiveConfig{
		Token:          token,
		OutputPath:     outputDir,
		Stderr:         traceWriter,
		ProgressOutput: nil,
		Emitter:        telemetry.New(statusWriter, telemetry.LevelDefault),
		UsePublicDERP:  true,
		ForceRelay:     false,
		ParallelPolicy: session.DefaultParallelPolicy(),
		Progress: func(current, total int64) {
			if callbacks != nil {
				callbacks.Progress(current, total)
			}
		},
	})
	if err != nil {
		return "", err
	}
	return singleReceivedFile(outputDir)
}

func (r *Receiver) Cancel() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *Receiver) context() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.cancel = cancel
	r.mu.Unlock()
	return ctx, cancel
}

func (r *Receiver) clearCancel(cancel context.CancelFunc) {
	r.mu.Lock()
	if r.cancel == cancel {
		r.cancel = nil
	}
	r.mu.Unlock()
}

type callbackLineWriter struct {
	line func(string)
}

func (w callbackLineWriter) Write(p []byte) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(p)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && w.line != nil {
			w.line(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func singleReceivedFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	if len(files) != 1 {
		if len(files) == 0 {
			return "", io.ErrUnexpectedEOF
		}
		return "", errAmbiguousReceiveOutput
	}
	return files[0], nil
}
```

- [ ] **Step 8: Run mobile bridge tests and verify pass**

Run:

```bash
go test ./pkg/derpholemobile ./pkg/derphole -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit progress and bridge**

```bash
git add pkg/derphole/progress.go pkg/derphole/progress_test.go pkg/derphole/transfer.go pkg/derphole/transfer_test.go pkg/derpholemobile
git commit -m "feat: expose Derphole receive to iOS"
```

## Task 4: Mise Mobile Framework Tasks

**Files:**
- Modify: `.mise.toml`

- [ ] **Step 1: Add mobile task definitions**

In `.mise.toml`, add after `apple:test`:

```toml
[tasks."apple:mobile-tools"]
description = "Install gomobile tools into dist/tools/bin"
shell = "bash -c"
run = """
set -euo pipefail
tool_bin="$PWD/dist/tools/bin"
mkdir -p "$tool_bin"
GOBIN="$tool_bin" go install golang.org/x/mobile/cmd/gomobile@latest
GOBIN="$tool_bin" go install golang.org/x/mobile/cmd/gobind@latest
PATH="$tool_bin:$PATH" gomobile init
"""

[tasks."apple:mobile-framework"]
description = "Build the DerpholeMobile gomobile XCFramework"
depends = ["apple:mobile-tools"]
shell = "bash -c"
run = """
set -euo pipefail
tool_bin="$PWD/dist/tools/bin"
mkdir -p dist/apple
PATH="$tool_bin:$PATH" gomobile bind \
  -target=ios,iossimulator \
  -iosversion "${APPLE_IOS_VERSION:-17.0}" \
  -o dist/apple/DerpholeMobile.xcframework \
  ./pkg/derpholemobile
"""
```

- [ ] **Step 2: Make Apple build/test invoke mobile framework**

At the top of the `apple:build` script body, after `set -euo pipefail`, add:

```bash
mise run apple:mobile-framework
```

At the top of the `apple:test` script body, after `set -euo pipefail`, add:

```bash
mise run apple:mobile-framework
```

- [ ] **Step 3: Run mobile framework task**

Run:

```bash
mise run apple:mobile-framework
```

Expected: PASS and `dist/apple/DerpholeMobile.xcframework` exists.

- [ ] **Step 4: Commit mise tasks**

```bash
git add .mise.toml
git commit -m "build: add gomobile framework task"
```

## Task 5: Xcode Framework And Permission Wiring

**Files:**
- Modify: `apple/Derphole/Derphole.xcodeproj/project.pbxproj`

- [ ] **Step 1: Add generated Info.plist keys**

In both Derphole target build configurations in `apple/Derphole/Derphole.xcodeproj/project.pbxproj`, add:

```pbxproj
INFOPLIST_KEY_NSCameraUsageDescription = "Derphole uses the camera to scan receive QR codes.";
INFOPLIST_KEY_NSLocalNetworkUsageDescription = "Derphole uses the local network to transfer files directly between your devices.";
```

The two blocks are the `XCBuildConfiguration` sections for target `Derphole`, Debug and Release, near `PRODUCT_BUNDLE_IDENTIFIER = dev.shayne.Derphole;`.

- [ ] **Step 2: Link the gomobile XCFramework**

Add a file reference for `DerpholeMobile.xcframework` under the main group:

```pbxproj
26D100012F9700000048F045 /* DerpholeMobile.xcframework */ = {isa = PBXFileReference; lastKnownFileType = wrapper.xcframework; name = DerpholeMobile.xcframework; path = ../../dist/apple/DerpholeMobile.xcframework; sourceTree = "<group>"; };
```

Add a build file reference:

```pbxproj
26D100022F9700000048F045 /* DerpholeMobile.xcframework in Frameworks */ = {isa = PBXBuildFile; fileRef = 26D100012F9700000048F045 /* DerpholeMobile.xcframework */; };
```

Add `26D100022F9700000048F045 /* DerpholeMobile.xcframework in Frameworks */` to the Derphole target `PBXFrameworksBuildPhase` files list. Add `26D100012F9700000048F045 /* DerpholeMobile.xcframework */` to the root group children list. These IDs do not appear in the current project file.

- [ ] **Step 3: Build Xcode project**

Run:

```bash
mise run apple:build
```

Expected: PASS. If Swift import fails because gomobile generated a module name different from `Derpholemobile`, inspect `dist/apple/DerpholeMobile.xcframework/ios-arm64*/DerpholeMobile.framework/Modules/module.modulemap` and use that module name in Task 6.

- [ ] **Step 4: Commit Xcode wiring**

```bash
git add apple/Derphole/Derphole.xcodeproj/project.pbxproj
git commit -m "build: link Derphole mobile framework"
```

## Task 6: SwiftUI Receive App

**Files:**
- Create: `apple/Derphole/Derphole/TransferState.swift`
- Create: `apple/Derphole/Derphole/QRScannerView.swift`
- Create: `apple/Derphole/Derphole/DocumentExporter.swift`
- Modify: `apple/Derphole/Derphole/ContentView.swift`
- Modify: `apple/Derphole/Derphole.xcodeproj/project.pbxproj`

- [ ] **Step 1: Add Swift files to the project**

Add these `PBXFileReference` entries in the Derphole group:

```pbxproj
26D100032F9700000048F045 /* TransferState.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = TransferState.swift; sourceTree = "<group>"; };
26D100042F9700000048F045 /* QRScannerView.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = QRScannerView.swift; sourceTree = "<group>"; };
26D100052F9700000048F045 /* DocumentExporter.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = DocumentExporter.swift; sourceTree = "<group>"; };
```

Add these `PBXBuildFile` entries:

```pbxproj
26D100062F9700000048F045 /* TransferState.swift in Sources */ = {isa = PBXBuildFile; fileRef = 26D100032F9700000048F045 /* TransferState.swift */; };
26D100072F9700000048F045 /* QRScannerView.swift in Sources */ = {isa = PBXBuildFile; fileRef = 26D100042F9700000048F045 /* QRScannerView.swift */; };
26D100082F9700000048F045 /* DocumentExporter.swift in Sources */ = {isa = PBXBuildFile; fileRef = 26D100052F9700000048F045 /* DocumentExporter.swift */; };
```

Add the three file reference IDs to the existing Derphole group `children` list. Add the three build file IDs to the Derphole target `PBXSourcesBuildPhase` files list. These IDs do not appear in the current project file.

- [ ] **Step 2: Create TransferState**

Create `apple/Derphole/Derphole/TransferState.swift`:

```swift
import Foundation
import SwiftUI
import Derpholemobile

@MainActor
final class TransferState: ObservableObject {
    enum Phase: Equatable {
        case idle
        case scanning
        case validating
        case receiving
        case completed(URL)
        case exporting(URL)
        case failed(String)
        case cancelled
    }

    @Published var phase: Phase = .idle
    @Published var payloadText: String = ""
    @Published var status: String = "Ready"
    @Published var currentBytes: Int64 = 0
    @Published var totalBytes: Int64 = 0
    @Published var sawDirect: Bool = false
    @Published var sawRelay: Bool = false

    private let receiver = DerpholemobileNewReceiver()
    private var receiveTask: Task<Void, Never>?

    func scanStarted() {
        phase = .scanning
        status = "Scanning"
    }

    func receive(payload: String) {
        receiveTask?.cancel()
        phase = .validating
        status = "Validating"
        payloadText = payload
        currentBytes = 0
        totalBytes = 0
        sawDirect = false
        sawRelay = false

        let outputDir = Self.outputDirectory()
        let callbacks = MobileCallbacks { [weak self] status in
            Task { @MainActor in self?.handle(status: status) }
        } progress: { [weak self] current, total in
            Task { @MainActor in
                self?.currentBytes = current
                self?.totalBytes = total
            }
        } trace: { [weak self] trace in
            Task { @MainActor in self?.status = trace }
        }

        phase = .receiving
        receiveTask = Task.detached { [receiver] in
            do {
                let path = try receiver.receive(payload, outputDir: outputDir.path, callbacks: callbacks)
                await MainActor.run {
                    self.phase = .completed(URL(fileURLWithPath: path))
                    self.status = self.sawDirect ? "Completed over direct" : "Completed over relay"
                }
            } catch {
                await MainActor.run {
                    self.phase = .failed(error.localizedDescription)
                    self.status = error.localizedDescription
                }
            }
        }
    }

    func cancel() {
        receiver.cancel()
        receiveTask?.cancel()
        receiveTask = nil
        phase = .cancelled
        status = "Cancelled"
    }

    func reset() {
        cancel()
        phase = .idle
        status = "Ready"
        payloadText = ""
        currentBytes = 0
        totalBytes = 0
        sawDirect = false
        sawRelay = false
    }

    func export(url: URL) {
        phase = .exporting(url)
    }

    private func handle(status: String) {
        self.status = status
        if status == "connected-direct" {
            sawDirect = true
        }
        if status == "connected-relay" {
            sawRelay = true
        }
    }

    private static func outputDirectory() -> URL {
        let base = FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("derphole-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}

final class MobileCallbacks: NSObject, DerpholemobileCallbacksProtocol {
    private let statusHandler: (String) -> Void
    private let progressHandler: (Int64, Int64) -> Void
    private let traceHandler: (String) -> Void

    init(status: @escaping (String) -> Void, progress: @escaping (Int64, Int64) -> Void, trace: @escaping (String) -> Void) {
        self.statusHandler = status
        self.progressHandler = progress
        self.traceHandler = trace
    }

    func status(_ status: String?) {
        statusHandler(status ?? "")
    }

    func progress(_ current: Int64, total: Int64) {
        progressHandler(current, total)
    }

    func trace(_ trace: String?) {
        traceHandler(trace ?? "")
    }
}
```

If gomobile generates a different Swift protocol name for `Callbacks`, use the exact generated name from the framework header and update `MobileCallbacks` accordingly.

- [ ] **Step 3: Create QR scanner wrapper**

Create `apple/Derphole/Derphole/QRScannerView.swift`:

```swift
import AVFoundation
import SwiftUI

struct QRScannerView: UIViewControllerRepresentable {
    var onCode: (String) -> Void
    var onError: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onCode = onCode
        controller.onError = onError
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    var onError: ((String) -> Void)?
    private let session = AVCaptureSession()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configure()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { self.session.stopRunning() }
        }
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video) else {
            onError?("Camera is not available")
            return
        }
        do {
            let input = try AVCaptureDeviceInput(device: device)
            if session.canAddInput(input) {
                session.addInput(input)
            }
            let output = AVCaptureMetadataOutput()
            if session.canAddOutput(output) {
                session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main)
                output.metadataObjectTypes = [.qr]
            }
            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.bounds
            view.layer.addSublayer(preview)
        } catch {
            onError?(error.localizedDescription)
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        view.layer.sublayers?.compactMap { $0 as? AVCaptureVideoPreviewLayer }.forEach { $0.frame = view.bounds }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let code = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject }).first?.stringValue else {
            return
        }
        session.stopRunning()
        onCode?(code)
    }
}
```

- [ ] **Step 4: Create document exporter**

Create `apple/Derphole/Derphole/DocumentExporter.swift`:

```swift
import SwiftUI
import UIKit

struct DocumentExporter: UIViewControllerRepresentable {
    let url: URL
    let onComplete: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onComplete: onComplete)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let controller = UIDocumentPickerViewController(forExporting: [url], asCopy: true)
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onComplete: () -> Void

        init(onComplete: @escaping () -> Void) {
            self.onComplete = onComplete
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            onComplete()
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            onComplete()
        }
    }
}
```

- [ ] **Step 5: Replace ContentView**

Replace `apple/Derphole/Derphole/ContentView.swift` with:

```swift
import SwiftUI

struct ContentView: View {
    @StateObject private var transfer = TransferState()
    @State private var showingScanner = false
    @State private var showingExporter = false
    @State private var exportURL: URL?

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                VStack(spacing: 8) {
                    Image(systemName: transfer.sawDirect ? "bolt.horizontal.circle.fill" : "qrcode.viewfinder")
                        .font(.system(size: 56, weight: .semibold))
                        .foregroundStyle(transfer.sawDirect ? .green : .blue)
                    Text(title)
                        .font(.title2.weight(.semibold))
                    Text(transfer.status)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                progressView

                Button {
                    transfer.scanStarted()
                    showingScanner = true
                } label: {
                    Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                payloadField

                if case let .completed(url) = transfer.phase {
                    Button {
                        exportURL = url
                        showingExporter = true
                        transfer.export(url: url)
                    } label: {
                        Label("Save File", systemImage: "square.and.arrow.down")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }

                if case .receiving = transfer.phase {
                    Button(role: .destructive) {
                        transfer.cancel()
                    } label: {
                        Label("Cancel", systemImage: "xmark.circle")
                    }
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Derphole")
            .sheet(isPresented: $showingScanner) {
                QRScannerView { code in
                    showingScanner = false
                    transfer.receive(payload: code)
                } onError: { message in
                    showingScanner = false
                    transfer.phase = .failed(message)
                    transfer.status = message
                }
            }
            .sheet(isPresented: $showingExporter, onDismiss: {
                transfer.phase = exportURL.map { .completed($0) } ?? .idle
            }) {
                if let exportURL {
                    DocumentExporter(url: exportURL) {
                        showingExporter = false
                    }
                }
            }
        }
    }

    private var title: String {
        switch transfer.phase {
        case .idle: return "Ready to Receive"
        case .scanning: return "Scanning"
        case .validating: return "Validating"
        case .receiving: return "Receiving"
        case .completed: return transfer.sawDirect ? "Received Direct" : "Received"
        case .exporting: return "Saving"
        case .failed: return "Transfer Failed"
        case .cancelled: return "Cancelled"
        }
    }

    private var progressView: some View {
        VStack(spacing: 8) {
            if transfer.totalBytes > 0 {
                ProgressView(value: Double(transfer.currentBytes), total: Double(transfer.totalBytes))
            } else {
                ProgressView()
                    .opacity(isBusy ? 1 : 0)
            }
            HStack {
                Label(transfer.sawRelay ? "Relay seen" : "Relay pending", systemImage: "point.3.connected.trianglepath.dotted")
                Spacer()
                Label(transfer.sawDirect ? "Direct" : "Direct pending", systemImage: "bolt.horizontal")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private var payloadField: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Paste receive payload", text: $transfer.payloadText, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button {
                transfer.receive(payload: transfer.payloadText)
            } label: {
                Label("Use Pasted Payload", systemImage: "doc.on.clipboard")
            }
            .disabled(transfer.payloadText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .accessibilityIdentifier("payload-support-section")
    }

    private var isBusy: Bool {
        if case .receiving = transfer.phase { return true }
        if case .validating = transfer.phase { return true }
        return false
    }
}

#Preview {
    ContentView()
}
```

- [ ] **Step 6: Build app**

Run:

```bash
mise run apple:build
```

Expected: PASS.

- [ ] **Step 7: Commit Swift app**

```bash
git add apple/Derphole/Derphole.xcodeproj/project.pbxproj apple/Derphole/Derphole/TransferState.swift apple/Derphole/Derphole/QRScannerView.swift apple/Derphole/Derphole/DocumentExporter.swift apple/Derphole/Derphole/ContentView.swift
git commit -m "feat: add iOS QR receive app"
```

## Task 7: Apple Tests

**Files:**
- Modify: `apple/Derphole/DerpholeTests/DerpholeTests.swift`
- Modify: `apple/Derphole/DerpholeUITests/DerpholeUITests.swift`

- [ ] **Step 1: Replace unit tests**

Replace `apple/Derphole/DerpholeTests/DerpholeTests.swift` with:

```swift
import XCTest
@testable import Derphole

@MainActor
final class DerpholeTests: XCTestCase {
    func testInitialStateIsIdle() {
        let state = TransferState()
        XCTAssertEqual(state.status, "Ready")
        XCTAssertFalse(state.sawDirect)
        XCTAssertFalse(state.sawRelay)
    }

    func testCancelSetsCancelledState() {
        let state = TransferState()
        state.cancel()
        XCTAssertEqual(state.status, "Cancelled")
        if case .cancelled = state.phase {
            return
        }
        XCTFail("phase = \(state.phase), want cancelled")
    }

    func testScanStartedSetsScanningState() {
        let state = TransferState()
        state.scanStarted()
        XCTAssertEqual(state.status, "Scanning")
        if case .scanning = state.phase {
            return
        }
        XCTFail("phase = \(state.phase), want scanning")
    }
}
```

- [ ] **Step 2: Replace UI test**

Replace `apple/Derphole/DerpholeUITests/DerpholeUITests.swift` with:

```swift
import XCTest

final class DerpholeUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsQRFirstUIAndPayloadSupport() throws {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(app.buttons["Scan QR Code"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.textFields["Paste receive payload"].exists)
        XCTAssertTrue(app.buttons["Use Pasted Payload"].exists)
    }
}
```

- [ ] **Step 3: Run Apple tests**

Run:

```bash
mise run apple:test
```

Expected: PASS on the available iPhone simulator.

- [ ] **Step 4: Commit Apple tests**

```bash
git add apple/Derphole/DerpholeTests/DerpholeTests.swift apple/Derphole/DerpholeUITests/DerpholeUITests.swift
git commit -m "test: cover iOS receive app states"
```

## Task 8: End-To-End Local Verification

**Files:**
- No source edits unless verification exposes a defect.

- [ ] **Step 1: Run Go tests**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 2: Run Apple framework build**

Run:

```bash
mise run apple:mobile-framework
```

Expected: PASS.

- [ ] **Step 3: Run Apple build**

Run:

```bash
mise run apple:build
```

Expected: PASS.

- [ ] **Step 4: Run Apple tests**

Run:

```bash
mise run apple:test
```

Expected: PASS.

- [ ] **Step 5: Run simulator skill smoke check**

Use `$ios-simulator-skill` scripts:

```bash
python .agents/skills/ios-simulator-skill/scripts/build_and_test.py --project apple/Derphole/Derphole.xcodeproj --scheme Derphole --simulator "iPhone 17" --test --json
```

Expected: JSON result indicates build/test success with zero errors.

- [ ] **Step 6: Handle verification fixes if needed**

If verification exposed fixes, return to the failing implementation task, edit the source files named by that task, rerun the relevant verification command, and commit with that task's listed `git add` command. Do not create a broad catch-all verification commit.

```bash
git status --short
```

If no fixes were needed, do not create an empty commit.

## Task 9: Physical iPhone Direct Verification

**Files:**
- Create: `docs/superpowers/specs/2026-04-19-ios-qr-transfer-design.md` amendment only if real-device testing changes the design.
- Modify source files only if physical-device direct fails.

- [ ] **Step 1: Build for physical device**

Run with signing enabled from Xcode or command line. Use the existing app bundle identifier `dev.shayne.Derphole` and the user's Apple development team in Xcode.

- [ ] **Step 2: Install on iPhone**

Install the app on a physical iPhone through Xcode Devices, Xcode Run, or an equivalent local deployment command.

- [ ] **Step 3: Generate a large QR send**

Run:

```bash
mkdir -p dist/manual-ios-direct
dd if=/dev/urandom of=dist/manual-ios-direct/direct-test.bin bs=1m count=256
mise run build
./dist/derphole send --qr dist/manual-ios-direct/direct-test.bin
```

Expected: terminal displays a QR code and waits for the receiver.

- [ ] **Step 4: Scan and receive**

On the iPhone, scan the QR code, accept camera and local-network prompts, and let the transfer complete.

Expected: app status includes `connected-direct` before completion and completion text says direct.

- [ ] **Step 5: Export and compare bytes**

Export the file to iCloud Drive as `direct-test.bin`, wait for the file to appear on the Mac, then compare it with the source:

```bash
exported_file="$HOME/Library/Mobile Documents/com~apple~CloudDocs/direct-test.bin"
test -f "$exported_file"
shasum -a 256 dist/manual-ios-direct/direct-test.bin "$exported_file"
```

Expected: both SHA-256 hashes are identical.

- [ ] **Step 6: Record direct evidence**

Record in the final response:

- iPhone model or simulator/device name
- file size
- whether `connected-direct` appeared
- elapsed transfer time
- SHA-256 match result

- [ ] **Step 7: Test relay fallback separately**

Run one blocked-direct transfer by disabling local network permission for the app or forcing a network setup that prevents direct.

Expected: transfer can complete over relay, but this result is recorded as fallback-only and does not replace Step 4 direct success.

## Task 10: Final Verification And Summary

**Files:**
- No source edits unless final verification exposes a defect.

- [ ] **Step 1: Run final command set**

Run:

```bash
mise run test
mise run apple:mobile-framework
mise run apple:build
mise run apple:test
```

Expected: all commands PASS.

- [ ] **Step 2: Check worktree**

Run:

```bash
git status --short
```

Expected: only intentional uncommitted user files remain. Do not revert unrelated existing files.

- [ ] **Step 3: Final response**

Report:

- files changed at a high level
- verification commands and outcomes
- physical-device direct result
- whether relay fallback was checked
- any remaining limitation, especially if iOS entitlement work is still needed
