// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derphole/protocol"
	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/token"
)

func TestSendTextIssuesTokenAndTransfersPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	var sendStderr synchronizedBuffer
	go func() {
		sendDone <- Send(ctx, SendConfig{
			Text:   "hello derphole",
			Stderr: &sendStderr,
		})
	}()

	token := waitForTokenLine(t, &sendStderr)
	var out bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:  token,
		Stdout: &out,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := out.String(); got != "hello derphole" {
		t.Fatalf("stdout = %q, want %q", got, "hello derphole")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestReceiveAllocateIssuesTokenAndAcceptsText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var recvOut bytes.Buffer
	var recvErr synchronizedBuffer
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- Receive(ctx, ReceiveConfig{
			Allocate: true,
			Stdout:   &recvOut,
			Stderr:   &recvErr,
		})
	}()

	token := waitForTokenLine(t, &recvErr)
	if err := Send(ctx, SendConfig{
		Token: token,
		Text:  "allocated flow",
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := recvOut.String(); got != "allocated flow" {
		t.Fatalf("stdout = %q, want %q", got, "allocated flow")
	}
}

func TestSendFileTransfersSuggestedFilename(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(srcPath, []byte("hello file"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr synchronizedBuffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			What:   srcPath,
			Stderr: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:      token,
		OutputPath: recvDir,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "hello file" {
		t.Fatalf("received = %q, want %q", got, "hello file")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestSendDirectoryTransfersTopLevelDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcParent := t.TempDir()
	srcDir := filepath.Join(srcParent, "project")
	if err := os.MkdirAll(filepath.Join(srcDir, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "nested", "child.txt"), []byte("child"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr synchronizedBuffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			What:   srcDir,
			Stderr: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:      token,
		OutputPath: recvDir,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "project", "root.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "root" {
		t.Fatalf("root.txt = %q, want %q", got, "root")
	}

	got, err = os.ReadFile(filepath.Join(recvDir, "project", "nested", "child.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "child" {
		t.Fatalf("child.txt = %q, want %q", got, "child")
	}

	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestSendFileReportsProgressOnBothSides(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(srcPath, bytes.Repeat([]byte("a"), 64*1024), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr synchronizedBuffer
	var recvErr bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			What:           srcPath,
			Stderr:         &sendErr,
			ProgressOutput: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:          token,
		OutputPath:     recvDir,
		Stderr:         &recvErr,
		ProgressOutput: &recvErr,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := sendErr.String(); !strings.Contains(got, "Sending ") || !strings.Contains(got, "file named") || !strings.Contains(got, "100%|") {
		t.Fatalf("send stderr = %q, want summary and progress", got)
	}
	if got := recvErr.String(); !strings.Contains(got, "Receiving file") || !strings.Contains(got, "100%|") {
		t.Fatalf("receive stderr = %q, want summary and progress", got)
	}
}

func TestSendTextDoesNotEmitProgressBar(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sendErr synchronizedBuffer
	var recvErr, out bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			Text:           "hello progressless text",
			Stderr:         &sendErr,
			ProgressOutput: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:          token,
		Stdout:         &out,
		Stderr:         &recvErr,
		ProgressOutput: &recvErr,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if got := out.String(); got != "hello progressless text" {
		t.Fatalf("stdout = %q, want %q", got, "hello progressless text")
	}
	if got := sendErr.String(); !strings.Contains(got, "Sending text message") {
		t.Fatalf("send stderr = %q, want text summary", got)
	}
	if strings.Contains(sendErr.String(), "100%|") {
		t.Fatalf("send stderr = %q, want no progress bar for text", sendErr.String())
	}
	if strings.Contains(recvErr.String(), "100%|") {
		t.Fatalf("receive stderr = %q, want no progress bar for text", recvErr.String())
	}
}

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

func TestReceiveZeroByteFileReportsFinalProgressCallback(t *testing.T) {
	var buf bytes.Buffer
	header := protocol.Header{Version: 1, Kind: protocol.KindFile, Name: "empty.txt", Size: 0}
	if err := protocol.WriteHeader(&buf, header); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}

	var events [][2]int64
	err := readTransfer(&buf, "", io.Discard, t.TempDir(), io.Discard, nil, func(current, total int64) {
		events = append(events, [2]int64{current, total})
	})
	if err != nil {
		t.Fatalf("readTransfer() error = %v", err)
	}
	if len(events) != 1 || events[0] != [2]int64{0, 0} {
		t.Fatalf("progress events = %v, want [[0 0]]", events)
	}
}

func TestWriteTransferWritesHeaderBodyAndFinishesProgress(t *testing.T) {
	tx := sendTransfer{
		header:        protocol.Header{Version: 1, Kind: protocol.KindText},
		body:          strings.NewReader("transfer body"),
		summary:       "Sending test body",
		progressTotal: int64(len("transfer body")),
	}

	var wire bytes.Buffer
	var progress bytes.Buffer
	var stderr bytes.Buffer
	if err := writeTransfer(&wire, tx, &progress, &stderr); err != nil {
		t.Fatalf("writeTransfer() error = %v", err)
	}
	reader := bufio.NewReader(&wire)
	header, err := protocol.ReadHeader(reader)
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}
	if header.Kind != protocol.KindText {
		t.Fatalf("header.Kind = %v, want text", header.Kind)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll(body) error = %v", err)
	}
	if got := string(body); got != "transfer body" {
		t.Fatalf("body = %q, want transfer body", got)
	}
	if !strings.Contains(stderr.String(), "Sending test body") {
		t.Fatalf("stderr = %q, want summary", stderr.String())
	}
	if !strings.Contains(progress.String(), "100%|") {
		t.Fatalf("progress = %q, want final progress", progress.String())
	}
}

func TestDecodeDirectorySummaryHandlesEmptyInvalidAndValidMetadata(t *testing.T) {
	if meta, ok := decodeDirectorySummary(nil); ok || meta.FileCount != 0 {
		t.Fatalf("decodeDirectorySummary(empty) = (%+v, %t), want false", meta, ok)
	}
	if _, ok := decodeDirectorySummary([]byte("{")); ok {
		t.Fatal("decodeDirectorySummary(invalid) ok = true, want false")
	}
	meta, ok := decodeDirectorySummary([]byte(`{"file_count":3,"uncompressed_bytes":99}`))
	if !ok {
		t.Fatal("decodeDirectorySummary(valid) ok = false, want true")
	}
	if meta.FileCount != 3 || meta.UncompressedBytes != 99 {
		t.Fatalf("decodeDirectorySummary(valid) = %+v, want file_count=3 bytes=99", meta)
	}
}

func TestSendQRRejectsNonFileTransfer(t *testing.T) {
	dir := t.TempDir()
	for _, cfg := range []SendConfig{
		{QR: true},
		{QR: true, Text: "hello"},
		{QR: true, What: "hello"},
		{QR: true, Stdin: strings.NewReader("hello")},
		{QR: true, What: dir},
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
		_, _ = io.Copy(io.Discard, cfg.StdioIn)
		return "", nil
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "photo.jpg")
	if err := os.WriteFile(path, []byte("image"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	err := Send(context.Background(), SendConfig{
		QR:     true,
		What:   path,
		Stdin:  strings.NewReader("ignored"),
		Stderr: &stderr,
	})
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

func TestSendDefaultsParallelPolicyForOffer(t *testing.T) {
	prev := derpholeSessionOffer
	t.Cleanup(func() {
		derpholeSessionOffer = prev
	})

	sentinel := errors.New("sentinel-offer")
	var got session.OfferConfig
	derpholeSessionOffer = func(_ context.Context, cfg session.OfferConfig) (string, error) {
		got = cfg
		return "", sentinel
	}

	err := Send(context.Background(), SendConfig{Text: "hello"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send() error = %v, want %v", err, sentinel)
	}
	if got.TokenSink == nil {
		t.Fatal("got.TokenSink = nil, want allocated sink")
	}
	if gotPolicy, want := got.ParallelPolicy, session.DefaultParallelPolicy(); gotPolicy != want {
		t.Fatalf("got.ParallelPolicy = %#v, want %#v", gotPolicy, want)
	}
}

func TestReceiveDefaultsParallelPolicyForAttachDial(t *testing.T) {
	prev := derpholeSessionDialAttach
	t.Cleanup(func() {
		derpholeSessionDialAttach = prev
	})

	sentinel := errors.New("sentinel-attach")
	var got session.AttachDialConfig
	derpholeSessionDialAttach = func(_ context.Context, cfg session.AttachDialConfig) (net.Conn, error) {
		got = cfg
		return nil, sentinel
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityAttach,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	err = Receive(context.Background(), ReceiveConfig{Token: tok})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Receive() error = %v, want %v", err, sentinel)
	}
	if got.Token != tok {
		t.Fatalf("got.Token = %q, want %q", got.Token, tok)
	}
	if gotPolicy, want := got.ParallelPolicy, session.DefaultParallelPolicy(); gotPolicy != want {
		t.Fatalf("got.ParallelPolicy = %#v, want %#v", gotPolicy, want)
	}
}

func TestReceiveWebFileTokenUsesWebRelayReceiver(t *testing.T) {
	prev := derpholeWebRelayReceiveWithOptions
	prevDirect := derpholeNewWebDirect
	t.Cleanup(func() {
		derpholeWebRelayReceiveWithOptions = prev
		derpholeNewWebDirect = prevDirect
	})
	derpholeNewWebDirect = nil

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityWebFile,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	var gotToken string
	var gotSink webrelay.FileSink
	var gotProgressOutput bool
	derpholeWebRelayReceiveWithOptions = func(_ context.Context, encodedToken string, sink webrelay.FileSink, cb webrelay.Callbacks, _ webrelay.TransferOptions) error {
		gotToken = encodedToken
		gotSink = sink
		gotProgressOutput = cb.Progress != nil
		return nil
	}

	var recvErr bytes.Buffer
	err = Receive(context.Background(), ReceiveConfig{
		Token:          tok,
		OutputPath:     t.TempDir(),
		Stderr:         &recvErr,
		ProgressOutput: &recvErr,
	})
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if gotToken != tok {
		t.Fatalf("web relay token = %q, want %q", gotToken, tok)
	}
	if gotSink == nil {
		t.Fatal("web relay sink = nil, want native file sink")
	}
	if !gotProgressOutput {
		t.Fatal("web relay progress callback not configured")
	}
}

func TestReceiveViaWebRelayUsesNativeDirectByDefault(t *testing.T) {
	oldReceive := derpholeWebRelayReceiveWithOptions
	oldDirect := derpholeNewWebDirect
	defer func() {
		derpholeWebRelayReceiveWithOptions = oldReceive
		derpholeNewWebDirect = oldDirect
	}()

	var gotDirect bool
	derpholeNewWebDirect = func() webrelay.DirectTransport {
		return newFakeDirect()
	}
	derpholeWebRelayReceiveWithOptions = func(_ context.Context, _ string, _ webrelay.FileSink, _ webrelay.Callbacks, opts webrelay.TransferOptions) error {
		gotDirect = opts.Direct != nil
		return nil
	}

	err := receiveViaWebRelay(context.Background(), ReceiveConfig{}, "token")
	if err != nil {
		t.Fatalf("receiveViaWebRelay() error = %v", err)
	}
	if !gotDirect {
		t.Fatal("receiveViaWebRelay did not pass native direct transport")
	}
}

func TestReceiveViaWebRelaySkipsNativeDirectWhenForcedRelay(t *testing.T) {
	oldReceive := derpholeWebRelayReceiveWithOptions
	oldDirect := derpholeNewWebDirect
	defer func() {
		derpholeWebRelayReceiveWithOptions = oldReceive
		derpholeNewWebDirect = oldDirect
	}()

	var gotDirect bool
	derpholeNewWebDirect = func() webrelay.DirectTransport {
		return newFakeDirect()
	}
	derpholeWebRelayReceiveWithOptions = func(_ context.Context, _ string, _ webrelay.FileSink, _ webrelay.Callbacks, opts webrelay.TransferOptions) error {
		gotDirect = opts.Direct != nil
		return nil
	}

	err := receiveViaWebRelay(context.Background(), ReceiveConfig{ForceRelay: true}, "token")
	if err != nil {
		t.Fatalf("receiveViaWebRelay() error = %v", err)
	}
	if gotDirect {
		t.Fatal("receiveViaWebRelay passed direct transport despite ForceRelay")
	}
}

type fakeWebDirect struct{}

func newFakeDirect() webrelay.DirectTransport { return fakeWebDirect{} }

func (fakeWebDirect) Start(context.Context, webrelay.DirectRole, webrelay.DirectSignalPeer) error {
	return nil
}
func (fakeWebDirect) Ready() <-chan struct{} { return make(chan struct{}) }
func (fakeWebDirect) Failed() <-chan error   { return make(chan error) }
func (fakeWebDirect) SendFrame(context.Context, []byte) error {
	return nil
}
func (fakeWebDirect) ReceiveFrames() <-chan []byte { return make(chan []byte) }
func (fakeWebDirect) Close() error                 { return nil }

func TestNativeWebFileSinkWritesFileAndProgress(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	sink := newNativeWebFileSink(dir, &stderr, &stderr, nil)

	if err := sink.Open(context.Background(), webproto.Meta{Name: "../payload.txt", Size: 5}); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := sink.WriteChunk(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("WriteChunk() error = %v", err)
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "payload.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("received = %q, want %q", got, "hello")
	}
	if log := stderr.String(); !strings.Contains(log, "Receiving file") || !strings.Contains(log, "100%|") {
		t.Fatalf("stderr = %q, want receive summary and progress", log)
	}
}

func TestSendPrefersSessionErrorOverClosedPipe(t *testing.T) {
	prev := derpholeSessionSend
	t.Cleanup(func() {
		derpholeSessionSend = prev
	})

	sentinel := errors.New("session send failed")
	derpholeSessionSend = func(_ context.Context, cfg session.SendConfig) error {
		if rc, ok := cfg.StdioIn.(io.ReadCloser); ok {
			_ = rc.Close()
		}
		return sentinel
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdio,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	err = Send(context.Background(), SendConfig{
		Token: tok,
		Stdin: bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20)),
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send() error = %v, want %v", err, sentinel)
	}
}

func TestOfferPrefersSessionErrorOverClosedPipe(t *testing.T) {
	prev := derpholeSessionOffer
	t.Cleanup(func() {
		derpholeSessionOffer = prev
	})

	sentinel := errors.New("session offer failed")
	derpholeSessionOffer = func(_ context.Context, cfg session.OfferConfig) (string, error) {
		if cfg.TokenSink != nil {
			cfg.TokenSink <- "fake-token"
		}
		if rc, ok := cfg.StdioIn.(io.ReadCloser); ok {
			_ = rc.Close()
		}
		return "", sentinel
	}

	err := Send(context.Background(), SendConfig{
		Stdin: bytes.NewReader(bytes.Repeat([]byte("y"), 1<<20)),
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send() error = %v, want %v", err, sentinel)
	}
}

func TestReceivePrefersSessionErrorOverIncompleteEOF(t *testing.T) {
	prev := derpholeSessionReceive
	t.Cleanup(func() {
		derpholeSessionReceive = prev
	})

	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "peer aborted", err: session.ErrPeerAborted},
		{name: "peer disconnected", err: session.ErrPeerDisconnected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			derpholeSessionReceive = func(_ context.Context, cfg session.ReceiveConfig) error {
				if err := protocol.WriteHeader(cfg.StdioOut, protocol.Header{
					Version: 1,
					Kind:    protocol.KindFile,
					Name:    "partial.bin",
					Size:    8,
					Verify:  VerificationString(cfg.Token),
				}); err != nil {
					return err
				}
				if _, err := cfg.StdioOut.Write([]byte("abc")); err != nil {
					return err
				}
				if closer, ok := cfg.StdioOut.(io.Closer); ok {
					_ = closer.Close()
				}
				return tt.err
			}

			tok, err := token.Encode(token.Token{
				Version:      token.SupportedVersion,
				ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
				Capabilities: token.CapabilityStdioOffer,
			})
			if err != nil {
				t.Fatalf("token.Encode() error = %v", err)
			}

			err = Receive(context.Background(), ReceiveConfig{
				Token:      tok,
				OutputPath: t.TempDir(),
				Stderr:     io.Discard,
			})
			if !errors.Is(err, tt.err) {
				t.Fatalf("Receive() error = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestOfferSendCancelsWhileWaitingForReceiver(t *testing.T) {
	prev := derpholeSessionOffer
	t.Cleanup(func() {
		derpholeSessionOffer = prev
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tokenSent := make(chan struct{})
	derpholeSessionOffer = func(ctx context.Context, cfg session.OfferConfig) (string, error) {
		if cfg.TokenSink != nil {
			cfg.TokenSink <- "fake-token"
		}
		close(tokenSent)
		<-ctx.Done()
		return "", ctx.Err()
	}

	done := make(chan error, 1)
	go func() {
		done <- Send(ctx, SendConfig{
			Stdin:  bytes.NewReader(bytes.Repeat([]byte("y"), 1<<20)),
			Stderr: io.Discard,
		})
	}()

	select {
	case <-tokenSent:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for offer token")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Send() error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("Send() did not return after context cancellation")
	}
}

func TestTokenSendCancelsWhileSessionWaits(t *testing.T) {
	prev := derpholeSessionSend
	t.Cleanup(func() {
		derpholeSessionSend = prev
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sendStarted := make(chan struct{})
	derpholeSessionSend = func(ctx context.Context, _ session.SendConfig) error {
		close(sendStarted)
		<-ctx.Done()
		return ctx.Err()
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdio,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- Send(ctx, SendConfig{
			Token: tok,
			Stdin: bytes.NewReader(bytes.Repeat([]byte("z"), 1<<20)),
		})
	}()

	select {
	case <-sendStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session send")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Send() error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("Send() did not return after context cancellation")
	}
}

func TestSendDoesNotFinishProgressWhenSessionFailsAfterDrainingInput(t *testing.T) {
	prev := derpholeSessionSend
	t.Cleanup(func() {
		derpholeSessionSend = prev
	})

	derpholeSessionSend = func(_ context.Context, cfg session.SendConfig) error {
		if _, err := io.Copy(io.Discard, cfg.StdioIn); err != nil {
			return err
		}
		return context.DeadlineExceeded
	}

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, bytes.Repeat([]byte("z"), 64*1024), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdio,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	var stderr bytes.Buffer
	err = Send(context.Background(), SendConfig{
		Token:          tok,
		What:           srcPath,
		Stderr:         &stderr,
		ProgressOutput: &stderr,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if strings.Contains(stderr.String(), "100%|") {
		t.Fatalf("send stderr = %q, want no final 100%% progress on failed session", stderr.String())
	}
}

func TestSendPassesKnownFileWireSizeToSession(t *testing.T) {
	prev := derpholeSessionSend
	t.Cleanup(func() {
		derpholeSessionSend = prev
	})

	sentinel := errors.New("session stopped")
	var got session.SendConfig
	derpholeSessionSend = func(_ context.Context, cfg session.SendConfig) error {
		got = cfg
		if rc, ok := cfg.StdioIn.(io.ReadCloser); ok {
			_ = rc.Close()
		}
		return sentinel
	}

	payload := bytes.Repeat([]byte("q"), 4096)
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdio,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	err = Send(context.Background(), SendConfig{
		Token: tok,
		What:  srcPath,
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send() error = %v, want %v", err, sentinel)
	}
	headerBytes, err := protocol.HeaderWireSize(protocol.Header{
		Version: 1,
		Kind:    protocol.KindFile,
		Name:    "payload.bin",
		Size:    int64(len(payload)),
		Verify:  VerificationString(tok),
	})
	if err != nil {
		t.Fatalf("HeaderWireSize() error = %v", err)
	}
	if want := headerBytes + int64(len(payload)); got.StdioExpectedBytes != want {
		t.Fatalf("StdioExpectedBytes = %d, want %d", got.StdioExpectedBytes, want)
	}
}

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForTokenLine(t *testing.T, stderr interface{ String() string }) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(stderr.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "On the other machine") {
				continue
			}
			if strings.Contains(line, " receive ") {
				fields := strings.Fields(line)
				return fields[len(fields)-1]
			}
			return line
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("token line not found in stderr %q", stderr.String())
	return ""
}
