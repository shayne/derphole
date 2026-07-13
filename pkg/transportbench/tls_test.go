// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSFileTransferUsesEightPinnedLanesAndPreservesFile(t *testing.T) {
	testStarted := time.Now()
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.bin")
	outputPath := filepath.Join(tempDir, "output.bin")
	readyPath := filepath.Join(tempDir, "ready.json")
	senderTrace := filepath.Join(tempDir, "sender.csv")
	receiverTrace := filepath.Join(tempDir, "receiver.csv")
	payload := deterministicPayload(8<<20 + 37)
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	receiveResult := make(chan tlsTestResult, 1)
	go func() {
		summary, err := ReceiveTLS(context.Background(), TLSReceiveConfig{
			ListenAddr: "127.0.0.1:0",
			OutputPath: outputPath,
			ReadyFile:  readyPath,
			TracePath:  receiverTrace,
			Timeout:    10 * time.Second,
		})
		receiveResult <- tlsTestResult{summary: summary, err: err}
	}()

	ready := waitForReady(t, readyPath)
	transferID := decodeTransferID(t, ready.TransferID)
	senderSummary, err := SendTLS(context.Background(), TLSSendConfig{
		PeerAddr:          ready.Address,
		FingerprintSHA256: ready.FingerprintSHA256,
		TransferID:        transferID,
		InputPath:         inputPath,
		TracePath:         senderTrace,
		Timeout:           10 * time.Second,
	})
	if err != nil {
		t.Fatalf("SendTLS() error = %v", err)
	}
	receiver := <-receiveResult
	if receiver.err != nil {
		t.Fatalf("ReceiveTLS() error = %v", receiver.err)
	}
	if elapsed := time.Since(testStarted); elapsed >= 2*time.Second {
		t.Fatalf("successful transfer cleanup took %s, want less than 2s", elapsed)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("received payload does not match: got %d bytes, want %d", len(got), len(payload))
	}
	wantHash := sha256.Sum256(payload)
	for role, summary := range map[string]TransferSummary{"sender": senderSummary, "receiver": receiver.summary} {
		if summary.Engine != EngineTLS8 || summary.Connections != TLSLaneCount {
			t.Fatalf("%s engine/connections = %q/%d", role, summary.Engine, summary.Connections)
		}
		if summary.SizeBytes != int64(len(payload)) {
			t.Fatalf("%s size = %d, want %d", role, summary.SizeBytes, len(payload))
		}
		if summary.SHA256 != hex.EncodeToString(wantHash[:]) {
			t.Fatalf("%s SHA-256 = %q", role, summary.SHA256)
		}
		if summary.TLSVersion != "TLS1.3" || summary.ALPN != TLSProtocol || summary.TLSCipher == "" {
			t.Fatalf("%s TLS facts = version %q ALPN %q cipher %q", role, summary.TLSVersion, summary.ALPN, summary.TLSCipher)
		}
		if !summary.PinVerified {
			t.Fatalf("%s pin_verified = false", role)
		}
		if summary.TransferElapsedMS < 1 || summary.CommandElapsedMS < summary.TransferElapsedMS {
			t.Fatalf("%s timing = transfer %d ms command %d ms", role, summary.TransferElapsedMS, summary.CommandElapsedMS)
		}
		if sumLaneBytes(summary.LaneBytes) != int64(len(payload)) {
			t.Fatalf("%s lane bytes = %v", role, summary.LaneBytes)
		}
	}

	for _, tracePath := range []string{senderTrace, receiverTrace} {
		trace, err := os.ReadFile(tracePath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(trace), "timestamp_unix_ms,elapsed_ms,role,lane_0_bytes") {
			t.Fatalf("trace %s missing header: %q", tracePath, trace)
		}
		if strings.Count(string(trace), "\n") < 2 {
			t.Fatalf("trace %s missing final sample", tracePath)
		}
	}

	conn, err := net.DialTimeout("tcp", ready.Address, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("listener %s remained reachable after transfer", ready.Address)
	}
}

func TestTLSListeningSenderTransferUsesEightPinnedLanesAndPreservesFile(t *testing.T) {
	testStarted := time.Now()
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.bin")
	outputPath := filepath.Join(tempDir, "output.bin")
	readyPath := filepath.Join(tempDir, "ready.json")
	senderTrace := filepath.Join(tempDir, "sender.csv")
	receiverTrace := filepath.Join(tempDir, "receiver.csv")
	payload := deterministicPayload(8<<20 + 37)
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	sendResult := make(chan tlsTestResult, 1)
	go func() {
		summary, err := SendTLSListening(context.Background(), TLSSendListenConfig{
			ListenAddr: "127.0.0.1:0",
			InputPath:  inputPath,
			ReadyFile:  readyPath,
			TracePath:  senderTrace,
			Timeout:    10 * time.Second,
		})
		sendResult <- tlsTestResult{summary: summary, err: err}
	}()

	ready := waitForReady(t, readyPath)
	receiverSummary, err := ReceiveTLSConnecting(context.Background(), TLSReceiveConnectConfig{
		PeerAddr:          ready.Address,
		FingerprintSHA256: ready.FingerprintSHA256,
		TransferID:        decodeTransferID(t, ready.TransferID),
		OutputPath:        outputPath,
		TracePath:         receiverTrace,
		Timeout:           10 * time.Second,
	})
	if err != nil {
		t.Fatalf("ReceiveTLSConnecting() error = %v", err)
	}
	sender := <-sendResult
	if sender.err != nil {
		t.Fatalf("SendTLSListening() error = %v", sender.err)
	}
	if elapsed := time.Since(testStarted); elapsed >= 2*time.Second {
		t.Fatalf("successful transfer cleanup took %s, want less than 2s", elapsed)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received payload does not match: got %d bytes, want %d", len(got), len(payload))
	}
	wantHash := sha256.Sum256(payload)
	for role, summary := range map[string]TransferSummary{"sender": sender.summary, "receiver": receiverSummary} {
		if summary.Engine != EngineTLS8 || summary.Connections != TLSLaneCount {
			t.Fatalf("%s engine/connections = %q/%d", role, summary.Engine, summary.Connections)
		}
		if summary.Role != role {
			t.Fatalf("%s summary role = %q", role, summary.Role)
		}
		if summary.SizeBytes != int64(len(payload)) || summary.SHA256 != hex.EncodeToString(wantHash[:]) {
			t.Fatalf("%s size/hash = %d/%q", role, summary.SizeBytes, summary.SHA256)
		}
		if summary.TLSVersion != "TLS1.3" || summary.ALPN != TLSProtocol || summary.TLSCipher == "" || !summary.PinVerified {
			t.Fatalf("%s TLS facts = version %q ALPN %q cipher %q pin %t", role, summary.TLSVersion, summary.ALPN, summary.TLSCipher, summary.PinVerified)
		}
		if sumLaneBytes(summary.LaneBytes) != int64(len(payload)) {
			t.Fatalf("%s lane bytes = %v", role, summary.LaneBytes)
		}
	}

	conn, err := net.DialTimeout("tcp", ready.Address, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("listener %s remained reachable after transfer", ready.Address)
	}
}

func TestTLSSenderRejectsWrongFingerprint(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.bin")
	if err := os.WriteFile(inputPath, deterministicPayload(1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(tempDir, "ready.json")
	receiveResult := make(chan error, 1)
	go func() {
		_, err := ReceiveTLS(context.Background(), TLSReceiveConfig{
			ListenAddr: "127.0.0.1:0",
			OutputPath: filepath.Join(tempDir, "output.bin"),
			ReadyFile:  readyPath,
			TracePath:  filepath.Join(tempDir, "receiver.csv"),
			Timeout:    750 * time.Millisecond,
		})
		receiveResult <- err
	}()
	ready := waitForReady(t, readyPath)

	_, err := SendTLS(context.Background(), TLSSendConfig{
		PeerAddr:          ready.Address,
		FingerprintSHA256: strings.Repeat("0", 64),
		TransferID:        decodeTransferID(t, ready.TransferID),
		InputPath:         inputPath,
		TracePath:         filepath.Join(tempDir, "sender.csv"),
		Timeout:           750 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("SendTLS() error = %v, want fingerprint failure", err)
	}
	if err := <-receiveResult; err == nil {
		t.Fatal("ReceiveTLS() error = nil after rejected clients")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "output.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receiver created output before lane validation: %v", err)
	}
}

func TestTLSReceiveCancellationClosesListener(t *testing.T) {
	tempDir := t.TempDir()
	readyPath := filepath.Join(tempDir, "ready.json")
	ctx, cancel := context.WithCancel(context.Background())
	receiveResult := make(chan error, 1)
	go func() {
		_, err := ReceiveTLS(ctx, TLSReceiveConfig{
			ListenAddr: "127.0.0.1:0",
			OutputPath: filepath.Join(tempDir, "output.bin"),
			ReadyFile:  readyPath,
			TracePath:  filepath.Join(tempDir, "receiver.csv"),
			Timeout:    10 * time.Second,
		})
		receiveResult <- err
	}()
	ready := waitForReady(t, readyPath)
	cancel()
	select {
	case err := <-receiveResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ReceiveTLS() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReceiveTLS() did not return after cancellation")
	}
	if conn, err := net.DialTimeout("tcp", ready.Address, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("listener remained open after cancellation")
	}
}

func TestRoundedUpMillisecondsPreservesSubMillisecondTiming(t *testing.T) {
	tests := []struct {
		duration time.Duration
		want     int64
	}{
		{duration: 0, want: 0},
		{duration: time.Nanosecond, want: 1},
		{duration: time.Millisecond, want: 1},
		{duration: time.Millisecond + time.Nanosecond, want: 2},
	}
	for _, tt := range tests {
		if got := roundedUpMilliseconds(tt.duration); got != tt.want {
			t.Errorf("roundedUpMilliseconds(%s) = %d, want %d", tt.duration, got, tt.want)
		}
	}
}

func TestSendTLSChunkCompletesShortWrites(t *testing.T) {
	payload := deterministicPayload(1024)
	writer := &shortWriter{maximum: 7}
	counters := &tlsTransferCounters{}

	err := sendTLSChunk(context.Background(), writer, bytes.NewReader(payload), 0, ByteRange{Length: int64(len(payload))}, make([]byte, len(payload)), counters)

	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.buffer.Bytes(), payload) {
		t.Fatal("short-write output does not match input")
	}
	if got := counters.lanes[0].Load(); got != int64(len(payload)) {
		t.Fatalf("committed bytes = %d, want %d", got, len(payload))
	}
}

func TestSendTLSChunkRejectsNoProgressWriter(t *testing.T) {
	err := sendTLSChunk(context.Background(), zeroWriter{}, bytes.NewReader([]byte("payload")), 0, ByteRange{Length: 7}, make([]byte, 7), &tlsTransferCounters{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
}

func TestReceiveTLSChunkRejectsShortWriteAt(t *testing.T) {
	header := TLSChunkHeader{Length: 7}
	err := receiveTLSChunk(context.Background(), bytes.NewReader([]byte("payload")), shortWriterAt{}, 0, header, make([]byte, 7), &tlsTransferCounters{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
}

func TestReceiveTLSPayloadsRejectsMissingOrLegacyLanes(t *testing.T) {
	for name, lanes := range map[string][]tlsAcceptedLane{
		"missing":         nil,
		"legacy unframed": {{header: LaneHeader{TotalSize: 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := receiveTLSPayloads(context.Background(), lanes, shortWriterAt{}, &tlsTransferCounters{}); err == nil {
				t.Fatal("receiveTLSPayloads() error = nil")
			}
		})
	}
}

type tlsTestResult struct {
	summary TransferSummary
	err     error
}

func waitForReady(t *testing.T, path string) Ready {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			var ready Ready
			if err := json.Unmarshal(raw, &ready); err != nil {
				t.Fatalf("decode ready file: %v", err)
			}
			return ready
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ready file %s was not created", path)
	return Ready{}
}

func decodeTransferID(t *testing.T, value string) [16]byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		t.Fatalf("transfer ID %q is invalid: %v", value, err)
	}
	var result [16]byte
	copy(result[:], raw)
	return result
}

func deterministicPayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte((index*31 + 17) % 251)
	}
	return payload
}

func sumLaneBytes(values [TLSLaneCount]int64) int64 {
	var total int64
	for _, value := range values {
		total += value
	}
	return total
}

type shortWriter struct {
	maximum int
	buffer  bytes.Buffer
}

func (w *shortWriter) Write(payload []byte) (int, error) {
	return w.buffer.Write(payload[:min(len(payload), w.maximum)])
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type shortWriterAt struct{}

func (shortWriterAt) WriteAt(payload []byte, _ int64) (int, error) {
	return max(0, len(payload)-1), nil
}
