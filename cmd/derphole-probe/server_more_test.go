// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/probe"
)

func TestServerRunConfigValidationAndDefaults(t *testing.T) {
	var stderr bytes.Buffer
	cfg, code, failed := parseServerRunConfig([]string{"--mode", "blast", "--parallel", "3", "--peer-candidates", "127.0.0.1:1,[::1]:2"}, &stderr)
	if failed || code != 0 {
		t.Fatalf("parseServerRunConfig() failed=%v code=%d stderr=%q", failed, code, stderr.String())
	}
	if cfg.listenAddr != ":0" || cfg.transport != "legacy" || cfg.flags.Parallel != 3 {
		t.Fatalf("cfg = %+v, want listen :0 legacy parallel 3", cfg)
	}
	if len(cfg.peerCandidates) != 2 {
		t.Fatalf("peerCandidates = %v, want two parsed candidates", cfg.peerCandidates)
	}

	stderr.Reset()
	if _, code, failed := parseServerRunConfig([]string{"extra"}, &stderr); !failed || code != 2 || !strings.Contains(stderr.String(), "usage: derphole-probe server") {
		t.Fatalf("parseServerRunConfig(extra) failed=%v code=%d stderr=%q, want usage failure", failed, code, stderr.String())
	}
	stderr.Reset()
	if _, code, failed := parseServerRunConfig([]string{"--mode", "aead"}, &stderr); !failed || code != 2 || !strings.Contains(stderr.String(), "aead not implemented yet") {
		t.Fatalf("parseServerRunConfig(aead) failed=%v code=%d stderr=%q, want aead failure", failed, code, stderr.String())
	}
	stderr.Reset()
	if _, code, failed := parseServerRunConfig([]string{"--transport", "bogus"}, &stderr); !failed || code != 2 || !strings.Contains(stderr.String(), "unsupported transport") {
		t.Fatalf("parseServerRunConfig(bogus transport) failed=%v code=%d stderr=%q, want transport failure", failed, code, stderr.String())
	}
}

func TestServerWireGuardConfigAndReceiveValidation(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	cfg := serverRunConfig{
		mode:           "blast",
		transport:      "batched",
		peerCandidates: []net.Addr{peer},
		flags: serverFlags{
			WGPrivateKey: "priv",
			WGPeerPublic: "peer",
			WGLocalAddr:  "169.254.1.1",
			WGPeerAddr:   "169.254.1.2",
			WGPort:       1234,
			Parallel:     4,
			SizeBytes:    0,
		},
	}
	wg := serverWireGuardConfig(cfg)
	if wg.Transport != "batched" || wg.PrivateKeyHex != "priv" || wg.PeerPublicHex != "peer" || wg.Port != 1234 || wg.Streams != 4 || len(wg.PeerCandidates) != 1 {
		t.Fatalf("serverWireGuardConfig() = %+v, want copied config", wg)
	}

	if _, err := receiveServerTransfer(context.Background(), nil, nil, cfg); err == nil || !strings.Contains(err.Error(), "size bytes is required") {
		t.Fatalf("receiveServerTransfer(blast missing size) error = %v, want size required", err)
	}
}

func TestRunServerTransferWritesReadyBeforeReceiveError(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cfg := serverRunConfig{mode: "blast", transport: "legacy", flags: serverFlags{SizeBytes: 0}}
	var stdout bytes.Buffer
	_, err = runServerTransfer(context.Background(), conn, []net.PacketConn{conn}, cfg, nil, &stdout)
	if err == nil || !strings.Contains(err.Error(), "size bytes is required") {
		t.Fatalf("runServerTransfer() error = %v, want size required", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "READY ") {
		t.Fatalf("stdout = %q, want READY line", stdout.String())
	}
	var ready serverReady
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[0], "READY ")), &ready); err != nil {
		t.Fatalf("READY json error = %v", err)
	}
	if ready.Addr == "" {
		t.Fatal("READY addr empty")
	}
}

func TestRunWGIPerfServerReportsStartupFailure(t *testing.T) {
	_, err := runWGIPerfServer(context.Background(), nil, serverRunConfig{}, nil, io.Discard)
	if err == nil {
		t.Fatal("runWGIPerfServer(nil conn) error = nil, want startup failure")
	}
}

func TestBuildServerDoneFirstByteMeasured(t *testing.T) {
	started := time.Unix(100, 0)
	done := buildServerDone(probe.TransferStats{
		StartedAt:     started,
		CompletedAt:   started.Add(2 * time.Second),
		FirstByteAt:   time.Time{},
		BytesReceived: 123,
	})
	if done.FirstByteMeasured == nil || *done.FirstByteMeasured {
		t.Fatalf("FirstByteMeasured = %#v, want false pointer", done.FirstByteMeasured)
	}
	if done.DurationMS != 2000 || done.FirstByteMS != 0 {
		t.Fatalf("durations = %d/%d, want 2000/0", done.DurationMS, done.FirstByteMS)
	}
}
