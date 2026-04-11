package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
)

type readyNotifyWriter struct {
	once sync.Once
	ch   chan struct{}
}

func TestServerDoneJSONRoundTripsFirstByteMeasured(t *testing.T) {
	tests := []struct {
		name string
		done serverDone
		want *bool
	}{
		{name: "nil", done: serverDone{}, want: nil},
		{name: "false", done: serverDone{FirstByteMeasured: boolPtr(false)}, want: boolPtr(false)},
		{name: "true", done: serverDone{FirstByteMeasured: boolPtr(true)}, want: boolPtr(true)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotJSON, err := json.Marshal(tc.done)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			var decoded serverDone
			if err := json.Unmarshal(gotJSON, &decoded); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if tc.want == nil {
				if decoded.FirstByteMeasured != nil {
					t.Fatalf("decoded.FirstByteMeasured = %#v, want nil", decoded.FirstByteMeasured)
				}
				return
			}
			if decoded.FirstByteMeasured == nil || *decoded.FirstByteMeasured != *tc.want {
				t.Fatalf("decoded.FirstByteMeasured = %#v, want %v", decoded.FirstByteMeasured, *tc.want)
			}
		})
	}
}

func TestClientDoneJSONRoundTripsFirstByteMeasured(t *testing.T) {
	tests := []struct {
		name string
		done clientDone
		want *bool
	}{
		{name: "nil", done: clientDone{}, want: nil},
		{name: "false", done: clientDone{FirstByteMeasured: boolPtr(false)}, want: boolPtr(false)},
		{name: "true", done: clientDone{FirstByteMeasured: boolPtr(true)}, want: boolPtr(true)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotJSON, err := json.Marshal(tc.done)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			var decoded clientDone
			if err := json.Unmarshal(gotJSON, &decoded); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if tc.want == nil {
				if decoded.FirstByteMeasured != nil {
					t.Fatalf("decoded.FirstByteMeasured = %#v, want nil", decoded.FirstByteMeasured)
				}
				return
			}
			if decoded.FirstByteMeasured == nil || *decoded.FirstByteMeasured != *tc.want {
				t.Fatalf("decoded.FirstByteMeasured = %#v, want %v", decoded.FirstByteMeasured, *tc.want)
			}
		})
	}
}

func TestBuildServerDoneMarksUnmeasuredFirstByteExplicitFalse(t *testing.T) {
	done := buildServerDone(probe.TransferStats{
		StartedAt:     time.Unix(0, 0),
		CompletedAt:   time.Unix(1, 0),
		BytesReceived: 10,
	})
	if done.FirstByteMeasured == nil || *done.FirstByteMeasured {
		t.Fatalf("done.FirstByteMeasured = %#v, want false", done.FirstByteMeasured)
	}
	got, err := json.Marshal(done)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded["first_byte_measured"] != false {
		t.Fatalf("decoded first_byte_measured = %#v, want false", decoded["first_byte_measured"])
	}
}

func TestBuildClientDoneMarksMeasuredFirstByteExplicitTrue(t *testing.T) {
	done := buildClientDone(probe.TransferStats{
		StartedAt:   time.Unix(0, 0),
		FirstByteAt: time.Unix(0, 5),
		CompletedAt: time.Unix(1, 0),
		BytesSent:   10,
	})
	if done.FirstByteMeasured == nil || !*done.FirstByteMeasured {
		t.Fatalf("done.FirstByteMeasured = %#v, want true", done.FirstByteMeasured)
	}
	got, err := json.Marshal(done)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded["first_byte_measured"] != true {
		t.Fatalf("decoded first_byte_measured = %#v, want true", decoded["first_byte_measured"])
	}
}

func (w *readyNotifyWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("READY ")) {
		w.once.Do(func() { close(w.ch) })
	}
	return len(p), nil
}

func TestRunOrchestratePrintsJSONReport(t *testing.T) {
	oldRunOrchestrateProbe := runOrchestrateProbe
	defer func() { runOrchestrateProbe = oldRunOrchestrateProbe }()
	runOrchestrateProbe = func(ctx context.Context, cfg probe.OrchestrateConfig) (probe.RunReport, error) {
		return probe.RunReport{Host: cfg.Host, Mode: cfg.Mode, Direction: "forward", SizeBytes: cfg.SizeBytes, Direct: true}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--user", "root", "--mode", "raw", "--size-bytes", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"host\": \"ktzlxc\"") {
		t.Fatalf("stdout missing host JSON: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"mode\": \"raw\"") {
		t.Fatalf("stdout missing mode JSON: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "user") || strings.Contains(stdout.String(), "remote_path") || strings.Contains(stdout.String(), "listen_addr") {
		t.Fatalf("stdout included extra fields: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"direct\": true") {
		t.Fatalf("stdout missing direct=true: %s", stdout.String())
	}
}

func TestRunServerInvokesProbeReceive(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverProbeCandidates := discoverProbeCandidates
	defer func() {
		listenPacket = oldListenPacket
		discoverProbeCandidates = oldDiscoverProbeCandidates
	}()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	listenPacket = func(network, address string) (net.PacketConn, error) {
		if address != ":0" {
			t.Fatalf("listen address = %q, want %q", address, ":0")
		}
		return serverConn, nil
	}
	discoverProbeCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		code := runServer([]string{"--mode", "raw"}, io.Discard, io.Discard)
		if code != 0 {
			t.Errorf("runServer() code = %d, want 0", code)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	if _, err := probe.Send(ctx, senderConn, serverConn.LocalAddr().String(), bytes.NewReader([]byte("hello")), probe.SendConfig{Raw: true}); err != nil {
		t.Fatalf("probe.Send() error = %v", err)
	}

	wg.Wait()
}

func TestRunClientInvokesProbeSend(t *testing.T) {
	oldListenPacket := listenPacket
	oldClientTimeout := clientTimeout
	defer func() { listenPacket = oldListenPacket }()
	defer func() { clientTimeout = oldClientTimeout }()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	listenPacket = func(network, address string) (net.PacketConn, error) {
		if address != ":0" {
			t.Fatalf("listen address = %q, want %q", address, ":0")
		}
		return net.ListenPacket(network, address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := probe.ReceiveToWriter(ctx, serverConn, "", io.Discard, probe.ReceiveConfig{Raw: true})
		done <- err
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runClient([]string{"--host", serverConn.LocalAddr().String(), "--mode", "raw"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runClient() code = %d, want 0; stderr=%s", code, stderr.String())
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReceiveToWriter() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for ReceiveToWriter")
	}
}

func TestRunClientTimesOutWithoutPeer(t *testing.T) {
	oldClientTimeout := clientTimeout
	defer func() { clientTimeout = oldClientTimeout }()
	clientTimeout = 20 * time.Millisecond

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runClient([]string{"--host", "127.0.0.1:1", "--mode", "raw"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runClient() code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "deadline exceeded") && !strings.Contains(stderr.String(), "i/o timeout") {
		t.Fatalf("stderr = %q, want timeout", stderr.String())
	}
}

func TestRunClientPassesRawTuningFlags(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverProbeCandidates := discoverProbeCandidates
	oldProbeSend := probeSend
	defer func() {
		listenPacket = oldListenPacket
		discoverProbeCandidates = oldDiscoverProbeCandidates
		probeSend = oldProbeSend
	}()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	listenPacket = func(network, address string) (net.PacketConn, error) {
		if address != ":0" {
			t.Fatalf("listen address = %q, want %q", address, ":0")
		}
		return clientConn, nil
	}
	discoverProbeCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}

	var gotRemote string
	var gotCfg probe.SendConfig
	probeSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg probe.SendConfig) (probe.TransferStats, error) {
		gotRemote = remoteAddr
		gotCfg = cfg
		now := time.Now()
		return probe.TransferStats{StartedAt: now, FirstByteAt: now, CompletedAt: now}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runClient([]string{
		"--host", "127.0.0.1:9999",
		"--mode", "raw",
		"--chunk-size", "1234",
		"--window-size", "321",
		"--parallel", "4",
		"--rate-mbps", "123",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runClient() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if gotRemote != "127.0.0.1:9999" {
		t.Fatalf("remote addr = %q, want %q", gotRemote, "127.0.0.1:9999")
	}
	if !gotCfg.Raw || gotCfg.Blast {
		t.Fatalf("send config = %+v, want raw mode only", gotCfg)
	}
	if gotCfg.ChunkSize != 1234 {
		t.Fatalf("chunk size = %d, want %d", gotCfg.ChunkSize, 1234)
	}
	if gotCfg.WindowSize != 321 {
		t.Fatalf("window size = %d, want %d", gotCfg.WindowSize, 321)
	}
	if gotCfg.Parallel != 4 {
		t.Fatalf("parallel = %d, want %d", gotCfg.Parallel, 4)
	}
	if gotCfg.RateMbps != 123 {
		t.Fatalf("rate mbps = %d, want %d", gotCfg.RateMbps, 123)
	}
}

func TestRunOrchestrateRejectsAeadMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--mode", "aead"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runOrchestrate() code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "aead not implemented yet") {
		t.Fatalf("stderr = %q, want aead rejection", stderr.String())
	}
}

func TestRunOrchestrateAcceptsBlastMode(t *testing.T) {
	oldRunOrchestrateProbe := runOrchestrateProbe
	defer func() { runOrchestrateProbe = oldRunOrchestrateProbe }()
	runOrchestrateProbe = func(ctx context.Context, cfg probe.OrchestrateConfig) (probe.RunReport, error) {
		return probe.RunReport{Host: cfg.Host, Mode: cfg.Mode, Direction: "forward", SizeBytes: cfg.SizeBytes, Direct: true}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--mode", "blast", "--size-bytes", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"mode\": \"blast\"") {
		t.Fatalf("stdout missing blast JSON: %s", stdout.String())
	}
}

func TestRunOrchestrateAcceptsWireGuardMode(t *testing.T) {
	oldRunOrchestrateProbe := runOrchestrateProbe
	defer func() { runOrchestrateProbe = oldRunOrchestrateProbe }()
	runOrchestrateProbe = func(ctx context.Context, cfg probe.OrchestrateConfig) (probe.RunReport, error) {
		return probe.RunReport{Host: cfg.Host, Mode: cfg.Mode, Direction: "forward", SizeBytes: cfg.SizeBytes, Direct: true}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--mode", "wg", "--size-bytes", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"mode\": \"wg\"") {
		t.Fatalf("stdout missing wg JSON: %s", stdout.String())
	}
}

func TestRunOrchestrateAcceptsWireGuardIperfMode(t *testing.T) {
	oldRunOrchestrateProbe := runOrchestrateProbe
	defer func() { runOrchestrateProbe = oldRunOrchestrateProbe }()
	runOrchestrateProbe = func(ctx context.Context, cfg probe.OrchestrateConfig) (probe.RunReport, error) {
		return probe.RunReport{Host: cfg.Host, Mode: cfg.Mode, Direction: "forward", SizeBytes: cfg.SizeBytes, Direct: true}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--mode", "wgiperf", "--size-bytes", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"mode\": \"wgiperf\"") {
		t.Fatalf("stdout missing wgiperf JSON: %s", stdout.String())
	}
}

func TestRunOrchestrateRejectsMissingHost(t *testing.T) {
	oldRunOrchestrateProbe := runOrchestrateProbe
	defer func() { runOrchestrateProbe = oldRunOrchestrateProbe }()
	runOrchestrateProbe = func(ctx context.Context, cfg probe.OrchestrateConfig) (probe.RunReport, error) {
		return probe.RunReport{Host: cfg.Host, Mode: cfg.Mode, Direction: "forward", SizeBytes: cfg.SizeBytes, Direct: true}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0 for help", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = runOrchestrate([]string{"--user", "root"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runOrchestrate() code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "host is required") {
		t.Fatalf("stderr = %q, want host validation", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runOrchestrate([]string{"--host", "   "}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runOrchestrate() code = %d, want 2 for whitespace host; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "host is required") {
		t.Fatalf("stderr = %q, want whitespace host validation", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runOrchestrate([]string{"--host", " ktzlxc "}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0 for trimmed host; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"host\": \"ktzlxc\"") {
		t.Fatalf("stdout = %s, want trimmed host in report", stdout.String())
	}
}

func TestRunOrchestrateAcceptsReverseDirection(t *testing.T) {
	oldRunOrchestrateProbe := runOrchestrateProbe
	defer func() { runOrchestrateProbe = oldRunOrchestrateProbe }()

	runOrchestrateProbe = func(ctx context.Context, cfg probe.OrchestrateConfig) (probe.RunReport, error) {
		return probe.RunReport{Host: cfg.Host, Mode: cfg.Mode, Transport: cfg.Transport, Direction: cfg.Direction, SizeBytes: cfg.SizeBytes, Direct: true}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--direction", "reverse"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0; stderr=%s", code, stderr.String())
	}
}

func TestRunOrchestrateRejectsNegativeSize(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--size-bytes", "-1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runOrchestrate() code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "size bytes must be non-negative") {
		t.Fatalf("stderr = %q, want size validation", stderr.String())
	}
}

func TestRunServerRejectsAeadMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runServer([]string{"--mode", "aead"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runServer() code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "aead not implemented yet") {
		t.Fatalf("stderr = %q, want aead rejection", stderr.String())
	}
}

func TestRunServerAcceptsBlastMode(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverProbeCandidates := discoverProbeCandidates
	defer func() {
		listenPacket = oldListenPacket
		discoverProbeCandidates = oldDiscoverProbeCandidates
	}()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	listenPacket = func(network, address string) (net.PacketConn, error) {
		if address != ":0" {
			t.Fatalf("listen address = %q, want %q", address, ":0")
		}
		return serverConn, nil
	}
	discoverProbeCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}

	var wg sync.WaitGroup
	readyCh := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		code := runServer([]string{"--mode", "blast", "--size-bytes", "5"}, &readyNotifyWriter{ch: readyCh}, io.Discard)
		if code != 0 {
			t.Errorf("runServer() code = %d, want 0", code)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case <-readyCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for server READY: %v", ctx.Err())
	}

	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	if _, err := probe.Send(ctx, senderConn, serverConn.LocalAddr().String(), bytes.NewReader([]byte("hello")), probe.SendConfig{Blast: true}); err != nil {
		t.Fatalf("probe.Send() error = %v", err)
	}

	wg.Wait()
}

func TestOpenServerPacketConnsUsesDistinctPortsForParallelBlast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conns, err := openServerPacketConns(ctx, "blast", "127.0.0.1:0", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer closePacketConns(conns)
	if len(conns) != 3 {
		t.Fatalf("len(conns) = %d, want 3", len(conns))
	}

	seen := make(map[string]bool)
	for _, conn := range conns {
		addr := conn.LocalAddr().String()
		if seen[addr] {
			t.Fatalf("parallel blast reused local address %s, want distinct sockets", addr)
		}
		seen[addr] = true
	}
}

func TestDiscoverServerCandidatesIncludesEveryParallelSocket(t *testing.T) {
	oldDiscoverProbeCandidates := discoverProbeCandidates
	defer func() { discoverProbeCandidates = oldDiscoverProbeCandidates }()

	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	discoverProbeCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := discoverServerCandidates(ctx, []net.PacketConn{a, b})
	if err != nil {
		t.Fatal(err)
	}
	gotStrings := probe.CandidateStrings(got)
	for _, want := range []string{a.LocalAddr().String(), b.LocalAddr().String()} {
		if !containsString(gotStrings, want) {
			t.Fatalf("discoverServerCandidates() = %v, missing %s", gotStrings, want)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunClientRejectsAeadMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runClient([]string{"--host", "127.0.0.1:1", "--mode", "aead"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runClient() code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "aead not implemented yet") {
		t.Fatalf("stderr = %q, want aead rejection", stderr.String())
	}
}

func TestRunClientAcceptsBlastMode(t *testing.T) {
	oldListenPacket := listenPacket
	oldClientTimeout := clientTimeout
	defer func() { listenPacket = oldListenPacket }()
	defer func() { clientTimeout = oldClientTimeout }()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	listenPacket = func(network, address string) (net.PacketConn, error) {
		if address != ":0" {
			t.Fatalf("listen address = %q, want %q", address, ":0")
		}
		return net.ListenPacket(network, address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := probe.ReceiveToWriter(ctx, serverConn, "", io.Discard, probe.ReceiveConfig{Blast: true})
		done <- err
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runClient([]string{"--host", serverConn.LocalAddr().String(), "--mode", "blast"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runClient() code = %d, want 0; stderr=%s", code, stderr.String())
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReceiveToWriter() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for ReceiveToWriter")
	}
}

func TestRunClientBlastParallelSendsOneSharePerPeerCandidate(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverProbeCandidates := discoverProbeCandidates
	oldProbeSend := probeSend
	oldClientTimeout := clientTimeout
	defer func() {
		listenPacket = oldListenPacket
		discoverProbeCandidates = oldDiscoverProbeCandidates
		probeSend = oldProbeSend
		clientTimeout = oldClientTimeout
	}()
	clientTimeout = 2 * time.Second

	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}
	discoverProbeCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}

	var mu sync.Mutex
	var gotRemotes []string
	var gotSizes []int64
	var gotRates []int
	probeSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg probe.SendConfig) (probe.TransferStats, error) {
		if !cfg.Blast || cfg.Raw {
			return probe.TransferStats{}, fmt.Errorf("send config = %+v, want blast mode only", cfg)
		}
		n, err := io.Copy(io.Discard, src)
		if err != nil {
			return probe.TransferStats{}, err
		}
		mu.Lock()
		gotRemotes = append(gotRemotes, remoteAddr)
		gotSizes = append(gotSizes, n)
		gotRates = append(gotRates, cfg.RateMbps)
		mu.Unlock()
		now := time.Now()
		return probe.TransferStats{BytesSent: n, StartedAt: now, FirstByteAt: now, CompletedAt: now}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runClient([]string{
		"--mode", "blast",
		"--transport", "batched",
		"--peer-candidates", "203.0.113.1:4001,203.0.113.1:4002",
		"--parallel", "2",
		"--rate-mbps", "2000",
		"--size-bytes", "11",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runClient() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	sort.Strings(gotRemotes)
	sort.Slice(gotSizes, func(i, j int) bool { return gotSizes[i] > gotSizes[j] })
	if strings.Join(gotRemotes, ",") != "203.0.113.1:4001,203.0.113.1:4002" {
		t.Fatalf("remote addresses = %v, want both peer candidates", gotRemotes)
	}
	if len(gotSizes) != 2 || gotSizes[0] != 6 || gotSizes[1] != 5 {
		t.Fatalf("share sizes = %v, want [6 5]", gotSizes)
	}
	sort.Ints(gotRates)
	if len(gotRates) != 2 || gotRates[0] != 1000 || gotRates[1] != 1000 {
		t.Fatalf("rate mbps = %v, want [1000 1000]", gotRates)
	}
}

func TestSelectClientRemoteAddrsByConnAvoidsDuplicateRemotePorts(t *testing.T) {
	observedByConn := [][]net.Addr{
		{mustClientUDPAddr(t, "100.107.23.123:51048")},
		{mustClientUDPAddr(t, "68.20.14.192:51048"), mustClientUDPAddr(t, "68.20.14.192:52315")},
		{mustClientUDPAddr(t, "68.20.14.192:35365")},
	}
	fallback := []string{"68.20.14.192:35365", "68.20.14.192:52315", "68.20.14.192:51048"}

	got := selectClientRemoteAddrsByConn(observedByConn, fallback, 3)
	want := []string{"100.107.23.123:51048", "68.20.14.192:52315", "68.20.14.192:35365"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selectClientRemoteAddrsByConn() = %v, want %v", got, want)
	}
}

func TestSelectClientRemoteAddrsByConnBackfillsEmptyLanesFromAnyUnusedFallback(t *testing.T) {
	observedByConn := [][]net.Addr{
		{mustClientUDPAddr(t, "68.20.14.192:51048")},
		{mustClientUDPAddr(t, "100.107.23.123:51048")},
		{mustClientUDPAddr(t, "68.20.14.192:50924")},
		{mustClientUDPAddr(t, "68.20.14.192:50924")},
	}
	fallback := []string{
		"68.20.14.192:51048",
		"68.20.14.192:50924",
		"68.20.14.192:37597",
		"68.20.14.192:47634",
	}

	got := selectClientRemoteAddrsByConn(observedByConn, fallback, 4)
	want := []string{"68.20.14.192:51048", "68.20.14.192:37597", "68.20.14.192:50924", "68.20.14.192:47634"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selectClientRemoteAddrsByConn() = %v, want %v", got, want)
	}
}

func mustClientUDPAddr(t *testing.T, raw string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestClientSizedReaderDoesNotRewritePayloadBuffer(t *testing.T) {
	reader := sizedReader(2)
	buf := []byte{1, 2, 3, 4}

	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 2 {
		t.Fatalf("Read() n = %d, want 2", n)
	}
	if got := fmt.Sprint(buf); got != "[1 2 3 4]" {
		t.Fatalf("buffer = %s, want unchanged probe payload buffer", got)
	}
}
