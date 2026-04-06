package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
)

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
	wg.Add(1)
	go func() {
		defer wg.Done()
		code := runServer([]string{"--mode", "blast"}, io.Discard, io.Discard)
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

	if _, err := probe.Send(ctx, senderConn, serverConn.LocalAddr().String(), bytes.NewReader([]byte("hello")), probe.SendConfig{Blast: true}); err != nil {
		t.Fatalf("probe.Send() error = %v", err)
	}

	wg.Wait()
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
