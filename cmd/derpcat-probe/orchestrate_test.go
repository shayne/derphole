package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
)

func TestRunOrchestratePrintsJSONReport(t *testing.T) {
	oldPath := os.Getenv("PATH")
	sshDir := t.TempDir()
	sshPath := filepath.Join(sshDir, "ssh")
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", sshDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Setenv("PATH", oldPath) }()

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
	if !strings.Contains(stdout.String(), "\"direct\": false") {
		t.Fatalf("stdout missing direct=false: %s", stdout.String())
	}
}

func TestRunServerInvokesProbeReceive(t *testing.T) {
	oldListenPacket := listenPacket
	defer func() { listenPacket = oldListenPacket }()

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
	defer func() { listenPacket = oldListenPacket }()

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
