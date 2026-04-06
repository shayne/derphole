package probe

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRemoteCommandIncludesProbeBinaryAndServerMode(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ServerCommand(ServerConfig{ListenAddr: ":0", Mode: "raw", Transport: "batched"})

	if got, want := cmd[0], "ssh"; got != want {
		t.Fatalf("cmd[0] = %q, want %q", got, want)
	}

	found := false
	for _, part := range cmd {
		if part == "/tmp/derpcat-probe" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("server command missing expected remote binary: %#v", cmd)
	}
	if !strings.Contains(strings.Join(cmd, " "), "server --listen :0 --mode raw --transport batched") {
		t.Fatalf("server command missing expected remote invocation: %#v", cmd)
	}
}

func TestRemoteClientCommandIncludesProbeBinaryAndPeerCandidates(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ClientCommand(ClientConfig{
		Mode:              "blast",
		Transport:         "batched",
		SizeBytes:         1024,
		PeerCandidatesCSV: "198.51.100.10:40000,203.0.113.10:50000",
	})

	if got, want := cmd[0], "ssh"; got != want {
		t.Fatalf("cmd[0] = %q, want %q", got, want)
	}
	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, "/tmp/derpcat-probe client --mode blast --transport batched --size-bytes 1024 --peer-candidates 198.51.100.10:40000,203.0.113.10:50000") {
		t.Fatalf("client command missing expected remote invocation: %#v", cmd)
	}
}

func TestRemoteServerCommandIncludesWireGuardArgs(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ServerCommand(ServerConfig{
		ListenAddr:        ":0",
		Mode:              "wg",
		Transport:         "legacy",
		PeerCandidatesCSV: "198.51.100.10:40000",
		WGPrivateKeyHex:   "privhex",
		WGPeerPublicHex:   "pubhex",
		WGLocalAddr:       "fd00::1",
		WGPeerAddr:        "fd00::2",
		WGPort:            7000,
		Parallel:          8,
	})

	joined := strings.Join(cmd, " ")
	for _, want := range []string{
		"/tmp/derpcat-probe",
		"server",
		"--listen :0",
		"--mode wg",
		"--transport legacy",
		"--peer-candidates 198.51.100.10:40000",
		"--wg-private privhex",
		"--wg-peer-public pubhex",
		"--wg-local-addr fd00::1",
		"--wg-peer-addr fd00::2",
		"--wg-port 7000",
		"--parallel 8",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("server command missing %q: %#v", want, cmd)
		}
	}
}

func TestRemoteClientCommandIncludesWireGuardArgs(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ClientCommand(ClientConfig{
		Mode:              "wg",
		Transport:         "legacy",
		SizeBytes:         1024,
		PeerCandidatesCSV: "198.51.100.10:40000",
		WGPrivateKeyHex:   "privhex",
		WGPeerPublicHex:   "pubhex",
		WGLocalAddr:       "fd00::2",
		WGPeerAddr:        "fd00::1",
		WGPort:            7000,
		Parallel:          8,
	})

	joined := strings.Join(cmd, " ")
	for _, want := range []string{
		"/tmp/derpcat-probe",
		"client",
		"--mode wg",
		"--transport legacy",
		"--size-bytes 1024",
		"--peer-candidates 198.51.100.10:40000",
		"--wg-private privhex",
		"--wg-peer-public pubhex",
		"--wg-local-addr fd00::2",
		"--wg-peer-addr fd00::1",
		"--wg-port 7000",
		"--parallel 8",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("client command missing %q: %#v", want, cmd)
		}
	}
}

func TestOrchestratorRejectsMissingHost(t *testing.T) {
	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Fatalf("RunOrchestrate() error = %v, want host validation error", err)
	}
}

func TestRunOrchestrateForwardTransfersAndReportsDirect(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteServer := launchRemoteServer
	oldSend := orchestrateSend
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteServer = oldLaunchRemoteServer
		orchestrateSend = oldSend
	}()

	var gotArgv []string
	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 40000}}, nil
	}
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		gotArgv = runner.ServerCommand(cfg)
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\",\"batch_size\":128,\"tx_offload\":true}}\nDONE {\"bytes_received\":1024,\"first_byte_ms\":9,\"duration_ms\":2000,\"retransmits\":0,\"packets_sent\":0,\"packets_acked\":0}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait: func() error {
				return nil
			},
		}, nil
	}
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		n, err := io.Copy(io.Discard, src)
		if err != nil {
			return TransferStats{}, err
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:    n,
			StartedAt:    startedAt,
			CompletedAt:  startedAt.Add(2 * time.Second),
			Retransmits:  3,
			PacketsSent:  12,
			PacketsAcked: 8,
			Transport:    TransportCaps{Kind: "legacy", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "raw",
		Transport: "batched",
		Direction: "forward",
		SizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if !report.Direct {
		t.Fatal("RunOrchestrate() report.Direct = false, want true")
	}
	if report.Host != "ktzlxc" || report.Mode != "raw" || report.Transport != "batched" || report.Direction != "forward" {
		t.Fatalf("RunOrchestrate() report = %#v", report)
	}
	if report.DurationMS != 2000 {
		t.Fatalf("report.DurationMS = %d, want 2000", report.DurationMS)
	}
	if report.FirstByteMS != 9 {
		t.Fatalf("report.FirstByteMS = %d, want 9", report.FirstByteMS)
	}
	if report.GoodputMbps <= 0 {
		t.Fatalf("report.GoodputMbps = %f, want > 0", report.GoodputMbps)
	}
	if report.Retransmits != 3 {
		t.Fatalf("report.Retransmits = %d, want 3", report.Retransmits)
	}
	if report.Local.Kind != "legacy" || report.Remote.Kind != "batched" {
		t.Fatalf("transport report = %#v", report)
	}
	if len(gotArgv) < 7 || gotArgv[0] != "ssh" || !strings.Contains(strings.Join(gotArgv, " "), "BatchMode=yes") || !strings.Contains(strings.Join(gotArgv, " "), "ConnectTimeout=5") || !strings.Contains(strings.Join(gotArgv, " "), "/tmp/derpcat-probe server --listen :0 --mode raw --transport batched") || !strings.Contains(strings.Join(gotArgv, " "), "--peer-candidates 198.51.100.10:40000") {
		t.Fatalf("RunOrchestrate() argv = %#v", gotArgv)
	}
}

func TestRunOrchestrateRejectsAeadMode(t *testing.T) {
	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "aead",
		SizeBytes: 1024,
	})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want aead rejection")
	}
	if !strings.Contains(err.Error(), "aead not implemented yet") {
		t.Fatalf("RunOrchestrate() error = %v, want aead rejection", err)
	}
}

func TestRunOrchestrateTrimsHost(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteServer := launchRemoteServer
	oldSend := orchestrateSend
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteServer = oldLaunchRemoteServer
		orchestrateSend = oldSend
	}()

	var gotArgv []string
	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 40000}}, nil
	}
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		gotArgv = runner.ServerCommand(cfg)
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"]}\nDONE {\"bytes_received\":1024,\"first_byte_ms\":4,\"duration_ms\":1000}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait: func() error {
				return nil
			},
		}, nil
	}
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		_, err := io.Copy(io.Discard, src)
		if err != nil {
			return TransferStats{}, err
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{BytesSent: 1024, StartedAt: startedAt, CompletedAt: startedAt.Add(time.Second)}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      " ktzlxc ",
		User:      "root",
		Mode:      "raw",
		SizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if report.Host != "ktzlxc" {
		t.Fatalf("report.Host = %q, want %q", report.Host, "ktzlxc")
	}
	if strings.Contains(strings.Join(gotArgv, " "), " ktzlxc ") {
		t.Fatalf("RunOrchestrate() argv = %#v, want trimmed host", gotArgv)
	}
}

func TestRunOrchestrateReverseTransfersAndReportsDirect(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteClient := launchRemoteClient
	oldReceive := orchestrateReceive
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteClient = oldLaunchRemoteClient
		orchestrateReceive = oldReceive
	}()

	var gotArgv []string
	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 40000}}, nil
	}
	launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
		gotArgv = runner.ClientCommand(cfg)
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\",\"batch_size\":128}}\nDONE {\"bytes_sent\":1024,\"duration_ms\":1500,\"retransmits\":2,\"packets_sent\":12,\"packets_acked\":8}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait: func() error {
				return nil
			},
		}, nil
	}
	orchestrateReceive = func(ctx context.Context, conn net.PacketConn, remoteAddr string, dst io.Writer, cfg ReceiveConfig) (TransferStats, error) {
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesReceived: 1024,
			StartedAt:     startedAt,
			FirstByteAt:   startedAt.Add(10 * time.Millisecond),
			CompletedAt:   startedAt.Add(1500 * time.Millisecond),
			Transport:     TransportCaps{Kind: "legacy", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "raw",
		Transport: "batched",
		Direction: "reverse",
		SizeBytes: 1024,
		Parallel:  4,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if report.Direction != "reverse" || report.Transport != "batched" {
		t.Fatalf("report = %#v", report)
	}
	if report.FirstByteMS != 10 {
		t.Fatalf("report.FirstByteMS = %d, want 10", report.FirstByteMS)
	}
	if report.Retransmits != 2 {
		t.Fatalf("report.Retransmits = %d, want 2", report.Retransmits)
	}
	if report.Local.Kind != "legacy" || report.Remote.Kind != "batched" {
		t.Fatalf("transport report = %#v", report)
	}
	joined := strings.Join(gotArgv, " ")
	if !strings.Contains(joined, "/tmp/derpcat-probe client --mode raw --transport batched --size-bytes 1024 --peer-candidates 198.51.100.10:40000") {
		t.Fatalf("RunOrchestrate() argv = %#v", gotArgv)
	}
	if strings.Contains(joined, "--parallel") {
		t.Fatalf("RunOrchestrate() unexpectedly passed --parallel for raw mode: %#v", gotArgv)
	}
}

func TestRunCommandIncludesCombinedOutputOnFailure(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := filepath.Join(scriptDir, "fail.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho permission denied >&2\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := runCommand(context.Background(), []string{scriptPath})
	if err == nil {
		t.Fatal("runCommand() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("runCommand() error = %v, want combined stderr", err)
	}
}

func TestProbeSendTuningDefaultsAndOverrides(t *testing.T) {
	for _, key := range []string{"DERPCAT_PROBE_WINDOW_SIZE", "DERPCAT_PROBE_CHUNK_SIZE"} {
		old := os.Getenv(key)
		defer func(k, v string) {
			if v == "" {
				_ = os.Unsetenv(k)
				return
			}
			_ = os.Setenv(k, v)
		}(key, old)
		_ = os.Unsetenv(key)
	}

	if got := probeWindowSize(); got != 1024 {
		t.Fatalf("probeWindowSize() = %d, want 1024", got)
	}
	if got := probeChunkSize(); got != defaultChunkSize {
		t.Fatalf("probeChunkSize() = %d, want %d", got, defaultChunkSize)
	}

	_ = os.Setenv("DERPCAT_PROBE_WINDOW_SIZE", strconv.Itoa(256))
	_ = os.Setenv("DERPCAT_PROBE_CHUNK_SIZE", strconv.Itoa(1300))

	if got := probeWindowSize(); got != 256 {
		t.Fatalf("probeWindowSize() = %d, want 256", got)
	}
	if got := probeChunkSize(); got != 1300 {
		t.Fatalf("probeChunkSize() = %d, want 1300", got)
	}
}
