package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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

func TestRemoteClientCommandIncludesRawParallel(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ClientCommand(ClientConfig{
		Mode:      "raw",
		Transport: "batched",
		SizeBytes: 1024,
		Host:      "198.51.100.10:40000",
		Parallel:  4,
	})

	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, "/tmp/derpcat-probe client --mode raw --transport batched --size-bytes 1024 --host 198.51.100.10:40000 --parallel 4") {
		t.Fatalf("client command missing raw parallel: %#v", cmd)
	}
}

func TestRemoteCommandsIncludeBlastParallel(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}

	serverCmd := strings.Join(runner.ServerCommand(ServerConfig{
		ListenAddr: ":0",
		Mode:       "blast",
		Transport:  "batched",
		SizeBytes:  1024,
		Parallel:   4,
	}), " ")
	if !strings.Contains(serverCmd, "/tmp/derpcat-probe server --listen :0 --mode blast --transport batched --size-bytes 1024 --parallel 4") {
		t.Fatalf("server command missing blast parallel: %s", serverCmd)
	}

	clientCmd := strings.Join(runner.ClientCommand(ClientConfig{
		Mode:              "blast",
		Transport:         "batched",
		SizeBytes:         1024,
		PeerCandidatesCSV: "198.51.100.10:40000,203.0.113.10:50000",
		Parallel:          4,
	}), " ")
	if !strings.Contains(clientCmd, "/tmp/derpcat-probe client --mode blast --transport batched --size-bytes 1024 --peer-candidates 198.51.100.10:40000,203.0.113.10:50000 --parallel 4") {
		t.Fatalf("client command missing blast parallel: %s", clientCmd)
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
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\",\"batch_size\":128,\"tx_offload\":true}}\nDONE {\"bytes_received\":1024,\"first_byte_ms\":9,\"first_byte_measured\":true,\"duration_ms\":2000,\"retransmits\":0,\"packets_sent\":0,\"packets_acked\":0}\n")),
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
	if report.FirstByteMeasured == nil || !*report.FirstByteMeasured {
		t.Fatalf("report.FirstByteMeasured = %#v, want true", report.FirstByteMeasured)
	}
	if report.GoodputMbps <= 0 {
		t.Fatalf("report.GoodputMbps = %f, want > 0", report.GoodputMbps)
	}
	if report.PeakGoodputMbps != 0 {
		t.Fatalf("report.PeakGoodputMbps = %f, want 0", report.PeakGoodputMbps)
	}
	if report.Success == nil || !*report.Success {
		t.Fatalf("report.Success = %#v, want true", report.Success)
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

func TestRunOrchestrateForwardDoesNotInventMeasuredFirstByteFromZeroDone(t *testing.T) {
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

	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 40000}}, nil
	}
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_received\":1024,\"first_byte_ms\":0,\"duration_ms\":2000,\"retransmits\":0,\"packets_sent\":0,\"packets_acked\":0}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:    1024,
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
	if report.FirstByteMeasured != nil {
		t.Fatalf("report.FirstByteMeasured = %#v, want nil", report.FirstByteMeasured)
	}
	if report.FirstByteMS != 0 {
		t.Fatalf("report.FirstByteMS = %d, want 0", report.FirstByteMS)
	}
}

func TestRunOrchestrateWgiperfReportsSuccessWithoutMeasuredFirstByte(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteServer := launchRemoteServer
	oldSendWgIperf := orchestrateSendWireGuardOSIperf
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteServer = oldLaunchRemoteServer
		orchestrateSendWireGuardOSIperf = oldSendWgIperf
	}()

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localConn.Close()
	listenPacket = func(network, address string) (net.PacketConn, error) {
		return localConn, nil
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		addr, err := net.ResolveUDPAddr("udp", "198.51.100.10:40000")
		if err != nil {
			return nil, err
		}
		return []net.Addr{addr}, nil
	}
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\"203.0.113.10:50000\",\"candidates\":[\"203.0.113.10:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_received\":1024,\"duration_ms\":2000,\"retransmits\":0,\"packets_sent\":0,\"packets_acked\":0}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}
	orchestrateSendWireGuardOSIperf = func(ctx context.Context, conn net.PacketConn, cfg WireGuardConfig) (TransferStats, error) {
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:     1024,
			BytesReceived: 1024,
			StartedAt:     startedAt,
			CompletedAt:   startedAt.Add(2 * time.Second),
			Transport:     TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "wgiperf",
		Transport: "batched",
		Direction: "forward",
		SizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if report.Success == nil || !*report.Success {
		t.Fatalf("report.Success = %#v, want true", report.Success)
	}
	if report.FirstByteMeasured != nil {
		t.Fatalf("report.FirstByteMeasured = %#v, want nil", report.FirstByteMeasured)
	}
	if report.FirstByteMS != 0 {
		t.Fatalf("report.FirstByteMS = %d, want 0", report.FirstByteMS)
	}
	if report.PeakGoodputMbps != 0 {
		t.Fatalf("report.PeakGoodputMbps = %f, want 0", report.PeakGoodputMbps)
	}
}

func TestRunOrchestrateForwardBlastPassesRateToSingleSession(t *testing.T) {
	t.Setenv("DERPCAT_PROBE_RATE_MBPS", "1200")
	t.Setenv("DERPCAT_PROBE_REPAIR_PAYLOADS", "1")

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

	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 40000}}, nil
	}
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_received\":1024,\"first_byte_ms\":9,\"duration_ms\":2000}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}
	var gotCfg SendConfig
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		gotCfg = cfg
		if _, err := io.Copy(io.Discard, src); err != nil {
			return TransferStats{}, err
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:   1024,
			StartedAt:   startedAt,
			FirstByteAt: startedAt.Add(9 * time.Millisecond),
			CompletedAt: startedAt.Add(2 * time.Second),
			Transport:   TransportCaps{Kind: "legacy", RequestedKind: "batched"},
		}, nil
	}

	if _, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "blast",
		Transport: "batched",
		Direction: "forward",
		SizeBytes: 1024,
		Parallel:  1,
	}); err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if !gotCfg.Blast || gotCfg.Raw {
		t.Fatalf("send config = %+v, want blast mode only", gotCfg)
	}
	if gotCfg.RateMbps != 1200 {
		t.Fatalf("RateMbps = %d, want 1200", gotCfg.RateMbps)
	}
	if !gotCfg.RepairPayloads {
		t.Fatalf("RepairPayloads = false, want true")
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
	orchestrateReceive = func(ctx context.Context, conn net.PacketConn, peer string, dst io.Writer, cfg ReceiveConfig) (TransferStats, error) {
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
		Parallel:  1,
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
	if report.PeakGoodputMbps != 0 {
		t.Fatalf("report.PeakGoodputMbps = %f, want 0", report.PeakGoodputMbps)
	}
	if report.Success == nil || !*report.Success {
		t.Fatalf("report.Success = %#v, want true", report.Success)
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
		t.Fatalf("RunOrchestrate() passed raw --parallel with Parallel=1: %#v", gotArgv)
	}
}

func TestRunOrchestrateReverseFailsOnShortReceive(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteClient := launchRemoteClient
	oldReceiveBlastParallel := orchestrateReceiveBlastParallel
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteClient = oldLaunchRemoteClient
		orchestrateReceiveBlastParallel = oldReceiveBlastParallel
	}()

	listenPacket = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 40000}}, nil
	}
	launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_sent\":11,\"duration_ms\":100}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}
	orchestrateReceiveBlastParallel = func(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesReceived: 7,
			StartedAt:     startedAt,
			FirstByteAt:   startedAt.Add(5 * time.Millisecond),
			CompletedAt:   startedAt.Add(100 * time.Millisecond),
			Transport:     TransportCaps{Kind: "legacy", RequestedKind: "batched"},
		}, nil
	}

	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "reverse",
		SizeBytes: 11,
		Parallel:  1,
	})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want short receive error")
	}
	if !strings.Contains(err.Error(), "received 7 bytes, want 11") {
		t.Fatalf("RunOrchestrate() error = %v, want short receive detail", err)
	}
}

func TestRunOrchestrateReverseBlastSingleUsesExpectedReceiver(t *testing.T) {
	t.Setenv("DERPCAT_PROBE_REQUIRE_COMPLETE", "1")

	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteClient := launchRemoteClient
	oldReceiveBlastParallel := orchestrateReceiveBlastParallel
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteClient = oldLaunchRemoteClient
		orchestrateReceiveBlastParallel = oldReceiveBlastParallel
	}()

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localConn.Close()
	listenPacket = func(network, address string) (net.PacketConn, error) {
		return localConn, nil
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}
	launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_sent\":11,\"duration_ms\":100}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}

	called := false
	orchestrateReceiveBlastParallel = func(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
		called = true
		if len(conns) != 1 {
			t.Fatalf("len(conns) = %d, want 1", len(conns))
		}
		if !cfg.Blast || cfg.Raw {
			t.Fatalf("receive config = %+v, want blast mode only", cfg)
		}
		if !cfg.RequireComplete {
			t.Fatalf("RequireComplete = false, want true")
		}
		if expectedBytes != 11 {
			t.Fatalf("expectedBytes = %d, want 11", expectedBytes)
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesReceived: 11,
			StartedAt:     startedAt,
			FirstByteAt:   startedAt.Add(5 * time.Millisecond),
			CompletedAt:   startedAt.Add(100 * time.Millisecond),
			Transport:     TransportCaps{Kind: "legacy", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "reverse",
		SizeBytes: 11,
		Parallel:  1,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if !called {
		t.Fatal("blast receiver was not called")
	}
	if report.BytesReceived != 11 || !report.Direct {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunOrchestrateReverseBlastParallelUsesBlastReceiver(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteClient := launchRemoteClient
	oldReceiveBlastParallel := orchestrateReceiveBlastParallel
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteClient = oldLaunchRemoteClient
		orchestrateReceiveBlastParallel = oldReceiveBlastParallel
	}()

	var opened []net.PacketConn
	listenPacket = func(network, address string) (net.PacketConn, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			opened = append(opened, conn)
		}
		return conn, err
	}
	defer func() {
		for _, conn := range opened {
			_ = conn.Close()
		}
	}()
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}
	launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
		if cfg.Parallel != 2 {
			t.Fatalf("client Parallel = %d, want 2", cfg.Parallel)
		}
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\",\"203.0.113.20:50001\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_sent\":11,\"duration_ms\":100}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}

	called := false
	orchestrateReceiveBlastParallel = func(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
		called = true
		if len(conns) != 2 {
			t.Fatalf("len(conns) = %d, want 2", len(conns))
		}
		if !cfg.Blast || cfg.Raw {
			t.Fatalf("receive config = %+v, want blast mode only", cfg)
		}
		if expectedBytes != 11 {
			t.Fatalf("expectedBytes = %d, want 11", expectedBytes)
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesReceived: 11,
			StartedAt:     startedAt,
			FirstByteAt:   startedAt.Add(5 * time.Millisecond),
			CompletedAt:   startedAt.Add(100 * time.Millisecond),
			Transport:     TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "reverse",
		SizeBytes: 11,
		Parallel:  2,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if !called {
		t.Fatal("blast parallel receiver was not called")
	}
	if report.BytesReceived != 11 || !report.Direct {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunOrchestrateReverseBlastParallelLeavesFirstByteMeasuredNilWhenUnmeasured(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteClient := launchRemoteClient
	oldReceiveBlastParallel := orchestrateReceiveBlastParallel
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteClient = oldLaunchRemoteClient
		orchestrateReceiveBlastParallel = oldReceiveBlastParallel
	}()

	var opened []net.PacketConn
	listenPacket = func(network, address string) (net.PacketConn, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			opened = append(opened, conn)
		}
		return conn, err
	}
	defer func() {
		for _, conn := range opened {
			_ = conn.Close()
		}
	}()
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}
	launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
		if cfg.Parallel != 2 {
			t.Fatalf("client Parallel = %d, want 2", cfg.Parallel)
		}
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\",\"203.0.113.20:50001\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_sent\":11,\"duration_ms\":100,\"first_byte_ms\":0}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}

	called := false
	orchestrateReceiveBlastParallel = func(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
		called = true
		if len(conns) != 2 {
			t.Fatalf("len(conns) = %d, want 2", len(conns))
		}
		if !cfg.Blast || cfg.Raw {
			t.Fatalf("receive config = %+v, want blast mode only", cfg)
		}
		if expectedBytes != 11 {
			t.Fatalf("expectedBytes = %d, want 11", expectedBytes)
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesReceived: 11,
			StartedAt:     startedAt,
			CompletedAt:   startedAt.Add(100 * time.Millisecond),
			Transport:     TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "reverse",
		SizeBytes: 11,
		Parallel:  2,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if !called {
		t.Fatal("blast parallel receiver was not called")
	}
	if report.BytesReceived != 11 || !report.Direct {
		t.Fatalf("report = %#v", report)
	}
	if report.FirstByteMeasured != nil {
		t.Fatalf("report.FirstByteMeasured = %#v, want nil", report.FirstByteMeasured)
	}
	if report.FirstByteMS != 0 {
		t.Fatalf("report.FirstByteMS = %d, want 0", report.FirstByteMS)
	}
}

func TestRunOrchestrateReverseBlastParallelUsesRemoteFirstByteFallback(t *testing.T) {
	oldListenPacket := listenPacket
	oldDiscoverCandidates := orchestrateDiscoverCandidates
	oldLaunchRemoteClient := launchRemoteClient
	oldReceiveBlastParallel := orchestrateReceiveBlastParallel
	defer func() {
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscoverCandidates
		launchRemoteClient = oldLaunchRemoteClient
		orchestrateReceiveBlastParallel = oldReceiveBlastParallel
	}()

	var opened []net.PacketConn
	listenPacket = func(network, address string) (net.PacketConn, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			opened = append(opened, conn)
		}
		return conn, err
	}
	defer func() {
		for _, conn := range opened {
			_ = conn.Close()
		}
	}()
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}
	launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
		if cfg.Parallel != 2 {
			t.Fatalf("client Parallel = %d, want 2", cfg.Parallel)
		}
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\":0\",\"candidates\":[\"203.0.113.20:50000\",\"203.0.113.20:50001\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_sent\":11,\"duration_ms\":100,\"first_byte_ms\":7,\"first_byte_measured\":true}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}

	called := false
	orchestrateReceiveBlastParallel = func(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg ReceiveConfig, expectedBytes int64) (TransferStats, error) {
		called = true
		if len(conns) != 2 {
			t.Fatalf("len(conns) = %d, want 2", len(conns))
		}
		if !cfg.Blast || cfg.Raw {
			t.Fatalf("receive config = %+v, want blast mode only", cfg)
		}
		if expectedBytes != 11 {
			t.Fatalf("expectedBytes = %d, want 11", expectedBytes)
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesReceived: 11,
			StartedAt:     startedAt,
			CompletedAt:   startedAt.Add(100 * time.Millisecond),
			Transport:     TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "reverse",
		SizeBytes: 11,
		Parallel:  2,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if !called {
		t.Fatal("blast parallel receiver was not called")
	}
	if report.BytesReceived != 11 || !report.Direct {
		t.Fatalf("report = %#v", report)
	}
	if report.FirstByteMeasured == nil || !*report.FirstByteMeasured {
		t.Fatalf("report.FirstByteMeasured = %#v, want true", report.FirstByteMeasured)
	}
	if report.FirstByteMS != 7 {
		t.Fatalf("report.FirstByteMS = %d, want 7", report.FirstByteMS)
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
	for _, key := range []string{"DERPCAT_PROBE_WINDOW", "DERPCAT_PROBE_WINDOW_SIZE", "DERPCAT_PROBE_CHUNK_SIZE"} {
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

	if got := probeWindowSize("raw", probeTransportLegacy); got != 256 {
		t.Fatalf("probeWindowSize(raw, legacy) = %d, want 256", got)
	}
	if got := probeWindowSize("raw", probeTransportBatched); got != 384 {
		t.Fatalf("probeWindowSize(raw, batched) = %d, want 384", got)
	}
	if got := probeWindowSize("blast", probeTransportBatched); got != 1024 {
		t.Fatalf("probeWindowSize(blast, batched) = %d, want 1024", got)
	}
	if got := probeChunkSize(); got != defaultChunkSize {
		t.Fatalf("probeChunkSize() = %d, want %d", got, defaultChunkSize)
	}

	_ = os.Setenv("DERPCAT_PROBE_WINDOW_SIZE", strconv.Itoa(256))
	_ = os.Setenv("DERPCAT_PROBE_CHUNK_SIZE", strconv.Itoa(1300))

	if got := probeWindowSize("raw", probeTransportBatched); got != 256 {
		t.Fatalf("probeWindowSize(raw, batched) override = %d, want 256", got)
	}
	_ = os.Unsetenv("DERPCAT_PROBE_WINDOW_SIZE")
	_ = os.Setenv("DERPCAT_PROBE_WINDOW", strconv.Itoa(320))
	if got := probeWindowSize("raw", probeTransportBatched); got != 320 {
		t.Fatalf("probeWindowSize(raw, batched) legacy override = %d, want 320", got)
	}
	if got := probeChunkSize(); got != 1300 {
		t.Fatalf("probeChunkSize() = %d, want 1300", got)
	}
}

func TestSplitOrchestrateShares(t *testing.T) {
	if got := splitOrchestrateShares(0, 8); len(got) != 1 || got[0] != 0 {
		t.Fatalf("splitOrchestrateShares(0, 8) = %#v, want [0]", got)
	}
	if got := splitOrchestrateShares(8, 16); len(got) != 8 {
		t.Fatalf("splitOrchestrateShares(8, 16) len = %d, want 8", len(got))
	}
	if got := splitOrchestrateShares(10, 3); len(got) != 3 || got[0] != 4 || got[1] != 3 || got[2] != 3 {
		t.Fatalf("splitOrchestrateShares(10, 3) = %#v, want [4 3 3]", got)
	}
}

func TestSelectRemoteAddrsByConnAvoidsDuplicateRemotePorts(t *testing.T) {
	observedByConn := [][]net.Addr{
		{mustUDPAddr(t, "100.107.23.123:51048")},
		{mustUDPAddr(t, "68.20.14.192:51048"), mustUDPAddr(t, "68.20.14.192:52315")},
		{mustUDPAddr(t, "68.20.14.192:35365")},
	}
	fallback := []string{"68.20.14.192:35365", "68.20.14.192:52315", "68.20.14.192:51048"}

	got := selectRemoteAddrsByConn(observedByConn, fallback, 3)
	want := []string{"100.107.23.123:51048", "68.20.14.192:52315", "68.20.14.192:35365"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selectRemoteAddrsByConn() = %v, want %v", got, want)
	}
}

func TestSelectRemoteAddrsByConnBackfillsEmptyLanesFromAnyUnusedFallback(t *testing.T) {
	observedByConn := [][]net.Addr{
		{mustUDPAddr(t, "68.20.14.192:51048")},
		{mustUDPAddr(t, "100.107.23.123:51048")},
		{mustUDPAddr(t, "68.20.14.192:50924")},
		{mustUDPAddr(t, "68.20.14.192:50924")},
	}
	fallback := []string{
		"68.20.14.192:51048",
		"68.20.14.192:50924",
		"68.20.14.192:37597",
		"68.20.14.192:47634",
	}

	got := selectRemoteAddrsByConn(observedByConn, fallback, 4)
	want := []string{"68.20.14.192:51048", "68.20.14.192:37597", "68.20.14.192:50924", "68.20.14.192:47634"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selectRemoteAddrsByConn() = %v, want %v", got, want)
	}
}

func mustUDPAddr(t *testing.T, raw string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestSizedReaderDoesNotRewritePayloadBuffer(t *testing.T) {
	reader := newSizedReader(2)
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

func TestRunOrchestratePassesRawParallelToSingleSession(t *testing.T) {
	oldChild := orchestrateChildRun
	oldLaunchRemoteServer := launchRemoteServer
	oldListenPacket := listenPacket
	oldDiscover := orchestrateDiscoverCandidates
	oldSend := orchestrateSend
	defer func() {
		orchestrateChildRun = oldChild
		launchRemoteServer = oldLaunchRemoteServer
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscover
		orchestrateSend = oldSend
	}()

	orchestrateChildRun = func(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
		t.Fatalf("orchestrateChildRun should not be used for raw in-session parallel")
		return RunReport{}, nil
	}

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localConn.Close()
	listenPacket = func(network, address string) (net.PacketConn, error) {
		return localConn, nil
	}
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		addr, err := net.ResolveUDPAddr("udp", "198.51.100.10:40000")
		if err != nil {
			return nil, err
		}
		return []net.Addr{addr}, nil
	}

	var gotServerCfg ServerConfig
	stdout := io.NopCloser(strings.NewReader("READY {\"addr\":\"203.0.113.10:50000\",\"candidates\":[\"203.0.113.10:50000\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_received\":1024,\"duration_ms\":100,\"first_byte_ms\":5}\n"))
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		gotServerCfg = cfg
		return &remoteServerHandle{
			stdout: stdout,
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}

	var gotSendCfg SendConfig
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		gotSendCfg = cfg
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:   1024,
			StartedAt:   startedAt,
			FirstByteAt: startedAt.Add(5 * time.Millisecond),
			CompletedAt: startedAt.Add(100 * time.Millisecond),
			Transport:   TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "raw",
		Transport: "batched",
		Direction: "forward",
		SizeBytes: 1024,
		Parallel:  4,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if gotServerCfg.Parallel != 4 {
		t.Fatalf("server Parallel = %d, want 4", gotServerCfg.Parallel)
	}
	if gotSendCfg.Parallel != 4 {
		t.Fatalf("send Parallel = %d, want 4", gotSendCfg.Parallel)
	}
	if report.BytesReceived != 1024 {
		t.Fatalf("report.BytesReceived = %d, want 1024", report.BytesReceived)
	}
	if !report.Direct || report.Local.Kind != "batched" || report.Remote.Kind != "batched" {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunOrchestratePassesBlastParallelToSingleSession(t *testing.T) {
	t.Setenv("DERPCAT_PROBE_RATE_MBPS", "2000")

	oldChild := orchestrateChildRun
	oldLaunchRemoteServer := launchRemoteServer
	oldListenPacket := listenPacket
	oldDiscover := orchestrateDiscoverCandidates
	oldSend := orchestrateSend
	defer func() {
		orchestrateChildRun = oldChild
		launchRemoteServer = oldLaunchRemoteServer
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscover
		orchestrateSend = oldSend
	}()

	orchestrateChildRun = func(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
		return RunReport{}, errors.New("orchestrateChildRun should not be used for blast in-session parallel")
	}

	var opened []net.PacketConn
	listenPacket = func(network, address string) (net.PacketConn, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			opened = append(opened, conn)
		}
		return conn, err
	}
	defer func() {
		for _, conn := range opened {
			_ = conn.Close()
		}
	}()
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}

	var gotServerCfg ServerConfig
	stdout := io.NopCloser(strings.NewReader("READY {\"addr\":\"203.0.113.10:50000\",\"candidates\":[\"203.0.113.10:50000\",\"203.0.113.10:50001\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_received\":11,\"duration_ms\":100,\"first_byte_ms\":5}\n"))
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		gotServerCfg = cfg
		return &remoteServerHandle{
			stdout: stdout,
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}

	var mu sync.Mutex
	var gotRemotes []string
	var gotSizes []int64
	var gotRates []int
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		n, err := io.Copy(io.Discard, src)
		if err != nil {
			return TransferStats{}, err
		}
		if !cfg.Blast || cfg.Raw {
			return TransferStats{}, fmt.Errorf("send config = %+v, want blast mode only", cfg)
		}
		mu.Lock()
		gotRemotes = append(gotRemotes, remoteAddr)
		gotSizes = append(gotSizes, n)
		gotRates = append(gotRates, cfg.RateMbps)
		mu.Unlock()
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:   n,
			StartedAt:   startedAt,
			FirstByteAt: startedAt.Add(5 * time.Millisecond),
			CompletedAt: startedAt.Add(100 * time.Millisecond),
			Transport:   TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "forward",
		SizeBytes: 11,
		Parallel:  2,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if gotServerCfg.Parallel != 2 {
		t.Fatalf("server Parallel = %d, want 2", gotServerCfg.Parallel)
	}
	sort.Strings(gotRemotes)
	sort.Slice(gotSizes, func(i, j int) bool { return gotSizes[i] > gotSizes[j] })
	if strings.Join(gotRemotes, ",") != "203.0.113.10:50000,203.0.113.10:50001" {
		t.Fatalf("remote addresses = %v, want both remote candidates", gotRemotes)
	}
	if len(gotSizes) != 2 || gotSizes[0] != 6 || gotSizes[1] != 5 {
		t.Fatalf("share sizes = %v, want [6 5]", gotSizes)
	}
	sort.Ints(gotRates)
	if len(gotRates) != 2 || gotRates[0] != 1000 || gotRates[1] != 1000 {
		t.Fatalf("rate mbps = %v, want [1000 1000]", gotRates)
	}
	if report.BytesReceived != 11 || !report.Direct {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunOrchestrateForwardBlastParallelFailsOnShortReceive(t *testing.T) {
	oldChild := orchestrateChildRun
	oldLaunchRemoteServer := launchRemoteServer
	oldListenPacket := listenPacket
	oldDiscover := orchestrateDiscoverCandidates
	oldSend := orchestrateSend
	defer func() {
		orchestrateChildRun = oldChild
		launchRemoteServer = oldLaunchRemoteServer
		listenPacket = oldListenPacket
		orchestrateDiscoverCandidates = oldDiscover
		orchestrateSend = oldSend
	}()

	orchestrateChildRun = func(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
		return RunReport{}, errors.New("orchestrateChildRun should not be used for blast in-session parallel")
	}

	var opened []net.PacketConn
	listenPacket = func(network, address string) (net.PacketConn, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			opened = append(opened, conn)
		}
		return conn, err
	}
	defer func() {
		for _, conn := range opened {
			_ = conn.Close()
		}
	}()
	orchestrateDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{conn.LocalAddr()}, nil
	}
	launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
		return &remoteServerHandle{
			stdout: io.NopCloser(strings.NewReader("READY {\"addr\":\"203.0.113.10:50000\",\"candidates\":[\"203.0.113.10:50000\",\"203.0.113.10:50001\"],\"transport\":{\"kind\":\"batched\",\"requested_kind\":\"batched\"}}\nDONE {\"bytes_received\":7,\"duration_ms\":100,\"first_byte_ms\":5}\n")),
			stderr: io.NopCloser(strings.NewReader("")),
			wait:   func() error { return nil },
		}, nil
	}
	orchestrateSend = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
		n, err := io.Copy(io.Discard, src)
		if err != nil {
			return TransferStats{}, err
		}
		startedAt := time.Unix(0, 0)
		return TransferStats{
			BytesSent:   n,
			StartedAt:   startedAt,
			FirstByteAt: startedAt.Add(5 * time.Millisecond),
			CompletedAt: startedAt.Add(100 * time.Millisecond),
			Transport:   TransportCaps{Kind: "batched", RequestedKind: "batched"},
		}, nil
	}

	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		Mode:      "blast",
		Transport: "batched",
		Direction: "forward",
		SizeBytes: 11,
		Parallel:  2,
	})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want short receive error")
	}
	if !strings.Contains(err.Error(), "received 7 bytes, want 11") {
		t.Fatalf("RunOrchestrate() error = %v, want short receive detail", err)
	}
}
