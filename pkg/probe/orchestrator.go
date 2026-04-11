package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultProbeRemotePath      = "/tmp/derpcat-probe"
	defaultSSHConnectTimeoutSec = 5
	defaultProbeWindowSize      = 1024
)

var listenPacket = net.ListenPacket
var orchestrateDiscoverCandidates = DiscoverCandidates
var orchestrateSend = Send
var orchestrateReceive = ReceiveToWriter
var orchestrateReceiveBlastParallel = ReceiveBlastParallelToWriter
var orchestrateSendWireGuardOSIperf = SendWireGuardOSIperf
var orchestrateChildRun func(context.Context, OrchestrateConfig) (RunReport, error)

func init() {
	orchestrateChildRun = RunOrchestrate
}

type OrchestrateConfig struct {
	Host       string
	User       string
	RemotePath string
	ListenAddr string
	Mode       string
	Transport  string
	Direction  string
	SizeBytes  int64
	Parallel   int
}

type ServerConfig struct {
	ListenAddr        string
	Mode              string
	Transport         string
	PeerCandidatesCSV string
	WGPrivateKeyHex   string
	WGPeerPublicHex   string
	WGLocalAddr       string
	WGPeerAddr        string
	WGPort            int
	SizeBytes         int64
	Parallel          int
}

type ClientConfig struct {
	Host              string
	Mode              string
	Transport         string
	SizeBytes         int64
	PeerCandidatesCSV string
	WGPrivateKeyHex   string
	WGPeerPublicHex   string
	WGLocalAddr       string
	WGPeerAddr        string
	WGPort            int
	Parallel          int
}

type SSHRunner struct {
	User       string
	Host       string
	RemotePath string
}

type remoteServerHandle struct {
	stdout io.ReadCloser
	stderr io.ReadCloser
	wait   func() error
}

type remoteReady struct {
	Addr       string        `json:"addr"`
	Candidates []string      `json:"candidates,omitempty"`
	Transport  TransportCaps `json:"transport,omitempty"`
}

type remoteDone struct {
	BytesSent         int64 `json:"bytes_sent,omitempty"`
	BytesReceived     int64 `json:"bytes_received"`
	DurationMS        int64 `json:"duration_ms"`
	FirstByteMS       int64 `json:"first_byte_ms"`
	FirstByteMeasured *bool `json:"first_byte_measured,omitempty"`
	Retransmits       int64 `json:"retransmits"`
	PacketsSent       int64 `json:"packets_sent"`
	PacketsAcked      int64 `json:"packets_acked"`
}

type outputEvent struct {
	ready *remoteReady
	done  *remoteDone
	err   error
}

func (r SSHRunner) target() string {
	if r.User == "" {
		return r.Host
	}
	return r.User + "@" + r.Host
}

func (r SSHRunner) binaryPath() string {
	if r.RemotePath != "" {
		return r.RemotePath
	}
	return defaultProbeRemotePath
}

func sshProbeEnvVars() []string {
	var env []string
	if trace := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_WG_TRACE")); trace != "" {
		env = append(env, "DERPCAT_PROBE_WG_TRACE="+trace)
	}
	if trace := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_TRACE")); trace != "" {
		env = append(env, "DERPCAT_PROBE_TRACE="+trace)
	}
	if rate := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_RATE_MBPS")); rate != "" {
		env = append(env, "DERPCAT_PROBE_RATE_MBPS="+rate)
	}
	if requireComplete := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_REQUIRE_COMPLETE")); requireComplete != "" {
		env = append(env, "DERPCAT_PROBE_REQUIRE_COMPLETE="+requireComplete)
	}
	if repairPayloads := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_REPAIR_PAYLOADS")); repairPayloads != "" {
		env = append(env, "DERPCAT_PROBE_REPAIR_PAYLOADS="+repairPayloads)
	}
	return env
}

func (r SSHRunner) ServerCommand(cfg ServerConfig) []string {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	mode := cfg.Mode
	if mode == "" {
		mode = "raw"
	}
	transport := cfg.Transport
	if transport == "" {
		transport = probeTransportLegacy
	}
	argv := []string{
		"ssh",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", defaultSSHConnectTimeoutSec),
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		argv = append(argv, "-o", "UserKnownHostsFile="+home+"/.ssh/known_hosts")
	}
	argv = append(argv,
		r.target(),
	)
	if envVars := sshProbeEnvVars(); len(envVars) > 0 {
		argv = append(argv, "env")
		argv = append(argv, envVars...)
	}
	argv = append(argv,
		r.binaryPath(),
		"server",
		"--listen", listenAddr,
		"--mode", mode,
		"--transport", transport,
	)
	if cfg.PeerCandidatesCSV != "" {
		argv = append(argv, "--peer-candidates", cfg.PeerCandidatesCSV)
	}
	if cfg.WGPrivateKeyHex != "" {
		argv = append(argv, "--wg-private", cfg.WGPrivateKeyHex)
	}
	if cfg.WGPeerPublicHex != "" {
		argv = append(argv, "--wg-peer-public", cfg.WGPeerPublicHex)
	}
	if cfg.WGLocalAddr != "" {
		argv = append(argv, "--wg-local-addr", cfg.WGLocalAddr)
	}
	if cfg.WGPeerAddr != "" {
		argv = append(argv, "--wg-peer-addr", cfg.WGPeerAddr)
	}
	if cfg.WGPort > 0 {
		argv = append(argv, "--wg-port", strconv.Itoa(cfg.WGPort))
	}
	if cfg.SizeBytes > 0 {
		argv = append(argv, "--size-bytes", strconv.FormatInt(cfg.SizeBytes, 10))
	}
	if cfg.Parallel > 1 && (mode == "raw" || mode == "blast" || mode == "wg" || mode == "wgos") {
		argv = append(argv, "--parallel", strconv.Itoa(cfg.Parallel))
	}
	return argv
}

func (r SSHRunner) ClientCommand(cfg ClientConfig) []string {
	mode := cfg.Mode
	if mode == "" {
		mode = "raw"
	}
	transport := cfg.Transport
	if transport == "" {
		transport = probeTransportLegacy
	}
	argv := []string{
		"ssh",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", defaultSSHConnectTimeoutSec),
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		argv = append(argv, "-o", "UserKnownHostsFile="+home+"/.ssh/known_hosts")
	}
	argv = append(argv,
		r.target(),
	)
	if envVars := sshProbeEnvVars(); len(envVars) > 0 {
		argv = append(argv, "env")
		argv = append(argv, envVars...)
	}
	argv = append(argv,
		r.binaryPath(),
		"client",
		"--mode", mode,
		"--transport", transport,
	)
	if cfg.SizeBytes > 0 {
		argv = append(argv, "--size-bytes", strconv.FormatInt(cfg.SizeBytes, 10))
	}
	if cfg.Host != "" {
		argv = append(argv, "--host", cfg.Host)
	}
	if cfg.PeerCandidatesCSV != "" {
		argv = append(argv, "--peer-candidates", cfg.PeerCandidatesCSV)
	}
	if cfg.WGPrivateKeyHex != "" {
		argv = append(argv, "--wg-private", cfg.WGPrivateKeyHex)
	}
	if cfg.WGPeerPublicHex != "" {
		argv = append(argv, "--wg-peer-public", cfg.WGPeerPublicHex)
	}
	if cfg.WGLocalAddr != "" {
		argv = append(argv, "--wg-local-addr", cfg.WGLocalAddr)
	}
	if cfg.WGPeerAddr != "" {
		argv = append(argv, "--wg-peer-addr", cfg.WGPeerAddr)
	}
	if cfg.WGPort > 0 {
		argv = append(argv, "--wg-port", strconv.Itoa(cfg.WGPort))
	}
	if cfg.Parallel > 1 && (mode == "raw" || mode == "blast" || mode == "wg" || mode == "wgos") {
		argv = append(argv, "--parallel", strconv.Itoa(cfg.Parallel))
	}
	if mode == "blast" {
		if rate := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_RATE_MBPS")); rate != "" {
			argv = append(argv, "--rate-mbps", rate)
		}
	}
	return argv
}

var launchRemoteServer = func(ctx context.Context, runner SSHRunner, cfg ServerConfig) (*remoteServerHandle, error) {
	argv := runner.ServerCommand(cfg)
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &remoteServerHandle{
		stdout: stdout,
		stderr: stderr,
		wait: func() error {
			return cmd.Wait()
		},
	}, nil
}

var launchRemoteClient = func(ctx context.Context, runner SSHRunner, cfg ClientConfig) (*remoteServerHandle, error) {
	argv := runner.ClientCommand(cfg)
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &remoteServerHandle{
		stdout: stdout,
		stderr: stderr,
		wait: func() error {
			return cmd.Wait()
		},
	}, nil
}

var runCommand = func(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return out, fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
		}
		return out, fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, msg)
	}
	return out, nil
}

func RunOrchestrate(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
	if ctx == nil {
		return RunReport{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return RunReport{}, err
	}

	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" {
		return RunReport{}, errors.New("host is required")
	}
	if cfg.RemotePath == "" {
		cfg.RemotePath = defaultProbeRemotePath
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	if cfg.Mode == "" {
		cfg.Mode = "raw"
	}
	if cfg.Direction == "" {
		cfg.Direction = "forward"
	}
	if cfg.Transport == "" {
		cfg.Transport = probeTransportLegacy
	}
	if cfg.SizeBytes < 0 {
		return RunReport{}, errors.New("size bytes must be non-negative")
	}
	switch cfg.Mode {
	case "raw", "blast", "wg", "wgos", "wgiperf":
	case "aead":
		return RunReport{}, errors.New("aead not implemented yet")
	default:
		return RunReport{}, fmt.Errorf("unsupported mode %q", cfg.Mode)
	}
	if cfg.Direction != "forward" && cfg.Direction != "reverse" {
		return RunReport{}, fmt.Errorf("unsupported direction %q", cfg.Direction)
	}
	if cfg.Parallel > 1 && cfg.Mode == "blast" {
		return runParallelBlastOrchestrate(ctx, cfg)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	localConn, err := listenPacket("udp", ":0")
	if err != nil {
		return RunReport{}, err
	}
	defer localConn.Close()

	localCandidates, err := orchestrateDiscoverCandidates(runCtx, localConn)
	if err != nil {
		return RunReport{}, err
	}
	localCandidates = preferredCandidates(localCandidates, 8)
	runner := SSHRunner{
		User:       cfg.User,
		Host:       cfg.Host,
		RemotePath: cfg.RemotePath,
	}
	if cfg.Mode == "wgiperf" {
		return runWireGuardOSIperfOrchestrate(runCtx, cfg, localConn, localCandidates, runner)
	}
	if cfg.Direction == "reverse" {
		return runReverseOrchestrate(runCtx, cfg, localConn, localCandidates, runner)
	}
	return runForwardOrchestrate(runCtx, cfg, localConn, localCandidates, runner)
}

func runParallelBlastOrchestrate(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if cfg.RemotePath == "" {
		cfg.RemotePath = defaultProbeRemotePath
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	runner := SSHRunner{
		User:       cfg.User,
		Host:       cfg.Host,
		RemotePath: cfg.RemotePath,
	}
	if cfg.Direction == "reverse" {
		return runReverseParallelBlastOrchestrate(runCtx, cfg, runner)
	}
	return runForwardParallelBlastOrchestrate(runCtx, cfg, runner)
}

func runForwardParallelBlastOrchestrate(runCtx context.Context, cfg OrchestrateConfig, runner SSHRunner) (RunReport, error) {
	localConns, err := listenParallelPacketConns(runCtx, cfg.Parallel)
	if err != nil {
		return RunReport{}, err
	}
	defer closePacketConns(localConns)

	localCandidates, err := discoverCandidatesForPacketConns(runCtx, localConns)
	if err != nil {
		return RunReport{}, err
	}
	localCandidates = limitCandidatesInOrder(localCandidates, parallelCandidateLimit(cfg.Parallel))
	probeTracef("forward local candidates: %s", strings.Join(CandidateStringsInOrder(localCandidates), ","))

	serverCfg := ServerConfig{
		ListenAddr:        cfg.ListenAddr,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		PeerCandidatesCSV: strings.Join(CandidateStringsInOrder(localCandidates), ","),
		SizeBytes:         cfg.SizeBytes,
		Parallel:          cfg.Parallel,
	}
	handle, err := launchRemoteServer(runCtx, runner, serverCfg)
	if err != nil {
		return RunReport{}, err
	}
	completed := false
	defer func() {
		if !completed && handle.wait != nil {
			_ = handle.wait()
		}
	}()

	var stderrBuf bytes.Buffer
	var stderrWG sync.WaitGroup
	if handle.stderr != nil {
		stderrWG.Add(1)
		go func() {
			defer stderrWG.Done()
			_, _ = io.Copy(traceStderrWriter(&stderrBuf), handle.stderr)
		}()
	}

	events := make(chan outputEvent, 8)
	go scanRemoteOutput(handle.stdout, events)

	ready, err := waitForRemoteReady(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates := limitCandidatesInOrder(ParseCandidateStrings(ready.Candidates), parallelCandidateLimit(cfg.Parallel))
	remoteAddrs := parallelCandidateStringsInOrder(remoteCandidates, len(localConns))
	probeTracef("forward remote candidates: %s", strings.Join(CandidateStringsInOrder(remoteCandidates), ","))
	probeTracef("forward initial remote addrs: %s", strings.Join(remoteAddrs, ","))
	if len(remoteAddrs) == 0 && ready.Addr != "" {
		remoteAddrs = []string{ready.Addr}
	}
	if len(remoteAddrs) == 0 {
		return RunReport{}, errors.New("remote server did not report usable parallel blast candidates")
	}
	if len(localConns) > len(remoteAddrs) {
		localConns = localConns[:len(remoteAddrs)]
	}

	punchCtx, punchCancel := context.WithCancel(runCtx)
	defer punchCancel()
	for _, conn := range localConns {
		go PunchAddrs(punchCtx, conn, remoteCandidates, []byte(defaultPunchPayload), defaultPunchInterval)
	}
	if observedByConn := ObservePunchAddrsByConn(runCtx, localConns, 1200*time.Millisecond); len(observedByConn) > 0 {
		probeTracef("forward observed punch addrs by conn: %s", formatObservedAddrsByConn(observedByConn))
		remoteAddrs = selectRemoteAddrsByConn(observedByConn, remoteAddrs, len(localConns))
	}
	probeTracef("forward selected remote addrs: %s", strings.Join(remoteAddrs, ","))

	sendStats, err := sendParallelBlastShares(runCtx, localConns, remoteAddrs, cfg)
	punchCancel()
	if err != nil {
		return RunReport{}, err
	}

	done, err := waitForRemoteDone(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	if handle.wait != nil {
		if err := handle.wait(); err != nil {
			if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
				return RunReport{}, fmt.Errorf("remote server failed: %w: %s", err, msg)
			}
			return RunReport{}, err
		}
	}
	stderrWG.Wait()
	completed = true

	durationMS := done.DurationMS
	if durationMS <= 0 {
		durationMS = elapsedMS(sendStats.StartedAt, sendStats.CompletedAt)
	}
	bytesReceived := done.BytesReceived
	if bytesReceived <= 0 {
		bytesReceived = sendStats.BytesSent
	}
	if err := requireExpectedBytes(bytesReceived, cfg.SizeBytes); err != nil {
		return RunReport{}, err
	}
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		Direct:            true,
		FirstByteMS:       done.FirstByteMS,
		FirstByteMeasured: firstByteMeasuredFlag(sendStats.FirstByteAt, done.FirstByteMeasured, done.FirstByteMS),
		LossRate:          retransmitRatio(sendStats.Retransmits, sendStats.PacketsSent),
		Retransmits:       sendStats.Retransmits,
		Success:           boolPtr(true),
		Local:             sendStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func runReverseParallelBlastOrchestrate(runCtx context.Context, cfg OrchestrateConfig, runner SSHRunner) (RunReport, error) {
	localConns, err := listenParallelPacketConns(runCtx, cfg.Parallel)
	if err != nil {
		return RunReport{}, err
	}
	defer closePacketConns(localConns)

	localCandidates, err := discoverCandidatesForPacketConns(runCtx, localConns)
	if err != nil {
		return RunReport{}, err
	}
	localCandidates = limitCandidatesInOrder(localCandidates, parallelCandidateLimit(cfg.Parallel))
	probeTracef("reverse local candidates: %s", strings.Join(CandidateStringsInOrder(localCandidates), ","))

	clientCfg := ClientConfig{
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		SizeBytes:         cfg.SizeBytes,
		PeerCandidatesCSV: strings.Join(CandidateStringsInOrder(localCandidates), ","),
		Parallel:          cfg.Parallel,
	}
	handle, err := launchRemoteClient(runCtx, runner, clientCfg)
	if err != nil {
		return RunReport{}, err
	}
	completed := false
	defer func() {
		if !completed && handle.wait != nil {
			_ = handle.wait()
		}
	}()

	var stderrBuf bytes.Buffer
	var stderrWG sync.WaitGroup
	if handle.stderr != nil {
		stderrWG.Add(1)
		go func() {
			defer stderrWG.Done()
			_, _ = io.Copy(traceStderrWriter(&stderrBuf), handle.stderr)
		}()
	}

	events := make(chan outputEvent, 8)
	go scanRemoteOutput(handle.stdout, events)

	ready, err := waitForRemoteReady(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates := limitCandidatesInOrder(ParseCandidateStrings(ready.Candidates), parallelCandidateLimit(cfg.Parallel))
	probeTracef("reverse remote candidates: %s", strings.Join(CandidateStringsInOrder(remoteCandidates), ","))

	punchCtx, punchCancel := context.WithCancel(runCtx)
	defer punchCancel()
	for _, conn := range localConns {
		go PunchAddrs(punchCtx, conn, remoteCandidates, []byte(defaultPunchPayload), defaultPunchInterval)
	}

	recvCtx, recvCancel := context.WithCancel(runCtx)
	defer recvCancel()
	type receiveResult struct {
		stats TransferStats
		err   error
	}
	type doneResult struct {
		done remoteDone
		err  error
	}
	recvCh := make(chan receiveResult, 1)
	doneCh := make(chan doneResult, 1)
	go func() {
		stats, err := orchestrateReceiveBlastParallel(recvCtx, localConns, io.Discard, ReceiveConfig{
			Blast:           true,
			Transport:       cfg.Transport,
			RequireComplete: probeRequireComplete(),
		}, cfg.SizeBytes)
		recvCh <- receiveResult{stats: stats, err: err}
	}()
	go func() {
		done, err := waitForRemoteDone(runCtx, events, &stderrBuf)
		doneCh <- doneResult{done: done, err: err}
	}()

	var recvStats TransferStats
	var done remoteDone
	var gotRecv, gotDone bool
	for !gotRecv || !gotDone {
		select {
		case result := <-recvCh:
			if result.err != nil {
				recvCancel()
				punchCancel()
				return RunReport{}, result.err
			}
			recvStats = result.stats
			gotRecv = true
		case result := <-doneCh:
			if result.err != nil {
				recvCancel()
				punchCancel()
				return RunReport{}, result.err
			}
			done = result.done
			gotDone = true
		case <-runCtx.Done():
			recvCancel()
			punchCancel()
			return RunReport{}, runCtx.Err()
		}
	}
	punchCancel()
	if handle.wait != nil {
		if err := handle.wait(); err != nil {
			if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
				return RunReport{}, fmt.Errorf("remote client failed: %w: %s", err, msg)
			}
			return RunReport{}, err
		}
	}
	stderrWG.Wait()
	completed = true

	durationMS := elapsedMS(recvStats.StartedAt, recvStats.CompletedAt)
	if durationMS <= 0 {
		durationMS = done.DurationMS
	}
	bytesReceived := recvStats.BytesReceived
	if bytesReceived <= 0 {
		bytesReceived = done.BytesSent
	}
	if err := requireExpectedBytes(bytesReceived, cfg.SizeBytes); err != nil {
		return RunReport{}, err
	}
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		Direct:            true,
		FirstByteMS:       elapsedMS(recvStats.StartedAt, recvStats.FirstByteAt),
		FirstByteMeasured: firstByteMeasuredFlag(recvStats.FirstByteAt, done.FirstByteMeasured, done.FirstByteMS),
		LossRate:          retransmitRatio(done.Retransmits, done.PacketsSent),
		Retransmits:       done.Retransmits,
		Success:           boolPtr(true),
		Local:             recvStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func listenParallelPacketConns(ctx context.Context, parallel int) ([]net.PacketConn, error) {
	if parallel <= 0 {
		parallel = 1
	}
	conns := make([]net.PacketConn, 0, parallel)
	for len(conns) < parallel {
		if err := ctx.Err(); err != nil {
			closePacketConns(conns)
			return nil, err
		}
		conn, err := listenPacket("udp", ":0")
		if err != nil {
			closePacketConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func closePacketConns(conns []net.PacketConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func discoverCandidatesForPacketConns(ctx context.Context, conns []net.PacketConn) ([]net.Addr, error) {
	type result struct {
		index int
		addrs []net.Addr
		err   error
	}
	results := make(chan result, len(conns))
	var wg sync.WaitGroup
	for i, conn := range conns {
		if conn == nil {
			continue
		}
		wg.Add(1)
		go func(i int, conn net.PacketConn) {
			defer wg.Done()
			addrs, err := orchestrateDiscoverCandidates(ctx, conn)
			results <- result{index: i, addrs: addrs, err: err}
		}(i, conn)
	}
	wg.Wait()
	close(results)

	byConn := make([][]net.Addr, len(conns))
	seen := make(map[string]net.Addr)
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		if result.index >= 0 && result.index < len(byConn) {
			byConn[result.index] = result.addrs
		}
	}
	out := make([]net.Addr, 0)
	for _, addrs := range byConn {
		for _, addr := range preferredCandidates(addrs, 1) {
			if addr == nil || seen[addr.String()] != nil {
				continue
			}
			seen[addr.String()] = addr
			out = append(out, addr)
		}
	}
	for _, addrs := range byConn {
		for _, addr := range addrs {
			if addr == nil {
				continue
			}
			if seen[addr.String()] != nil {
				continue
			}
			seen[addr.String()] = addr
			out = append(out, addr)
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func parallelCandidateLimit(parallel int) int {
	if parallel < 1 {
		parallel = 1
	}
	limit := parallel * 8
	if limit < 8 {
		return 8
	}
	return limit
}

func parallelCandidateStrings(candidates []net.Addr, parallel int) []string {
	if parallel <= 0 {
		parallel = 1
	}
	ordered := preferredCandidates(candidates, len(candidates))
	out := make([]string, 0, parallel)
	seen := make(map[string]bool)
	seenPort := make(map[int]bool)
	for _, addr := range ordered {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || seenPort[udpAddr.Port] {
			continue
		}
		candidate := addr.String()
		out = append(out, candidate)
		seen[candidate] = true
		seenPort[udpAddr.Port] = true
		if len(out) == parallel {
			return out
		}
	}
	for _, addr := range ordered {
		candidate := addr.String()
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) == parallel {
			return out
		}
	}
	return out
}

func parallelCandidateStringsInOrder(candidates []net.Addr, parallel int) []string {
	if parallel <= 0 {
		parallel = 1
	}
	out := make([]string, 0, parallel)
	seen := make(map[string]bool)
	seenPort := make(map[int]bool)
	for _, addr := range candidates {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || seenPort[udpAddr.Port] {
			continue
		}
		candidate := addr.String()
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		seenPort[udpAddr.Port] = true
		if len(out) == parallel {
			return out
		}
	}
	for _, candidate := range CandidateStringsInOrder(candidates) {
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) == parallel {
			return out
		}
	}
	return out
}

func limitCandidatesInOrder(candidates []net.Addr, limit int) []net.Addr {
	if limit <= 0 || len(candidates) <= limit {
		return candidates
	}
	return candidates[:limit]
}

func selectRemoteAddrsByConn(observedByConn [][]net.Addr, fallback []string, parallel int) []string {
	if parallel <= 0 {
		parallel = len(fallback)
	}
	out := make([]string, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		for _, candidate := range parallelCandidateStrings(observedByConn[i], len(observedByConn[i])) {
			endpoint := remoteCandidateEndpointKey(candidate)
			if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
				continue
			}
			out[i] = candidate
			seen[candidate] = true
			seenEndpoint[endpoint] = true
			break
		}
	}
	for i := range out {
		if out[i] != "" {
			continue
		}
		for _, candidate := range fallback {
			endpoint := remoteCandidateEndpointKey(candidate)
			if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
				continue
			}
			out[i] = candidate
			seen[out[i]] = true
			seenEndpoint[endpoint] = true
			break
		}
	}

	return out
}

func remoteCandidateEndpointKey(candidate string) string {
	addrPort, err := netip.ParseAddrPort(candidate)
	if err != nil {
		return candidate
	}
	return strconv.Itoa(int(addrPort.Port()))
}

func formatObservedAddrsByConn(observedByConn [][]net.Addr) string {
	parts := make([]string, 0, len(observedByConn))
	for i, observed := range observedByConn {
		parts = append(parts, fmt.Sprintf("%d=%s", i, strings.Join(parallelCandidateStrings(observed, len(observed)), "|")))
	}
	return strings.Join(parts, ",")
}

func sendParallelBlastShares(ctx context.Context, conns []net.PacketConn, remotes []string, cfg OrchestrateConfig) (TransferStats, error) {
	conns, remotes = parallelBlastPairs(conns, remotes)
	if len(conns) == 0 || len(remotes) == 0 {
		return TransferStats{}, errors.New("parallel blast requires local sockets and remote candidates")
	}
	shares := splitOrchestrateShares(cfg.SizeBytes, len(conns))
	rateMbps := perShareRateMbps(probeRateMbps(), len(conns))
	startedAt := time.Now()
	type result struct {
		stats TransferStats
		err   error
	}
	results := make(chan result, len(conns))
	for i, conn := range conns {
		share := shares[i]
		remote := remotes[i]
		go func(conn net.PacketConn, remote string, share int64) {
			probeTracef("forward sending share bytes=%d remote=%s local=%s", share, remote, conn.LocalAddr())
			stats, err := orchestrateSend(ctx, conn, remote, newSizedReader(share), SendConfig{
				Blast:          true,
				Transport:      cfg.Transport,
				ChunkSize:      probeChunkSize(),
				WindowSize:     probeWindowSize(cfg.Mode, cfg.Transport),
				Parallel:       1,
				RateMbps:       rateMbps,
				RepairPayloads: probeRepairPayloads(),
			})
			results <- result{stats: stats, err: err}
		}(conn, remote, share)
	}

	out := TransferStats{StartedAt: startedAt}
	for range conns {
		result := <-results
		if result.err != nil {
			return TransferStats{}, result.err
		}
		out.BytesSent += result.stats.BytesSent
		out.PacketsSent += result.stats.PacketsSent
		out.PacketsAcked += result.stats.PacketsAcked
		out.Retransmits += result.stats.Retransmits
		if !result.stats.FirstByteAt.IsZero() && (out.FirstByteAt.IsZero() || result.stats.FirstByteAt.Before(out.FirstByteAt)) {
			out.FirstByteAt = result.stats.FirstByteAt
		}
		if out.Transport.Kind == "" {
			out.Transport = result.stats.Transport
		}
	}
	out.CompletedAt = time.Now()
	return out, nil
}

func parallelBlastPairs(conns []net.PacketConn, remotes []string) ([]net.PacketConn, []string) {
	limit := len(conns)
	if len(remotes) < limit {
		limit = len(remotes)
	}
	pairedConns := make([]net.PacketConn, 0, limit)
	pairedRemotes := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		if conns[i] == nil || remotes[i] == "" {
			continue
		}
		pairedConns = append(pairedConns, conns[i])
		pairedRemotes = append(pairedRemotes, remotes[i])
	}
	return pairedConns, pairedRemotes
}

func splitOrchestrateShares(total int64, parallel int) []int64 {
	if total <= 0 || parallel <= 1 {
		return []int64{total}
	}
	if int64(parallel) > total {
		parallel = int(total)
	}
	base := total / int64(parallel)
	extra := total % int64(parallel)
	shares := make([]int64, 0, parallel)
	for i := 0; i < parallel; i++ {
		share := base
		if int64(i) < extra {
			share++
		}
		if share > 0 {
			shares = append(shares, share)
		}
	}
	if len(shares) == 0 {
		return []int64{total}
	}
	return shares
}

func perShareRateMbps(totalRateMbps int, shares int) int {
	if totalRateMbps <= 0 {
		return 0
	}
	if shares <= 1 {
		return totalRateMbps
	}
	rate := totalRateMbps / shares
	if rate <= 0 {
		return 1
	}
	return rate
}

func runForwardOrchestrate(runCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, localCandidates []net.Addr, runner SSHRunner) (RunReport, error) {
	var wgPlan wireGuardPlan
	if cfg.Mode == "wg" || cfg.Mode == "wgos" {
		var err error
		wgPlan, err = newWireGuardPlan()
		if err != nil {
			return RunReport{}, err
		}
	}
	serverCfg := ServerConfig{
		ListenAddr:        cfg.ListenAddr,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		PeerCandidatesCSV: strings.Join(CandidateStrings(localCandidates), ","),
		SizeBytes:         cfg.SizeBytes,
		Parallel:          cfg.Parallel,
	}
	if cfg.Mode == "wg" || cfg.Mode == "wgos" {
		serverCfg.WGPrivateKeyHex = wgPlan.listenerPrivHex
		serverCfg.WGPeerPublicHex = wgPlan.senderPubHex
		serverCfg.WGLocalAddr = wgPlan.listenerAddr.String()
		serverCfg.WGPeerAddr = wgPlan.senderAddr.String()
		serverCfg.WGPort = wgPlan.port
	}
	handle, err := launchRemoteServer(runCtx, runner, serverCfg)
	if err != nil {
		return RunReport{}, err
	}
	completed := false
	defer func() {
		if !completed && handle.wait != nil {
			_ = handle.wait()
		}
	}()

	var stderrBuf bytes.Buffer
	var stderrWG sync.WaitGroup
	if handle.stderr != nil {
		stderrWG.Add(1)
		go func() {
			defer stderrWG.Done()
			_, _ = io.Copy(&stderrBuf, handle.stderr)
		}()
	}

	events := make(chan outputEvent, 8)
	go scanRemoteOutput(handle.stdout, events)

	ready, err := waitForRemoteReady(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates := ParseCandidateStrings(ready.Candidates)
	remoteCandidates = preferredCandidates(remoteCandidates, 8)
	remoteAddr := ""
	if len(remoteCandidates) > 0 {
		remoteAddr = remoteCandidates[0].String()
	}
	if remoteAddr == "" && ready.Addr != "" {
		if addr, err := net.ResolveUDPAddr("udp", ready.Addr); err == nil {
			if preferred := preferredCandidates([]net.Addr{addr}, 1); len(preferred) > 0 {
				remoteAddr = preferred[0].String()
				remoteCandidates = preferred
			}
		}
	}
	if remoteAddr == "" {
		return RunReport{}, errors.New("remote server did not report a usable address")
	}
	if len(remoteCandidates) == 0 {
		if addr, err := net.ResolveUDPAddr("udp", remoteAddr); err == nil {
			remoteCandidates = []net.Addr{addr}
		}
	}

	punchCtx, punchCancel := context.WithCancel(runCtx)
	defer punchCancel()
	go PunchAddrs(punchCtx, localConn, remoteCandidates, []byte(defaultPunchPayload), defaultPunchInterval)

	src := newSizedReader(cfg.SizeBytes)
	var sendStats TransferStats
	if cfg.Mode == "wg" {
		sendStats, err = SendWireGuard(runCtx, localConn, src, WireGuardConfig{
			Transport:      cfg.Transport,
			PrivateKeyHex:  wgPlan.senderPrivHex,
			PeerPublicHex:  wgPlan.listenerPubHex,
			LocalAddr:      wgPlan.senderAddr.String(),
			PeerAddr:       wgPlan.listenerAddr.String(),
			DirectEndpoint: remoteAddr,
			PeerCandidates: remoteCandidates,
			Port:           uint16(wgPlan.port),
			Streams:        cfg.Parallel,
			SizeBytes:      cfg.SizeBytes,
		})
	} else if cfg.Mode == "wgos" {
		sendStats, err = SendWireGuardOS(runCtx, localConn, src, WireGuardConfig{
			Transport:      cfg.Transport,
			PrivateKeyHex:  wgPlan.senderPrivHex,
			PeerPublicHex:  wgPlan.listenerPubHex,
			LocalAddr:      wgPlan.senderAddr.String(),
			PeerAddr:       wgPlan.listenerAddr.String(),
			DirectEndpoint: remoteAddr,
			PeerCandidates: remoteCandidates,
			Port:           uint16(wgPlan.port),
			Streams:        cfg.Parallel,
			SizeBytes:      cfg.SizeBytes,
		})
	} else {
		sendStats, err = orchestrateSend(runCtx, localConn, remoteAddr, src, SendConfig{
			Raw:            cfg.Mode == "raw",
			Blast:          cfg.Mode == "blast",
			Transport:      cfg.Transport,
			ChunkSize:      probeChunkSize(),
			WindowSize:     probeWindowSize(cfg.Mode, cfg.Transport),
			Parallel:       cfg.Parallel,
			RateMbps:       probeRateMbps(),
			RepairPayloads: probeRepairPayloads(),
		})
	}
	punchCancel()
	if err != nil {
		return RunReport{}, err
	}

	done, err := waitForRemoteDone(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}

	if handle.wait != nil {
		if err := handle.wait(); err != nil {
			if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
				return RunReport{}, fmt.Errorf("remote server failed: %w: %s", err, msg)
			}
			return RunReport{}, err
		}
	}
	stderrWG.Wait()
	completed = true

	durationMS := done.DurationMS
	if durationMS <= 0 {
		durationMS = elapsedMS(sendStats.StartedAt, sendStats.CompletedAt)
	}
	bytesReceived := done.BytesReceived
	if bytesReceived <= 0 {
		bytesReceived = cfg.SizeBytes
	}
	if err := requireExpectedBytes(bytesReceived, cfg.SizeBytes); err != nil {
		return RunReport{}, err
	}

	report := RunReport{
		Host:          cfg.Host,
		Mode:          cfg.Mode,
		Transport:     cfg.Transport,
		Direction:     cfg.Direction,
		SizeBytes:     cfg.SizeBytes,
		BytesReceived: bytesReceived,
		DurationMS:    durationMS,
		GoodputMbps:   goodputMbps(bytesReceived, durationMS),
		Direct:        true,
		FirstByteMS:   done.FirstByteMS,
		LossRate:      retransmitRatio(sendStats.Retransmits, sendStats.PacketsSent),
		Retransmits:   sendStats.Retransmits,
		Success:       boolPtr(true),
		Local:         sendStats.Transport,
		Remote:        ready.Transport,
	}
	if done.FirstByteMeasured != nil {
		report.FirstByteMeasured = done.FirstByteMeasured
	} else if done.FirstByteMS > 0 {
		report.FirstByteMeasured = boolPtr(true)
	}
	return report, nil
}

func firstByteMeasuredFlag(localFirstByteAt time.Time, remoteMeasured *bool, remoteFirstByteMS int64) *bool {
	if !localFirstByteAt.IsZero() {
		return boolPtr(true)
	}
	if remoteMeasured != nil {
		return remoteMeasured
	}
	if remoteFirstByteMS > 0 {
		return boolPtr(true)
	}
	return nil
}

func runReverseOrchestrate(runCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, localCandidates []net.Addr, runner SSHRunner) (RunReport, error) {
	var wgPlan wireGuardPlan
	if cfg.Mode == "wg" || cfg.Mode == "wgos" {
		var err error
		wgPlan, err = newWireGuardPlan()
		if err != nil {
			return RunReport{}, err
		}
	}
	clientCfg := ClientConfig{
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		SizeBytes:         cfg.SizeBytes,
		PeerCandidatesCSV: strings.Join(CandidateStrings(localCandidates), ","),
		Parallel:          cfg.Parallel,
	}
	if cfg.Mode == "wg" || cfg.Mode == "wgos" {
		clientCfg.WGPrivateKeyHex = wgPlan.senderPrivHex
		clientCfg.WGPeerPublicHex = wgPlan.listenerPubHex
		clientCfg.WGLocalAddr = wgPlan.senderAddr.String()
		clientCfg.WGPeerAddr = wgPlan.listenerAddr.String()
		clientCfg.WGPort = wgPlan.port
	}
	handle, err := launchRemoteClient(runCtx, runner, clientCfg)
	if err != nil {
		return RunReport{}, err
	}
	completed := false
	defer func() {
		if !completed && handle.wait != nil {
			_ = handle.wait()
		}
	}()

	var stderrBuf bytes.Buffer
	var stderrWG sync.WaitGroup
	if handle.stderr != nil {
		stderrWG.Add(1)
		go func() {
			defer stderrWG.Done()
			_, _ = io.Copy(&stderrBuf, handle.stderr)
		}()
	}

	events := make(chan outputEvent, 8)
	go scanRemoteOutput(handle.stdout, events)

	ready, err := waitForRemoteReady(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates := ParseCandidateStrings(ready.Candidates)
	remoteCandidates = preferredCandidates(remoteCandidates, 8)

	punchCtx, punchCancel := context.WithCancel(runCtx)
	defer punchCancel()
	go PunchAddrs(punchCtx, localConn, remoteCandidates, []byte(defaultPunchPayload), defaultPunchInterval)

	recvCtx, recvCancel := context.WithCancel(runCtx)
	defer recvCancel()
	type receiveResult struct {
		stats TransferStats
		err   error
	}
	type doneResult struct {
		done remoteDone
		err  error
	}
	recvCh := make(chan receiveResult, 1)
	doneCh := make(chan doneResult, 1)
	go func() {
		var stats TransferStats
		var err error
		if cfg.Mode == "wg" {
			stats, err = ReceiveWireGuardToWriter(recvCtx, localConn, io.Discard, WireGuardConfig{
				Transport:      cfg.Transport,
				PrivateKeyHex:  wgPlan.listenerPrivHex,
				PeerPublicHex:  wgPlan.senderPubHex,
				LocalAddr:      wgPlan.listenerAddr.String(),
				PeerAddr:       wgPlan.senderAddr.String(),
				PeerCandidates: remoteCandidates,
				Port:           uint16(wgPlan.port),
				Streams:        cfg.Parallel,
				SizeBytes:      cfg.SizeBytes,
			})
		} else if cfg.Mode == "wgos" {
			stats, err = ReceiveWireGuardOSToWriter(recvCtx, localConn, io.Discard, WireGuardConfig{
				Transport:      cfg.Transport,
				PrivateKeyHex:  wgPlan.listenerPrivHex,
				PeerPublicHex:  wgPlan.senderPubHex,
				LocalAddr:      wgPlan.listenerAddr.String(),
				PeerAddr:       wgPlan.senderAddr.String(),
				PeerCandidates: remoteCandidates,
				Port:           uint16(wgPlan.port),
				Streams:        cfg.Parallel,
				SizeBytes:      cfg.SizeBytes,
			})
		} else if cfg.Mode == "blast" {
			stats, err = orchestrateReceiveBlastParallel(recvCtx, []net.PacketConn{localConn}, io.Discard, ReceiveConfig{
				Blast:           true,
				Transport:       cfg.Transport,
				RequireComplete: probeRequireComplete(),
			}, cfg.SizeBytes)
		} else {
			stats, err = orchestrateReceive(recvCtx, localConn, "", io.Discard, ReceiveConfig{
				Raw:       cfg.Mode == "raw",
				Transport: cfg.Transport,
			})
		}
		recvCh <- receiveResult{stats: stats, err: err}
	}()
	go func() {
		done, err := waitForRemoteDone(runCtx, events, &stderrBuf)
		doneCh <- doneResult{done: done, err: err}
	}()

	var recvStats TransferStats
	var done remoteDone
	var gotRecv, gotDone bool
	for !gotRecv || !gotDone {
		select {
		case result := <-recvCh:
			if result.err != nil {
				punchCancel()
				return RunReport{}, result.err
			}
			recvStats = result.stats
			gotRecv = true
		case result := <-doneCh:
			if result.err != nil {
				recvCancel()
				punchCancel()
				return RunReport{}, result.err
			}
			done = result.done
			gotDone = true
		case <-runCtx.Done():
			recvCancel()
			punchCancel()
			return RunReport{}, runCtx.Err()
		}
	}
	punchCancel()
	if handle.wait != nil {
		if err := handle.wait(); err != nil {
			if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
				return RunReport{}, fmt.Errorf("remote client failed: %w: %s", err, msg)
			}
			return RunReport{}, err
		}
	}
	stderrWG.Wait()
	completed = true

	durationMS := recvStats.CompletedAt.Sub(recvStats.StartedAt).Milliseconds()
	if durationMS <= 0 {
		durationMS = done.DurationMS
	}
	bytesReceived := recvStats.BytesReceived
	if bytesReceived <= 0 {
		bytesReceived = done.BytesSent
	}
	if err := requireExpectedBytes(bytesReceived, cfg.SizeBytes); err != nil {
		return RunReport{}, err
	}

	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		Direct:            true,
		FirstByteMS:       elapsedMS(recvStats.StartedAt, recvStats.FirstByteAt),
		FirstByteMeasured: firstByteMeasuredFlag(recvStats.FirstByteAt, done.FirstByteMeasured, done.FirstByteMS),
		LossRate:          retransmitRatio(done.Retransmits, done.PacketsSent),
		Retransmits:       done.Retransmits,
		Success:           boolPtr(true),
		Local:             recvStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func runWireGuardOSIperfOrchestrate(runCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, localCandidates []net.Addr, runner SSHRunner) (RunReport, error) {
	wgPlan, err := newWireGuardPlan()
	if err != nil {
		return RunReport{}, err
	}
	serverCfg := ServerConfig{
		ListenAddr:        cfg.ListenAddr,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		PeerCandidatesCSV: strings.Join(CandidateStrings(localCandidates), ","),
		SizeBytes:         cfg.SizeBytes,
		Parallel:          cfg.Parallel,
		WGPrivateKeyHex:   wgPlan.listenerPrivHex,
		WGPeerPublicHex:   wgPlan.senderPubHex,
		WGLocalAddr:       wgPlan.listenerAddr.String(),
		WGPeerAddr:        wgPlan.senderAddr.String(),
		WGPort:            wgPlan.port,
	}
	handle, err := launchRemoteServer(runCtx, runner, serverCfg)
	if err != nil {
		return RunReport{}, err
	}
	completed := false
	defer func() {
		if !completed && handle.wait != nil {
			_ = handle.wait()
		}
	}()

	var stderrBuf bytes.Buffer
	var stderrWG sync.WaitGroup
	if handle.stderr != nil {
		stderrWG.Add(1)
		go func() {
			defer stderrWG.Done()
			_, _ = io.Copy(&stderrBuf, handle.stderr)
		}()
	}

	events := make(chan outputEvent, 8)
	go scanRemoteOutput(handle.stdout, events)

	ready, err := waitForRemoteReady(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates := ParseCandidateStrings(ready.Candidates)
	remoteCandidates = preferredCandidates(remoteCandidates, 8)
	remoteAddr := ""
	if len(remoteCandidates) > 0 {
		remoteAddr = remoteCandidates[0].String()
	}
	if remoteAddr == "" && ready.Addr != "" {
		if addr, err := net.ResolveUDPAddr("udp", ready.Addr); err == nil {
			if preferred := preferredCandidates([]net.Addr{addr}, 1); len(preferred) > 0 {
				remoteAddr = preferred[0].String()
				remoteCandidates = preferred
			}
		}
	}
	if remoteAddr == "" {
		return RunReport{}, errors.New("remote server did not report a usable address")
	}

	sendStats, err := orchestrateSendWireGuardOSIperf(runCtx, localConn, WireGuardConfig{
		Transport:      cfg.Transport,
		PrivateKeyHex:  wgPlan.senderPrivHex,
		PeerPublicHex:  wgPlan.listenerPubHex,
		LocalAddr:      wgPlan.senderAddr.String(),
		PeerAddr:       wgPlan.listenerAddr.String(),
		DirectEndpoint: remoteAddr,
		PeerCandidates: remoteCandidates,
		Port:           uint16(wgPlan.port),
		Streams:        cfg.Parallel,
		SizeBytes:      cfg.SizeBytes,
		Reverse:        cfg.Direction == "reverse",
	})
	if err != nil {
		return RunReport{}, err
	}
	done, err := waitForRemoteDone(runCtx, events, &stderrBuf)
	if err != nil {
		return RunReport{}, err
	}
	if handle.wait != nil {
		if err := handle.wait(); err != nil {
			if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
				return RunReport{}, fmt.Errorf("remote server failed: %w: %s", err, msg)
			}
			return RunReport{}, err
		}
	}
	stderrWG.Wait()
	completed = true

	durationMS := elapsedMS(sendStats.StartedAt, sendStats.CompletedAt)
	if durationMS <= 0 {
		durationMS = done.DurationMS
	}
	bytesReceived := sendStats.BytesReceived
	if bytesReceived <= 0 {
		bytesReceived = done.BytesReceived
	}
	if err := requireExpectedBytes(bytesReceived, cfg.SizeBytes); err != nil {
		return RunReport{}, err
	}
	return RunReport{
		Host:          cfg.Host,
		Mode:          cfg.Mode,
		Transport:     cfg.Transport,
		Direction:     cfg.Direction,
		SizeBytes:     cfg.SizeBytes,
		BytesReceived: bytesReceived,
		DurationMS:    durationMS,
		GoodputMbps:   goodputMbps(bytesReceived, durationMS),
		Direct:        true,
		FirstByteMS:   elapsedMS(sendStats.StartedAt, sendStats.FirstByteAt),
		Success:       boolPtr(true),
		Local:         sendStats.Transport,
		Remote:        ready.Transport,
	}, nil
}

func waitForRemoteReady(ctx context.Context, events <-chan outputEvent, stderr *bytes.Buffer) (remoteReady, error) {
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				if msg := strings.TrimSpace(stderr.String()); msg != "" {
					return remoteReady{}, errors.New(msg)
				}
				return remoteReady{}, errors.New("remote server closed stdout before READY")
			}
			if ev.err != nil {
				return remoteReady{}, ev.err
			}
			if ev.ready != nil {
				return *ev.ready, nil
			}
		case <-ctx.Done():
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return remoteReady{}, fmt.Errorf("%w: %s", ctx.Err(), msg)
			}
			return remoteReady{}, ctx.Err()
		}
	}
}

func waitForRemoteDone(ctx context.Context, events <-chan outputEvent, stderr *bytes.Buffer) (remoteDone, error) {
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				if msg := strings.TrimSpace(stderr.String()); msg != "" {
					return remoteDone{}, errors.New(msg)
				}
				return remoteDone{}, errors.New("remote server closed stdout before DONE")
			}
			if ev.err != nil {
				return remoteDone{}, ev.err
			}
			if ev.done != nil {
				return *ev.done, nil
			}
		case <-ctx.Done():
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return remoteDone{}, fmt.Errorf("%w: %s", ctx.Err(), msg)
			}
			return remoteDone{}, ctx.Err()
		}
	}
}

func scanRemoteOutput(stdout io.Reader, events chan<- outputEvent) {
	defer close(events)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ev, ok := parseRemoteLine(line)
		if !ok {
			continue
		}
		events <- ev
	}
	if err := scanner.Err(); err != nil {
		events <- outputEvent{err: err}
	}
}

func parseRemoteLine(line string) (outputEvent, bool) {
	if strings.HasPrefix(line, "READY ") {
		var ready remoteReady
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "READY ")), &ready); err != nil {
			return outputEvent{err: err}, true
		}
		return outputEvent{ready: &ready}, true
	}
	if strings.HasPrefix(line, "DONE ") {
		var done remoteDone
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "DONE ")), &done); err != nil {
			return outputEvent{err: err}, true
		}
		return outputEvent{done: &done}, true
	}
	return outputEvent{}, false
}

type sizedReader struct {
	remaining int64
}

func newSizedReader(size int64) io.Reader {
	if size < 0 {
		size = 0
	}
	return &sizedReader{remaining: size}
}

func (r *sizedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	r.remaining -= int64(n)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func goodputMbps(bytes int64, durationMS int64) float64 {
	if bytes <= 0 || durationMS <= 0 {
		return 0
	}
	return float64(bytes*8) / (float64(durationMS) / 1000.0) / 1e6
}

func retransmitRatio(retransmits, packetsSent int64) float64 {
	if retransmits <= 0 || packetsSent <= 0 {
		return 0
	}
	return float64(retransmits) / float64(packetsSent)
}

func elapsedMS(start, end time.Time) int64 {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}

func requireExpectedBytes(received, expected int64) error {
	if expected <= 0 || received == expected {
		return nil
	}
	return fmt.Errorf("received %d bytes, want %d", received, expected)
}

func probeWindowSize(mode, transport string) int {
	if raw := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_WINDOW")); raw != "" {
		return envPositiveInt("DERPCAT_PROBE_WINDOW", defaultProbeWindowSize)
	}
	if raw := strings.TrimSpace(os.Getenv("DERPCAT_PROBE_WINDOW_SIZE")); raw != "" {
		return envPositiveInt("DERPCAT_PROBE_WINDOW_SIZE", defaultProbeWindowSize)
	}
	if mode == "raw" {
		if normalized, err := normalizeTransport(transport); err == nil && normalized == probeTransportBatched {
			return 384
		}
		return 256
	}
	return defaultProbeWindowSize
}

func probeChunkSize() int {
	return envPositiveInt("DERPCAT_PROBE_CHUNK_SIZE", defaultChunkSize)
}

func probeRateMbps() int {
	return envPositiveInt("DERPCAT_PROBE_RATE_MBPS", 0)
}

func probeRequireComplete() bool {
	return envBool("DERPCAT_PROBE_REQUIRE_COMPLETE")
}

func probeRepairPayloads() bool {
	return envBool("DERPCAT_PROBE_REPAIR_PAYLOADS")
}

func envBool(key string) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	return raw == "1" || strings.EqualFold(raw, "true") || strings.EqualFold(raw, "yes")
}

func envPositiveInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func probeTracef(format string, args ...any) {
	if strings.TrimSpace(os.Getenv("DERPCAT_PROBE_TRACE")) == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "probe-trace: "+format+"\n", args...)
}

func traceStderrWriter(buf *bytes.Buffer) io.Writer {
	if strings.TrimSpace(os.Getenv("DERPCAT_PROBE_TRACE")) == "" {
		return buf
	}
	return io.MultiWriter(buf, os.Stderr)
}
