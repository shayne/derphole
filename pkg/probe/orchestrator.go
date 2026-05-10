// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	defaultProbeRemotePath      = "/tmp/derphole-probe"
	defaultSSHConnectTimeoutSec = 5
	defaultProbeWindowSize      = 1024
)

var listenPacket = net.ListenPacket
var orchestrateDiscoverCandidates = DiscoverCandidates
var orchestrateSend = Send
var orchestrateSendWireGuard = SendWireGuard
var orchestrateSendWireGuardOS = SendWireGuardOS
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

type remoteProcessSession struct {
	handle    *remoteServerHandle
	stderrBuf bytes.Buffer
	stderrWG  sync.WaitGroup
	events    chan outputEvent
	completed bool
}

func newRemoteProcessSession(handle *remoteServerHandle, traceStderr bool) *remoteProcessSession {
	session := &remoteProcessSession{
		handle: handle,
		events: make(chan outputEvent, 8),
	}
	if handle.stderr != nil {
		session.stderrWG.Add(1)
		go session.copyStderr(traceStderr)
	}
	go scanRemoteOutput(handle.stdout, session.events)
	return session
}

func (s *remoteProcessSession) copyStderr(traceStderr bool) {
	defer s.stderrWG.Done()
	dst := io.Writer(&s.stderrBuf)
	if traceStderr {
		dst = traceStderrWriter(&s.stderrBuf)
	}
	_, _ = io.Copy(dst, s.handle.stderr)
}

func (s *remoteProcessSession) cleanup() {
	if !s.completed && s.handle.wait != nil {
		_ = s.handle.wait()
	}
}

func (s *remoteProcessSession) ready(ctx context.Context) (remoteReady, error) {
	return waitForRemoteReady(ctx, s.events, &s.stderrBuf)
}

func (s *remoteProcessSession) done(ctx context.Context) (remoteDone, error) {
	return waitForRemoteDone(ctx, s.events, &s.stderrBuf)
}

func (s *remoteProcessSession) finish(failurePrefix string) error {
	if s.handle.wait != nil {
		if err := s.handle.wait(); err != nil {
			return remoteProcessWaitError(failurePrefix, err, &s.stderrBuf)
		}
	}
	s.stderrWG.Wait()
	s.completed = true
	return nil
}

func remoteProcessWaitError(prefix string, err error, stderr *bytes.Buffer) error {
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("%s: %w: %s", prefix, err, msg)
	}
	return err
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
	if trace := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_WG_TRACE")); trace != "" {
		env = append(env, "DERPHOLE_PROBE_WG_TRACE="+trace)
	}
	if trace := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_TRACE")); trace != "" {
		env = append(env, "DERPHOLE_PROBE_TRACE="+trace)
	}
	if rate := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_RATE_MBPS")); rate != "" {
		env = append(env, "DERPHOLE_PROBE_RATE_MBPS="+rate)
	}
	if requireComplete := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_REQUIRE_COMPLETE")); requireComplete != "" {
		env = append(env, "DERPHOLE_PROBE_REQUIRE_COMPLETE="+requireComplete)
	}
	if repairPayloads := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_REPAIR_PAYLOADS")); repairPayloads != "" {
		env = append(env, "DERPHOLE_PROBE_REPAIR_PAYLOADS="+repairPayloads)
	}
	return env
}

func (r SSHRunner) ServerCommand(cfg ServerConfig) []string {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	mode := defaultProbeMode(cfg.Mode)
	argv := r.probeCommandPrefix()
	argv = append(argv,
		r.binaryPath(),
		"server",
		"--listen", listenAddr,
		"--mode", mode,
		"--transport", defaultProbeTransport(cfg.Transport),
	)
	argv = appendOptionalStringFlag(argv, "--peer-candidates", cfg.PeerCandidatesCSV)
	argv = appendWireGuardConfigFlags(argv, cfg.WGPrivateKeyHex, cfg.WGPeerPublicHex, cfg.WGLocalAddr, cfg.WGPeerAddr, cfg.WGPort)
	argv = appendOptionalInt64Flag(argv, "--size-bytes", cfg.SizeBytes)
	return appendParallelFlag(argv, mode, cfg.Parallel)
}

func defaultProbeMode(mode string) string {
	if mode == "" {
		return "raw"
	}
	return mode
}

func defaultProbeTransport(transport string) string {
	if transport == "" {
		return probeTransportLegacy
	}
	return transport
}

func (r SSHRunner) probeCommandPrefix() []string {
	argv := r.sshCommandPrefix()
	argv = append(argv, r.target())
	return appendProbeEnv(argv)
}

func (r SSHRunner) sshCommandPrefix() []string {
	argv := []string{
		"ssh",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", defaultSSHConnectTimeoutSec),
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		argv = append(argv, "-o", "UserKnownHostsFile="+home+"/.ssh/known_hosts")
	}
	return argv
}

func appendProbeEnv(argv []string) []string {
	envVars := sshProbeEnvVars()
	if len(envVars) == 0 {
		return argv
	}
	argv = append(argv, "env")
	return append(argv, envVars...)
}

func appendOptionalStringFlag(argv []string, flag string, value string) []string {
	if value != "" {
		argv = append(argv, flag, value)
	}
	return argv
}

func appendOptionalInt64Flag(argv []string, flag string, value int64) []string {
	if value > 0 {
		argv = append(argv, flag, strconv.FormatInt(value, 10))
	}
	return argv
}

func appendWireGuardConfigFlags(argv []string, privateHex string, peerPublicHex string, localAddr string, peerAddr string, port int) []string {
	argv = appendOptionalStringFlag(argv, "--wg-private", privateHex)
	argv = appendOptionalStringFlag(argv, "--wg-peer-public", peerPublicHex)
	argv = appendOptionalStringFlag(argv, "--wg-local-addr", localAddr)
	argv = appendOptionalStringFlag(argv, "--wg-peer-addr", peerAddr)
	if port > 0 {
		argv = append(argv, "--wg-port", strconv.Itoa(port))
	}
	return argv
}

func appendParallelFlag(argv []string, mode string, parallel int) []string {
	if parallel > 1 && modeSupportsParallelFlag(mode) {
		return append(argv, "--parallel", strconv.Itoa(parallel))
	}
	return argv
}

func modeSupportsParallelFlag(mode string) bool {
	return mode == "raw" || mode == "blast" || mode == "wg" || mode == "wgos"
}

func (r SSHRunner) ClientCommand(cfg ClientConfig) []string {
	mode := defaultProbeMode(cfg.Mode)
	argv := r.probeCommandPrefix()
	argv = append(argv,
		r.binaryPath(),
		"client",
		"--mode", mode,
		"--transport", defaultProbeTransport(cfg.Transport),
	)
	argv = appendOptionalInt64Flag(argv, "--size-bytes", cfg.SizeBytes)
	argv = appendOptionalStringFlag(argv, "--host", cfg.Host)
	argv = appendOptionalStringFlag(argv, "--peer-candidates", cfg.PeerCandidatesCSV)
	argv = appendWireGuardConfigFlags(argv, cfg.WGPrivateKeyHex, cfg.WGPeerPublicHex, cfg.WGLocalAddr, cfg.WGPeerAddr, cfg.WGPort)
	argv = appendParallelFlag(argv, mode, cfg.Parallel)
	return appendBlastClientRateFlag(argv, mode)
}

func appendBlastClientRateFlag(argv []string, mode string) []string {
	if mode != "blast" {
		return argv
	}
	rate := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_RATE_MBPS"))
	if rate == "" {
		return argv
	}
	return append(argv, "--rate-mbps", rate)
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

	cfg, err := normalizeOrchestrateConfig(cfg)
	if err != nil {
		return RunReport{}, err
	}
	if cfg.Parallel > 1 && cfg.Mode == "blast" {
		return runParallelBlastOrchestrate(ctx, cfg)
	}
	return runSingleOrchestrate(ctx, cfg)
}

func normalizeOrchestrateConfig(cfg OrchestrateConfig) (OrchestrateConfig, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" {
		return OrchestrateConfig{}, errors.New("host is required")
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
		return OrchestrateConfig{}, errors.New("size bytes must be non-negative")
	}
	if err := validateOrchestrateMode(cfg.Mode); err != nil {
		return OrchestrateConfig{}, err
	}
	if err := validateOrchestrateDirection(cfg.Direction); err != nil {
		return OrchestrateConfig{}, err
	}
	return cfg, nil
}

func validateOrchestrateMode(mode string) error {
	switch mode {
	case "raw", "blast", "wg", "wgos", "wgiperf":
		return nil
	case "aead":
		return errors.New("aead not implemented yet")
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
}

func validateOrchestrateDirection(direction string) error {
	if direction != "forward" && direction != "reverse" {
		return fmt.Errorf("unsupported direction %q", direction)
	}
	return nil
}

func runSingleOrchestrate(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	localConn, err := listenPacket("udp", ":0")
	if err != nil {
		return RunReport{}, err
	}
	defer func() { _ = localConn.Close() }()

	localCandidates, err := orchestrateDiscoverCandidates(runCtx, localConn)
	if err != nil {
		return RunReport{}, err
	}
	localCandidates = preferredCandidates(localCandidates, 8)
	runner := cfg.sshRunner()
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

	runner := cfg.sshRunner()
	if cfg.Direction == "reverse" {
		return runReverseParallelBlastOrchestrate(runCtx, cfg, runner)
	}
	return runForwardParallelBlastOrchestrate(runCtx, cfg, runner)
}

func (cfg OrchestrateConfig) sshRunner() SSHRunner {
	return SSHRunner{
		User:       cfg.User,
		Host:       cfg.Host,
		RemotePath: cfg.RemotePath,
	}
}

type parallelBlastLocal struct {
	conns      []net.PacketConn
	candidates []net.Addr
}

func prepareParallelBlastLocal(runCtx context.Context, cfg OrchestrateConfig, direction string) (parallelBlastLocal, error) {
	conns, err := listenParallelPacketConns(runCtx, cfg.Parallel)
	if err != nil {
		return parallelBlastLocal{}, err
	}
	candidates, err := discoverCandidatesForPacketConns(runCtx, conns)
	if err != nil {
		closePacketConns(conns)
		return parallelBlastLocal{}, err
	}
	candidates = limitCandidatesInOrder(candidates, parallelCandidateLimit(cfg.Parallel))
	probeTracef("%s local candidates: %s", direction, strings.Join(CandidateStringsInOrder(candidates), ","))
	return parallelBlastLocal{conns: conns, candidates: candidates}, nil
}

func startParallelPunch(runCtx context.Context, conns []net.PacketConn, candidates []net.Addr) context.CancelFunc {
	punchCtx, punchCancel := context.WithCancel(runCtx)
	for _, conn := range conns {
		go PunchAddrs(punchCtx, conn, candidates, []byte(defaultPunchPayload), defaultPunchInterval)
	}
	return punchCancel
}

func forwardParallelRemoteAddrs(ready remoteReady, parallel int, localConns []net.PacketConn) ([]net.Addr, []string, []net.PacketConn, error) {
	remoteCandidates := limitCandidatesInOrder(ParseCandidateStrings(ready.Candidates), parallelCandidateLimit(parallel))
	remoteAddrs := parallelCandidateStringsInOrder(remoteCandidates, len(localConns))
	probeTracef("forward remote candidates: %s", strings.Join(CandidateStringsInOrder(remoteCandidates), ","))
	probeTracef("forward initial remote addrs: %s", strings.Join(remoteAddrs, ","))
	if len(remoteAddrs) == 0 && ready.Addr != "" {
		remoteAddrs = []string{ready.Addr}
	}
	if len(remoteAddrs) == 0 {
		return nil, nil, nil, errors.New("remote server did not report usable parallel blast candidates")
	}
	if len(localConns) > len(remoteAddrs) {
		localConns = localConns[:len(remoteAddrs)]
	}
	return remoteCandidates, remoteAddrs, localConns, nil
}

func selectForwardParallelRemoteAddrs(runCtx context.Context, localConns []net.PacketConn, remoteAddrs []string) []string {
	observedByConn := ObservePunchAddrsByConn(runCtx, localConns, 1200*time.Millisecond)
	if len(observedByConn) == 0 {
		return remoteAddrs
	}
	probeTracef("forward observed punch addrs by conn: %s", formatObservedAddrsByConn(observedByConn))
	return selectRemoteAddrsByConn(observedByConn, remoteAddrs, len(localConns))
}

func runForwardParallelBlastOrchestrate(runCtx context.Context, cfg OrchestrateConfig, runner SSHRunner) (RunReport, error) {
	local, err := prepareParallelBlastLocal(runCtx, cfg, "forward")
	if err != nil {
		return RunReport{}, err
	}
	localConns := local.conns
	defer closePacketConns(localConns)

	serverCfg := ServerConfig{
		ListenAddr:        cfg.ListenAddr,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		PeerCandidatesCSV: strings.Join(CandidateStringsInOrder(local.candidates), ","),
		SizeBytes:         cfg.SizeBytes,
		Parallel:          cfg.Parallel,
	}
	handle, err := launchRemoteServer(runCtx, runner, serverCfg)
	if err != nil {
		return RunReport{}, err
	}
	remote := newRemoteProcessSession(handle, true)
	defer remote.cleanup()

	ready, err := remote.ready(runCtx)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates, remoteAddrs, localConns, err := forwardParallelRemoteAddrs(ready, cfg.Parallel, localConns)
	if err != nil {
		return RunReport{}, err
	}

	punchCancel := startParallelPunch(runCtx, localConns, remoteCandidates)
	defer punchCancel()
	remoteAddrs = selectForwardParallelRemoteAddrs(runCtx, localConns, remoteAddrs)
	probeTracef("forward selected remote addrs: %s", strings.Join(remoteAddrs, ","))

	sendStats, err := sendParallelBlastShares(runCtx, localConns, remoteAddrs, cfg)
	punchCancel()
	if err != nil {
		return RunReport{}, err
	}

	done, err := remote.done(runCtx)
	if err != nil {
		return RunReport{}, err
	}
	if err := remote.finish("remote server failed"); err != nil {
		return RunReport{}, err
	}

	return forwardParallelBlastReport(cfg, ready, done, sendStats)
}

func runReverseParallelBlastOrchestrate(runCtx context.Context, cfg OrchestrateConfig, runner SSHRunner) (RunReport, error) {
	local, err := prepareParallelBlastLocal(runCtx, cfg, "reverse")
	if err != nil {
		return RunReport{}, err
	}
	localConns := local.conns
	defer closePacketConns(localConns)

	clientCfg := ClientConfig{
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		SizeBytes:         cfg.SizeBytes,
		PeerCandidatesCSV: strings.Join(CandidateStringsInOrder(local.candidates), ","),
		Parallel:          cfg.Parallel,
	}
	handle, err := launchRemoteClient(runCtx, runner, clientCfg)
	if err != nil {
		return RunReport{}, err
	}
	remote := newRemoteProcessSession(handle, true)
	defer remote.cleanup()

	ready, err := remote.ready(runCtx)
	if err != nil {
		return RunReport{}, err
	}
	remoteCandidates := limitCandidatesInOrder(ParseCandidateStrings(ready.Candidates), parallelCandidateLimit(cfg.Parallel))
	probeTracef("reverse remote candidates: %s", strings.Join(CandidateStringsInOrder(remoteCandidates), ","))

	punchCancel := startParallelPunch(runCtx, localConns, remoteCandidates)
	defer punchCancel()

	recvCtx, recvCancel := context.WithCancel(runCtx)
	defer recvCancel()
	recvCh := make(chan orchestrateReceiveResult, 1)
	doneCh := make(chan orchestrateDoneResult, 1)
	go func() {
		stats, err := orchestrateReceiveBlastParallel(recvCtx, localConns, io.Discard, ReceiveConfig{
			Blast:           true,
			Transport:       cfg.Transport,
			RequireComplete: probeRequireComplete(),
		}, cfg.SizeBytes)
		recvCh <- orchestrateReceiveResult{stats: stats, err: err}
	}()
	go func() {
		done, err := remote.done(runCtx)
		doneCh <- orchestrateDoneResult{done: done, err: err}
	}()

	recvStats, done, err := waitForReceiveAndDone(runCtx, recvCancel, punchCancel, recvCh, doneCh)
	if err != nil {
		return RunReport{}, err
	}
	punchCancel()
	if err := remote.finish("remote client failed"); err != nil {
		return RunReport{}, err
	}

	return reverseParallelBlastReport(cfg, ready, done, recvStats)
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
	results := gatherCandidatesForPacketConns(ctx, conns)
	byConn, firstErr := orderedCandidateResults(conns, results)
	out := uniquePreferredByConn(byConn)
	out = appendRemainingCandidates(out, byConn)
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

type packetConnCandidateResult struct {
	index int
	addrs []net.Addr
	err   error
}

func gatherCandidatesForPacketConns(ctx context.Context, conns []net.PacketConn) []packetConnCandidateResult {
	results := make(chan packetConnCandidateResult, len(conns))
	var wg sync.WaitGroup
	for i, conn := range conns {
		if conn == nil {
			continue
		}
		wg.Add(1)
		go func(i int, conn net.PacketConn) {
			defer wg.Done()
			addrs, err := orchestrateDiscoverCandidates(ctx, conn)
			results <- packetConnCandidateResult{index: i, addrs: addrs, err: err}
		}(i, conn)
	}
	wg.Wait()
	close(results)

	out := make([]packetConnCandidateResult, 0, len(results))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func orderedCandidateResults(conns []net.PacketConn, results []packetConnCandidateResult) ([][]net.Addr, error) {
	byConn := make([][]net.Addr, len(conns))
	var firstErr error
	for _, result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		if result.index >= 0 && result.index < len(byConn) {
			byConn[result.index] = result.addrs
		}
	}
	return byConn, firstErr
}

func uniquePreferredByConn(byConn [][]net.Addr) []net.Addr {
	seen := make(map[string]net.Addr)
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
	return out
}

func appendRemainingCandidates(out []net.Addr, byConn [][]net.Addr) []net.Addr {
	seen := make(map[string]net.Addr, len(out))
	for _, addr := range out {
		seen[addr.String()] = addr
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
	return out
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
	selector := newCandidateStringSelector(parallel)
	for _, addr := range candidates {
		if selector.addUniquePort(addr) {
			return selector.out
		}
	}
	for _, candidate := range CandidateStringsInOrder(candidates) {
		if selector.addCandidate(candidate) {
			return selector.out
		}
	}
	return selector.out
}

type candidateStringSelector struct {
	limit    int
	out      []string
	seen     map[string]bool
	seenPort map[int]bool
}

func newCandidateStringSelector(limit int) *candidateStringSelector {
	return &candidateStringSelector{
		limit:    limit,
		out:      make([]string, 0, limit),
		seen:     make(map[string]bool),
		seenPort: make(map[int]bool),
	}
}

func (s *candidateStringSelector) addUniquePort(addr net.Addr) bool {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || s.seenPort[udpAddr.Port] {
		return false
	}
	candidate := addr.String()
	if candidate == "" || s.seen[candidate] {
		return false
	}
	if s.addCandidate(candidate) {
		return true
	}
	s.seenPort[udpAddr.Port] = true
	return false
}

func (s *candidateStringSelector) addCandidate(candidate string) bool {
	if candidate == "" || s.seen[candidate] {
		return false
	}
	s.out = append(s.out, candidate)
	s.seen[candidate] = true
	return len(s.out) == s.limit
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
	selector := newRemoteAddrSelector(parallel)
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		selector.fillFromObserved(i, observedByConn[i])
	}
	for i := range selector.out {
		if selector.out[i] != "" {
			continue
		}
		selector.fillFromFallback(i, fallback)
	}

	return selector.out
}

type remoteAddrSelector struct {
	out          []string
	seen         map[string]bool
	seenEndpoint map[string]bool
}

func newRemoteAddrSelector(parallel int) *remoteAddrSelector {
	return &remoteAddrSelector{
		out:          make([]string, parallel),
		seen:         make(map[string]bool),
		seenEndpoint: make(map[string]bool),
	}
}

func (s *remoteAddrSelector) fillFromObserved(index int, observed []net.Addr) {
	for _, candidate := range parallelCandidateStrings(observed, len(observed)) {
		if s.set(index, candidate) {
			return
		}
	}
}

func (s *remoteAddrSelector) fillFromFallback(index int, fallback []string) {
	for _, candidate := range fallback {
		if s.set(index, candidate) {
			return
		}
	}
}

func (s *remoteAddrSelector) set(index int, candidate string) bool {
	endpoint := remoteCandidateEndpointKey(candidate)
	if candidate == "" || s.seen[candidate] || s.seenEndpoint[endpoint] {
		return false
	}
	s.out[index] = candidate
	s.seen[candidate] = true
	s.seenEndpoint[endpoint] = true
	return true
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

func wireGuardProbeMode(mode string) bool {
	return mode == "wg" || mode == "wgos"
}

func wireGuardPlanForMode(mode string) (wireGuardPlan, error) {
	if !wireGuardProbeMode(mode) {
		return wireGuardPlan{}, nil
	}
	return newWireGuardPlan()
}

func applyServerWireGuardPlan(serverCfg *ServerConfig, wgPlan wireGuardPlan) {
	serverCfg.WGPrivateKeyHex = wgPlan.listenerPrivHex
	serverCfg.WGPeerPublicHex = wgPlan.senderPubHex
	serverCfg.WGLocalAddr = wgPlan.listenerAddr.String()
	serverCfg.WGPeerAddr = wgPlan.senderAddr.String()
	serverCfg.WGPort = wgPlan.port
}

func applyClientWireGuardPlan(clientCfg *ClientConfig, wgPlan wireGuardPlan) {
	clientCfg.WGPrivateKeyHex = wgPlan.senderPrivHex
	clientCfg.WGPeerPublicHex = wgPlan.listenerPubHex
	clientCfg.WGLocalAddr = wgPlan.senderAddr.String()
	clientCfg.WGPeerAddr = wgPlan.listenerAddr.String()
	clientCfg.WGPort = wgPlan.port
}

type remoteEndpoint struct {
	addr       string
	candidates []net.Addr
}

type orchestrateReceiveResult struct {
	stats TransferStats
	err   error
}

type orchestrateDoneResult struct {
	done remoteDone
	err  error
}

func waitForReceiveAndDone(runCtx context.Context, recvCancel context.CancelFunc, punchCancel context.CancelFunc, recvCh <-chan orchestrateReceiveResult, doneCh <-chan orchestrateDoneResult) (TransferStats, remoteDone, error) {
	var recvStats TransferStats
	var done remoteDone
	var gotRecv, gotDone bool
	for !gotRecv || !gotDone {
		select {
		case result := <-recvCh:
			if result.err != nil {
				punchCancel()
				return TransferStats{}, remoteDone{}, result.err
			}
			recvStats = result.stats
			gotRecv = true
		case result := <-doneCh:
			if result.err != nil {
				recvCancel()
				punchCancel()
				return TransferStats{}, remoteDone{}, result.err
			}
			done = result.done
			gotDone = true
		case <-runCtx.Done():
			recvCancel()
			punchCancel()
			return TransferStats{}, remoteDone{}, runCtx.Err()
		}
	}
	return recvStats, done, nil
}

func preferredRemoteEndpoint(ready remoteReady) (remoteEndpoint, error) {
	candidates := preferredCandidates(ParseCandidateStrings(ready.Candidates), 8)
	addr := firstCandidateString(candidates)
	if addr == "" && ready.Addr != "" {
		addr, candidates = fallbackRemoteEndpoint(ready.Addr)
	}
	if addr == "" {
		return remoteEndpoint{}, errors.New("remote server did not report a usable address")
	}
	if len(candidates) == 0 {
		candidates = remoteCandidatesFromAddr(addr)
	}
	return remoteEndpoint{addr: addr, candidates: candidates}, nil
}

func firstCandidateString(candidates []net.Addr) string {
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0].String()
}

func fallbackRemoteEndpoint(rawAddr string) (string, []net.Addr) {
	addr, err := net.ResolveUDPAddr("udp", rawAddr)
	if err != nil {
		return "", nil
	}
	candidates := preferredCandidates([]net.Addr{addr}, 1)
	return firstCandidateString(candidates), candidates
}

func remoteCandidatesFromAddr(rawAddr string) []net.Addr {
	addr, err := net.ResolveUDPAddr("udp", rawAddr)
	if err != nil {
		return nil
	}
	return []net.Addr{addr}
}

func runForwardSend(runCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, src io.Reader, wgPlan wireGuardPlan, endpoint remoteEndpoint) (TransferStats, error) {
	switch cfg.Mode {
	case "wg":
		return orchestrateSendWireGuard(runCtx, localConn, src, forwardWireGuardConfig(cfg, wgPlan, endpoint))
	case "wgos":
		return orchestrateSendWireGuardOS(runCtx, localConn, src, forwardWireGuardConfig(cfg, wgPlan, endpoint))
	default:
		return orchestrateSend(runCtx, localConn, endpoint.addr, src, SendConfig{
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
}

func forwardWireGuardConfig(cfg OrchestrateConfig, wgPlan wireGuardPlan, endpoint remoteEndpoint) WireGuardConfig {
	return WireGuardConfig{
		Transport:      cfg.Transport,
		PrivateKeyHex:  wgPlan.senderPrivHex,
		PeerPublicHex:  wgPlan.listenerPubHex,
		LocalAddr:      wgPlan.senderAddr.String(),
		PeerAddr:       wgPlan.listenerAddr.String(),
		DirectEndpoint: endpoint.addr,
		PeerCandidates: endpoint.candidates,
		Port:           uint16(wgPlan.port),
		Streams:        cfg.Parallel,
		SizeBytes:      cfg.SizeBytes,
	}
}

func forwardOrchestrateReport(cfg OrchestrateConfig, ready remoteReady, done remoteDone, sendStats TransferStats) (RunReport, error) {
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
	firstByte := firstByteMetricsPreferDone(sendStats.StartedAt, sendStats.FirstByteAt, done.FirstByteMS, done.FirstByteMeasured)
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		PeakGoodputMbps:   sendStats.PeakGoodputMbps,
		Direct:            true,
		FirstByteMS:       firstByte.ms,
		FirstByteMeasured: firstByte.measured,
		LossRate:          retransmitRatio(sendStats.Retransmits, sendStats.PacketsSent),
		Retransmits:       sendStats.Retransmits,
		Success:           boolPtr(true),
		Local:             sendStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func forwardParallelBlastReport(cfg OrchestrateConfig, ready remoteReady, done remoteDone, sendStats TransferStats) (RunReport, error) {
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
	firstByte := firstByteMetricsPreferDone(sendStats.StartedAt, sendStats.FirstByteAt, done.FirstByteMS, done.FirstByteMeasured)
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		PeakGoodputMbps:   sendStats.PeakGoodputMbps,
		Direct:            true,
		FirstByteMS:       firstByte.ms,
		FirstByteMeasured: firstByte.measured,
		LossRate:          retransmitRatio(sendStats.Retransmits, sendStats.PacketsSent),
		Retransmits:       sendStats.Retransmits,
		Success:           boolPtr(true),
		Local:             sendStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func reverseOrchestrateReport(cfg OrchestrateConfig, ready remoteReady, done remoteDone, recvStats TransferStats) (RunReport, error) {
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
	firstByte := firstByteMetrics(recvStats.StartedAt, recvStats.FirstByteAt, done.FirstByteMS, done.FirstByteMeasured)
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		PeakGoodputMbps:   recvStats.PeakGoodputMbps,
		Direct:            true,
		FirstByteMS:       firstByte.ms,
		FirstByteMeasured: firstByte.measured,
		LossRate:          retransmitRatio(done.Retransmits, done.PacketsSent),
		Retransmits:       done.Retransmits,
		Success:           boolPtr(true),
		Local:             recvStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func reverseParallelBlastReport(cfg OrchestrateConfig, ready remoteReady, done remoteDone, recvStats TransferStats) (RunReport, error) {
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
	firstByte := firstByteMetricsPreferDone(recvStats.StartedAt, recvStats.FirstByteAt, done.FirstByteMS, done.FirstByteMeasured)
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		PeakGoodputMbps:   recvStats.PeakGoodputMbps,
		Direct:            true,
		FirstByteMS:       firstByte.ms,
		FirstByteMeasured: firstByte.measured,
		LossRate:          retransmitRatio(done.Retransmits, done.PacketsSent),
		Retransmits:       done.Retransmits,
		Success:           boolPtr(true),
		Local:             recvStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func wireGuardOSIperfReport(cfg OrchestrateConfig, ready remoteReady, done remoteDone, sendStats TransferStats) (RunReport, error) {
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
	firstByte := firstByteMetrics(sendStats.StartedAt, sendStats.FirstByteAt, done.FirstByteMS, done.FirstByteMeasured)
	return RunReport{
		Host:              cfg.Host,
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		Direction:         cfg.Direction,
		SizeBytes:         cfg.SizeBytes,
		BytesReceived:     bytesReceived,
		DurationMS:        durationMS,
		GoodputMbps:       goodputMbps(bytesReceived, durationMS),
		PeakGoodputMbps:   sendStats.PeakGoodputMbps,
		Direct:            true,
		FirstByteMS:       firstByte.ms,
		FirstByteMeasured: firstByte.measured,
		Success:           boolPtr(true),
		Local:             sendStats.Transport,
		Remote:            ready.Transport,
	}, nil
}

func runForwardOrchestrate(runCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, localCandidates []net.Addr, runner SSHRunner) (RunReport, error) {
	wgPlan, err := wireGuardPlanForMode(cfg.Mode)
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
	}
	if wireGuardProbeMode(cfg.Mode) {
		applyServerWireGuardPlan(&serverCfg, wgPlan)
	}
	handle, err := launchRemoteServer(runCtx, runner, serverCfg)
	if err != nil {
		return RunReport{}, err
	}
	remote := newRemoteProcessSession(handle, false)
	defer remote.cleanup()

	ready, err := remote.ready(runCtx)
	if err != nil {
		return RunReport{}, err
	}
	endpoint, err := preferredRemoteEndpoint(ready)
	if err != nil {
		return RunReport{}, err
	}

	punchCtx, punchCancel := context.WithCancel(runCtx)
	defer punchCancel()
	go PunchAddrs(punchCtx, localConn, endpoint.candidates, []byte(defaultPunchPayload), defaultPunchInterval)

	src := newSizedReader(cfg.SizeBytes)
	sendStats, err := runForwardSend(runCtx, cfg, localConn, src, wgPlan, endpoint)
	punchCancel()
	if err != nil {
		return RunReport{}, err
	}

	done, err := remote.done(runCtx)
	if err != nil {
		return RunReport{}, err
	}

	if err := remote.finish("remote server failed"); err != nil {
		return RunReport{}, err
	}

	return forwardOrchestrateReport(cfg, ready, done, sendStats)
}

type firstByteMetricsResult struct {
	ms       int64
	measured *bool
}

func firstByteMetricsPreferDone(primaryStart, primaryFirstByteAt time.Time, doneFirstByteMS int64, doneMeasured *bool) firstByteMetricsResult {
	if doneMeasured != nil {
		if *doneMeasured {
			return firstByteMetricsResult{
				ms:       doneFirstByteMS,
				measured: boolPtr(true),
			}
		}
		return firstByteMetricsResult{measured: boolPtr(false)}
	} else if doneFirstByteMS > 0 {
		return firstByteMetricsResult{
			ms:       doneFirstByteMS,
			measured: boolPtr(true),
		}
	}
	if !primaryFirstByteAt.IsZero() {
		return firstByteMetricsResult{
			ms:       elapsedMS(primaryStart, primaryFirstByteAt),
			measured: boolPtr(true),
		}
	}
	return firstByteMetricsResult{}
}

func firstByteMetrics(primaryStart, primaryFirstByteAt time.Time, fallbackFirstByteMS int64, fallbackMeasured *bool) firstByteMetricsResult {
	if !primaryFirstByteAt.IsZero() {
		return firstByteMetricsResult{
			ms:       elapsedMS(primaryStart, primaryFirstByteAt),
			measured: boolPtr(true),
		}
	}
	if fallbackMeasured != nil {
		if *fallbackMeasured {
			return firstByteMetricsResult{
				ms:       fallbackFirstByteMS,
				measured: boolPtr(true),
			}
		}
		return firstByteMetricsResult{ms: 0, measured: boolPtr(false)}
	}
	if fallbackFirstByteMS > 0 {
		return firstByteMetricsResult{
			ms:       fallbackFirstByteMS,
			measured: boolPtr(true),
		}
	}
	return firstByteMetricsResult{}
}

func runReverseReceive(recvCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, wgPlan wireGuardPlan, remoteCandidates []net.Addr) (TransferStats, error) {
	switch cfg.Mode {
	case "wg":
		return ReceiveWireGuardToWriter(recvCtx, localConn, io.Discard, reverseWireGuardConfig(cfg, wgPlan, remoteCandidates))
	case "wgos":
		return ReceiveWireGuardOSToWriter(recvCtx, localConn, io.Discard, reverseWireGuardConfig(cfg, wgPlan, remoteCandidates))
	case "blast":
		return orchestrateReceiveBlastParallel(recvCtx, []net.PacketConn{localConn}, io.Discard, ReceiveConfig{
			Blast:           true,
			Transport:       cfg.Transport,
			RequireComplete: probeRequireComplete(),
		}, cfg.SizeBytes)
	default:
		return orchestrateReceive(recvCtx, localConn, "", io.Discard, ReceiveConfig{
			Raw:       cfg.Mode == "raw",
			Transport: cfg.Transport,
		})
	}
}

func reverseWireGuardConfig(cfg OrchestrateConfig, wgPlan wireGuardPlan, remoteCandidates []net.Addr) WireGuardConfig {
	return WireGuardConfig{
		Transport:      cfg.Transport,
		PrivateKeyHex:  wgPlan.listenerPrivHex,
		PeerPublicHex:  wgPlan.senderPubHex,
		LocalAddr:      wgPlan.listenerAddr.String(),
		PeerAddr:       wgPlan.senderAddr.String(),
		PeerCandidates: remoteCandidates,
		Port:           uint16(wgPlan.port),
		Streams:        cfg.Parallel,
		SizeBytes:      cfg.SizeBytes,
	}
}

func runReverseOrchestrate(runCtx context.Context, cfg OrchestrateConfig, localConn net.PacketConn, localCandidates []net.Addr, runner SSHRunner) (RunReport, error) {
	wgPlan, err := wireGuardPlanForMode(cfg.Mode)
	if err != nil {
		return RunReport{}, err
	}
	clientCfg := ClientConfig{
		Mode:              cfg.Mode,
		Transport:         cfg.Transport,
		SizeBytes:         cfg.SizeBytes,
		PeerCandidatesCSV: strings.Join(CandidateStrings(localCandidates), ","),
		Parallel:          cfg.Parallel,
	}
	if wireGuardProbeMode(cfg.Mode) {
		applyClientWireGuardPlan(&clientCfg, wgPlan)
	}
	handle, err := launchRemoteClient(runCtx, runner, clientCfg)
	if err != nil {
		return RunReport{}, err
	}
	remote := newRemoteProcessSession(handle, false)
	defer remote.cleanup()

	ready, err := remote.ready(runCtx)
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
	recvCh := make(chan orchestrateReceiveResult, 1)
	doneCh := make(chan orchestrateDoneResult, 1)
	go func() {
		stats, err := runReverseReceive(recvCtx, cfg, localConn, wgPlan, remoteCandidates)
		recvCh <- orchestrateReceiveResult{stats: stats, err: err}
	}()
	go func() {
		done, err := remote.done(runCtx)
		doneCh <- orchestrateDoneResult{done: done, err: err}
	}()

	recvStats, done, err := waitForReceiveAndDone(runCtx, recvCancel, punchCancel, recvCh, doneCh)
	if err != nil {
		return RunReport{}, err
	}
	punchCancel()
	if err := remote.finish("remote client failed"); err != nil {
		return RunReport{}, err
	}

	return reverseOrchestrateReport(cfg, ready, done, recvStats)
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
	remote := newRemoteProcessSession(handle, false)
	defer remote.cleanup()

	ready, err := remote.ready(runCtx)
	if err != nil {
		return RunReport{}, err
	}
	endpoint, err := preferredRemoteEndpoint(ready)
	if err != nil {
		return RunReport{}, err
	}

	sendStats, err := orchestrateSendWireGuardOSIperf(runCtx, localConn, WireGuardConfig{
		Transport:      cfg.Transport,
		PrivateKeyHex:  wgPlan.senderPrivHex,
		PeerPublicHex:  wgPlan.listenerPubHex,
		LocalAddr:      wgPlan.senderAddr.String(),
		PeerAddr:       wgPlan.listenerAddr.String(),
		DirectEndpoint: endpoint.addr,
		PeerCandidates: endpoint.candidates,
		Port:           uint16(wgPlan.port),
		Streams:        cfg.Parallel,
		SizeBytes:      cfg.SizeBytes,
		Reverse:        cfg.Direction == "reverse",
	})
	if err != nil {
		return RunReport{}, err
	}
	done, err := remote.done(runCtx)
	if err != nil {
		return RunReport{}, err
	}
	if err := remote.finish("remote server failed"); err != nil {
		return RunReport{}, err
	}

	return wireGuardOSIperfReport(cfg, ready, done, sendStats)
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
	if raw := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_WINDOW")); raw != "" {
		return envPositiveInt("DERPHOLE_PROBE_WINDOW", defaultProbeWindowSize)
	}
	if raw := strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_WINDOW_SIZE")); raw != "" {
		return envPositiveInt("DERPHOLE_PROBE_WINDOW_SIZE", defaultProbeWindowSize)
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
	return envPositiveInt("DERPHOLE_PROBE_CHUNK_SIZE", defaultChunkSize)
}

func probeRateMbps() int {
	return envPositiveInt("DERPHOLE_PROBE_RATE_MBPS", 0)
}

func probeRequireComplete() bool {
	return envBool("DERPHOLE_PROBE_REQUIRE_COMPLETE")
}

func probeRepairPayloads() bool {
	return envBool("DERPHOLE_PROBE_REPAIR_PAYLOADS")
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
	if strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_TRACE")) == "" {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "probe-trace: "+format+"\n", args...)
}

func traceStderrWriter(buf *bytes.Buffer) io.Writer {
	if strings.TrimSpace(os.Getenv("DERPHOLE_PROBE_TRACE")) == "" {
		return buf
	}
	return io.MultiWriter(buf, os.Stderr)
}
