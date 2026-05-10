// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/yargs"
)

var listenPacket = net.ListenPacket
var discoverProbeCandidates = probe.DiscoverCandidates

type serverReady struct {
	Addr       string              `json:"addr"`
	Candidates []string            `json:"candidates,omitempty"`
	Transport  probe.TransportCaps `json:"transport,omitempty"`
}

type serverDone struct {
	BytesReceived     int64 `json:"bytes_received"`
	DurationMS        int64 `json:"duration_ms"`
	FirstByteMS       int64 `json:"first_byte_ms"`
	FirstByteMeasured *bool `json:"first_byte_measured,omitempty"`
	Retransmits       int64 `json:"retransmits"`
	PacketsSent       int64 `json:"packets_sent"`
	PacketsAcked      int64 `json:"packets_acked"`
}

func boolPtr(v bool) *bool {
	return &v
}

func runServer(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 0
	}

	cfg, code, failed := parseServerRunConfig(args, stderr)
	if failed {
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conns, err := openServerPacketConns(ctx, cfg.mode, cfg.listenAddr, cfg.flags.Parallel)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer closePacketConns(conns)
	conn := conns[0]

	candidates, err := clientDiscoverCandidates(ctx, conns)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	stats, err := runServerTransfer(ctx, conn, conns, cfg, candidates, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	done := buildServerDone(stats)
	if err := writeMachineLine(stdout, "DONE", done); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

type serverRunConfig struct {
	flags          serverFlags
	mode           string
	transport      string
	listenAddr     string
	peerCandidates []net.Addr
}

func parseServerRunConfig(args []string, stderr io.Writer) (serverRunConfig, int, bool) {
	parsed, err := yargs.ParseKnownFlags[serverFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("server"))
		return serverRunConfig{}, 2, true
	}
	if len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("server"))
		return serverRunConfig{}, 2, true
	}

	mode := parsed.Flags.Mode
	if mode == "" {
		mode = "raw"
	}
	if code, failed := validateServerMode(mode, stderr); failed {
		return serverRunConfig{}, code, true
	}
	transport, err := probe.NormalizeTransportForCLI(parsed.Flags.Transport)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("server"))
		return serverRunConfig{}, 2, true
	}
	listenAddr := parsed.Flags.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	return serverRunConfig{
		flags:          parsed.Flags,
		mode:           mode,
		transport:      transport,
		listenAddr:     listenAddr,
		peerCandidates: probe.ParseCandidateStrings(splitCSVFlag(parsed.Flags.PeerCandidates)),
	}, 0, false
}

func validateServerMode(mode string, stderr io.Writer) (int, bool) {
	if mode == "aead" {
		_, _ = fmt.Fprintln(stderr, "aead not implemented yet")
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2, true
	}
	if mode != "raw" && mode != "blast" && mode != "wg" && mode != "wgos" && mode != "wgiperf" {
		_, _ = fmt.Fprintln(stderr, "unsupported mode:", mode)
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2, true
	}
	return 0, false
}

func runServerTransfer(ctx context.Context, conn net.PacketConn, conns []net.PacketConn, cfg serverRunConfig, candidates []net.Addr, stdout io.Writer) (probe.TransferStats, error) {
	if cfg.mode == "wgiperf" {
		return runWGIPerfServer(ctx, conn, cfg, candidates, stdout)
	}
	if err := writeMachineLine(stdout, "READY", clientReady(conn, candidates, cfg.transport)); err != nil {
		return probe.TransferStats{}, err
	}
	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	for _, punchConn := range conns {
		go probe.PunchAddrs(punchCtx, punchConn, cfg.peerCandidates, nil, 25*time.Millisecond)
	}
	stats, err := receiveServerTransfer(ctx, conn, conns, cfg)
	punchCancel()
	return stats, err
}

func runWGIPerfServer(ctx context.Context, conn net.PacketConn, cfg serverRunConfig, candidates []net.Addr, stdout io.Writer) (probe.TransferStats, error) {
	server, err := probe.StartWireGuardOSIperfServer(ctx, conn, serverWireGuardConfig(cfg))
	if err != nil {
		return probe.TransferStats{}, err
	}
	defer func() { _ = server.Close() }()
	if err := writeMachineLine(stdout, "READY", clientReady(conn, candidates, cfg.transport)); err != nil {
		return probe.TransferStats{}, err
	}
	return server.Wait()
}

func receiveServerTransfer(ctx context.Context, conn net.PacketConn, conns []net.PacketConn, cfg serverRunConfig) (probe.TransferStats, error) {
	switch cfg.mode {
	case "wg":
		return probe.ReceiveWireGuardToWriter(ctx, conn, io.Discard, serverWireGuardConfig(cfg))
	case "wgos":
		return probe.ReceiveWireGuardOSToWriter(ctx, conn, io.Discard, serverWireGuardConfig(cfg))
	case "blast":
		if cfg.flags.SizeBytes <= 0 {
			return probe.TransferStats{}, fmt.Errorf("size bytes is required for blast server mode")
		}
		return probe.ReceiveBlastParallelToWriter(ctx, conns, io.Discard, probe.ReceiveConfig{
			Blast:           true,
			Transport:       cfg.transport,
			RequireComplete: probeEnvBool("DERPHOLE_PROBE_REQUIRE_COMPLETE"),
		}, cfg.flags.SizeBytes)
	default:
		return probe.ReceiveToWriter(ctx, conn, "", io.Discard, probe.ReceiveConfig{Raw: cfg.mode == "raw", Blast: cfg.mode == "blast", Transport: cfg.transport})
	}
}

func serverWireGuardConfig(cfg serverRunConfig) probe.WireGuardConfig {
	return probe.WireGuardConfig{
		Transport:      cfg.transport,
		PrivateKeyHex:  cfg.flags.WGPrivateKey,
		PeerPublicHex:  cfg.flags.WGPeerPublic,
		LocalAddr:      cfg.flags.WGLocalAddr,
		PeerAddr:       cfg.flags.WGPeerAddr,
		PeerCandidates: cfg.peerCandidates,
		Port:           uint16(cfg.flags.WGPort),
		Streams:        cfg.flags.Parallel,
		SizeBytes:      cfg.flags.SizeBytes,
	}
}

func buildServerDone(stats probe.TransferStats) serverDone {
	done := serverDone{
		BytesReceived: stats.BytesReceived,
		DurationMS:    durationMS(stats.StartedAt, stats.CompletedAt),
		FirstByteMS:   durationMS(stats.StartedAt, stats.FirstByteAt),
		Retransmits:   stats.Retransmits,
		PacketsSent:   stats.PacketsSent,
		PacketsAcked:  stats.PacketsAcked,
	}
	if stats.FirstByteAt.IsZero() {
		done.FirstByteMeasured = boolPtr(false)
	} else {
		done.FirstByteMeasured = boolPtr(true)
	}
	return done
}

func openServerPacketConns(ctx context.Context, mode, listenAddr string, parallel int) ([]net.PacketConn, error) {
	if parallel <= 0 {
		parallel = 1
	}
	conns := make([]net.PacketConn, 0, parallel)
	first, err := listenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conns = append(conns, first)
	if mode != "blast" || parallel <= 1 {
		return conns, nil
	}
	extraListenAddr := parallelListenAddr(listenAddr)
	for len(conns) < parallel {
		if err := ctx.Err(); err != nil {
			closePacketConns(conns)
			return nil, err
		}
		extra, err := listenPacket("udp", extraListenAddr)
		if err != nil {
			closePacketConns(conns)
			return nil, err
		}
		conns = append(conns, extra)
	}
	return conns, nil
}

func parallelListenAddr(listenAddr string) string {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return ":0"
	}
	return net.JoinHostPort(host, "0")
}

func closePacketConns(conns []net.PacketConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func discoverServerCandidates(ctx context.Context, conns []net.PacketConn) ([]net.Addr, error) {
	results := runServerCandidateDiscovery(ctx, conns)
	byConn, firstErr := collectServerCandidateResults(conns, results)
	out := orderedServerCandidates(byConn)
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func runServerCandidateDiscovery(ctx context.Context, conns []net.PacketConn) <-chan resultServerCandidates {
	results := make(chan resultServerCandidates, len(conns))
	var wg sync.WaitGroup
	for i, conn := range conns {
		if conn == nil {
			continue
		}
		wg.Add(1)
		go func(i int, conn net.PacketConn) {
			defer wg.Done()
			addrs, err := discoverProbeCandidates(ctx, conn)
			results <- resultServerCandidates{index: i, addrs: addrs, err: err}
		}(i, conn)
	}
	wg.Wait()
	close(results)
	return results
}

type resultServerCandidates struct {
	index int
	addrs []net.Addr
	err   error
}

func collectServerCandidateResults(conns []net.PacketConn, results <-chan resultServerCandidates) ([][]net.Addr, error) {
	byConn := make([][]net.Addr, len(conns))
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		if result.index >= 0 && result.index < len(byConn) {
			byConn[result.index] = result.addrs
		}
	}
	return byConn, firstErr
}

func orderedServerCandidates(byConn [][]net.Addr) []net.Addr {
	out := make([]net.Addr, 0)
	seen := make(map[string]net.Addr)
	for _, addrs := range byConn {
		out = appendUniqueServerCandidates(out, seen, firstPreferredCandidate(addrs))
	}
	for _, addrs := range byConn {
		out = appendUniqueServerCandidates(out, seen, addrs)
	}
	return out
}

func appendUniqueServerCandidates(out []net.Addr, seen map[string]net.Addr, addrs []net.Addr) []net.Addr {
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		key := addr.String()
		if seen[key] != nil {
			continue
		}
		seen[key] = addr
		out = append(out, addr)
	}
	return out
}

func firstPreferredCandidate(addrs []net.Addr) []net.Addr {
	ordered := probe.CandidateStrings(addrs)
	if len(ordered) == 0 {
		return nil
	}
	for _, addr := range addrs {
		if addr != nil && addr.String() == ordered[0] {
			return []net.Addr{addr}
		}
	}
	return nil
}

func writeMachineLine(w io.Writer, prefix string, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s %s\n", prefix, payload)
	return err
}

func durationMS(start, end time.Time) int64 {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}

type serverFlags struct {
	ListenAddr     string `flag:"listen" help:"Listen address for the server"`
	Mode           string `flag:"mode" help:"Probe mode"`
	Transport      string `flag:"transport" help:"UDP transport: legacy or batched" default:"legacy"`
	PeerCandidates string `flag:"peer-candidates" help:"Comma-separated peer candidate addresses"`
	WGPrivateKey   string `flag:"wg-private" help:"WireGuard private key hex"`
	WGPeerPublic   string `flag:"wg-peer-public" help:"WireGuard peer public key hex"`
	WGLocalAddr    string `flag:"wg-local-addr" help:"WireGuard local IP"`
	WGPeerAddr     string `flag:"wg-peer-addr" help:"WireGuard peer IP"`
	WGPort         int    `flag:"wg-port" help:"WireGuard TCP port" default:"7000"`
	SizeBytes      int64  `flag:"size-bytes" help:"Expected payload size for parallel WireGuard tunnel modes"`
	Parallel       int    `flag:"parallel" help:"Parallel blast sockets or TCP streams for WireGuard tunnel modes" default:"1"`
}
