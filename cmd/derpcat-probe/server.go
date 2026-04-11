package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
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
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[serverFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}

	mode := parsed.Flags.Mode
	if mode == "" {
		mode = "raw"
	}
	if mode == "aead" {
		fmt.Fprintln(stderr, "aead not implemented yet")
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}
	if mode != "raw" && mode != "blast" && mode != "wg" && mode != "wgos" && mode != "wgiperf" {
		fmt.Fprintln(stderr, "unsupported mode:", mode)
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}
	transport, err := probe.NormalizeTransportForCLI(parsed.Flags.Transport)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}

	var peerCandidateStrings []string
	if raw := strings.TrimSpace(parsed.Flags.PeerCandidates); raw != "" {
		for _, candidate := range strings.Split(raw, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			peerCandidateStrings = append(peerCandidateStrings, candidate)
		}
	}
	peerCandidates := probe.ParseCandidateStrings(peerCandidateStrings)

	listenAddr := parsed.Flags.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conns, err := openServerPacketConns(ctx, mode, listenAddr, parsed.Flags.Parallel)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer closePacketConns(conns)
	conn := conns[0]

	discoverCtx, cancelDiscover := context.WithTimeout(ctx, 750*time.Millisecond)
	candidates, discoverErr := discoverServerCandidates(discoverCtx, conns)
	cancelDiscover()
	if discoverErr != nil && len(candidates) == 0 {
		fmt.Fprintln(stderr, discoverErr)
		return 1
	}
	var stats probe.TransferStats
	if mode == "wgiperf" {
		server, err := probe.StartWireGuardOSIperfServer(ctx, conn, probe.WireGuardConfig{
			Transport:      transport,
			PrivateKeyHex:  parsed.Flags.WGPrivateKey,
			PeerPublicHex:  parsed.Flags.WGPeerPublic,
			LocalAddr:      parsed.Flags.WGLocalAddr,
			PeerAddr:       parsed.Flags.WGPeerAddr,
			PeerCandidates: peerCandidates,
			Port:           uint16(parsed.Flags.WGPort),
			Streams:        parsed.Flags.Parallel,
			SizeBytes:      parsed.Flags.SizeBytes,
		})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer server.Close()
		ready := serverReady{
			Addr:       conn.LocalAddr().String(),
			Candidates: probe.CandidateStringsInOrder(candidates),
			Transport:  probe.PreviewTransportCaps(conn, transport),
		}
		if len(ready.Candidates) == 0 && ready.Addr != "" {
			ready.Candidates = []string{ready.Addr}
		}
		if err := writeMachineLine(stdout, "READY", ready); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		waitStats, waitErr := server.Wait()
		if waitErr != nil {
			fmt.Fprintln(stderr, waitErr)
			return 1
		}
		stats = waitStats
	} else {
		ready := serverReady{
			Addr:       conn.LocalAddr().String(),
			Candidates: probe.CandidateStringsInOrder(candidates),
			Transport:  probe.PreviewTransportCaps(conn, transport),
		}
		if len(ready.Candidates) == 0 && ready.Addr != "" {
			ready.Candidates = []string{ready.Addr}
		}
		if err := writeMachineLine(stdout, "READY", ready); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		punchCtx, punchCancel := context.WithCancel(ctx)
		defer punchCancel()
		for _, punchConn := range conns {
			go probe.PunchAddrs(punchCtx, punchConn, peerCandidates, nil, 25*time.Millisecond)
		}

		if mode == "wg" {
			waitStats, waitErr := probe.ReceiveWireGuardToWriter(ctx, conn, io.Discard, probe.WireGuardConfig{
				Transport:      transport,
				PrivateKeyHex:  parsed.Flags.WGPrivateKey,
				PeerPublicHex:  parsed.Flags.WGPeerPublic,
				LocalAddr:      parsed.Flags.WGLocalAddr,
				PeerAddr:       parsed.Flags.WGPeerAddr,
				PeerCandidates: peerCandidates,
				Port:           uint16(parsed.Flags.WGPort),
				Streams:        parsed.Flags.Parallel,
				SizeBytes:      parsed.Flags.SizeBytes,
			})
			if waitErr != nil {
				fmt.Fprintln(stderr, waitErr)
				return 1
			}
			stats = waitStats
		} else if mode == "wgos" {
			waitStats, waitErr := probe.ReceiveWireGuardOSToWriter(ctx, conn, io.Discard, probe.WireGuardConfig{
				Transport:      transport,
				PrivateKeyHex:  parsed.Flags.WGPrivateKey,
				PeerPublicHex:  parsed.Flags.WGPeerPublic,
				LocalAddr:      parsed.Flags.WGLocalAddr,
				PeerAddr:       parsed.Flags.WGPeerAddr,
				PeerCandidates: peerCandidates,
				Port:           uint16(parsed.Flags.WGPort),
				Streams:        parsed.Flags.Parallel,
				SizeBytes:      parsed.Flags.SizeBytes,
			})
			if waitErr != nil {
				fmt.Fprintln(stderr, waitErr)
				return 1
			}
			stats = waitStats
		} else if mode == "blast" {
			if parsed.Flags.SizeBytes <= 0 {
				fmt.Fprintln(stderr, "size bytes is required for blast server mode")
				return 2
			}
			waitStats, waitErr := probe.ReceiveBlastParallelToWriter(ctx, conns, io.Discard, probe.ReceiveConfig{
				Blast:           true,
				Transport:       transport,
				RequireComplete: probeEnvBool("DERPCAT_PROBE_REQUIRE_COMPLETE"),
			}, parsed.Flags.SizeBytes)
			if waitErr != nil {
				fmt.Fprintln(stderr, waitErr)
				return 1
			}
			stats = waitStats
		} else {
			waitStats, waitErr := probe.ReceiveToWriter(ctx, conn, "", io.Discard, probe.ReceiveConfig{Raw: mode == "raw", Blast: mode == "blast", Transport: transport})
			if waitErr != nil {
				fmt.Fprintln(stderr, waitErr)
				return 1
			}
			stats = waitStats
		}
		punchCancel()
	}
	done := buildServerDone(stats)
	if err := writeMachineLine(stdout, "DONE", done); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
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
			addrs, err := discoverProbeCandidates(ctx, conn)
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
		for _, addr := range firstPreferredCandidate(addrs) {
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
	}
	for _, addrs := range byConn {
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
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
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
