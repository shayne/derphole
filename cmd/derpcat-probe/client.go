package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

var clientTimeout = 5 * time.Minute
var probeSend = probe.Send
var probeSendWireGuard = probe.SendWireGuard
var probeSendWireGuardOS = probe.SendWireGuardOS

type clientDone struct {
	BytesSent         int64 `json:"bytes_sent,omitempty"`
	DurationMS        int64 `json:"duration_ms"`
	FirstByteMS       int64 `json:"first_byte_ms"`
	FirstByteMeasured *bool `json:"first_byte_measured,omitempty"`
	Retransmits       int64 `json:"retransmits"`
	PacketsSent       int64 `json:"packets_sent"`
	PacketsAcked      int64 `json:"packets_acked"`
}

func runClient(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[clientFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}

	mode := parsed.Flags.Mode
	if mode == "" {
		mode = "raw"
	}
	if mode == "aead" {
		fmt.Fprintln(stderr, "aead not implemented yet")
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	if mode != "raw" && mode != "blast" && mode != "wg" && mode != "wgos" {
		fmt.Fprintln(stderr, "unsupported mode:", mode)
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	transport, err := probe.NormalizeTransportForCLI(parsed.Flags.Transport)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	remoteAddr := strings.TrimSpace(parsed.Flags.Host)
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
	if remoteAddr == "" && len(peerCandidates) > 0 {
		remoteAddr = peerCandidates[0].String()
	}
	if remoteAddr == "" && mode != "wg" && mode != "wgos" {
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	if parsed.Flags.SizeBytes < 0 {
		fmt.Fprintln(stderr, "size bytes must be non-negative")
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()

	conns, err := openServerPacketConns(ctx, mode, ":0", parsed.Flags.Parallel)
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

	src := sizedReader(parsed.Flags.SizeBytes)
	var stats probe.TransferStats
	if mode == "wg" {
		stats, err = probeSendWireGuard(ctx, conn, &src, probe.WireGuardConfig{
			Transport:      transport,
			PrivateKeyHex:  parsed.Flags.WGPrivateKey,
			PeerPublicHex:  parsed.Flags.WGPeerPublic,
			LocalAddr:      parsed.Flags.WGLocalAddr,
			PeerAddr:       parsed.Flags.WGPeerAddr,
			DirectEndpoint: remoteAddr,
			PeerCandidates: peerCandidates,
			Port:           uint16(parsed.Flags.WGPort),
			Streams:        parsed.Flags.Parallel,
			SizeBytes:      parsed.Flags.SizeBytes,
		})
	} else if mode == "wgos" {
		stats, err = probeSendWireGuardOS(ctx, conn, &src, probe.WireGuardConfig{
			Transport:      transport,
			PrivateKeyHex:  parsed.Flags.WGPrivateKey,
			PeerPublicHex:  parsed.Flags.WGPeerPublic,
			LocalAddr:      parsed.Flags.WGLocalAddr,
			PeerAddr:       parsed.Flags.WGPeerAddr,
			DirectEndpoint: remoteAddr,
			PeerCandidates: peerCandidates,
			Port:           uint16(parsed.Flags.WGPort),
			Streams:        parsed.Flags.Parallel,
			SizeBytes:      parsed.Flags.SizeBytes,
		})
	} else if mode == "blast" && len(conns) > 1 {
		stats, err = sendBlastParallelClient(ctx, conns, remoteAddr, peerCandidates, parsed.Flags.SizeBytes, probe.SendConfig{
			Blast:          true,
			Transport:      transport,
			ChunkSize:      parsed.Flags.ChunkSize,
			WindowSize:     parsed.Flags.WindowSize,
			RateMbps:       parsed.Flags.RateMbps,
			RepairPayloads: probeEnvBool("DERPCAT_PROBE_REPAIR_PAYLOADS"),
		})
	} else {
		stats, err = probeSend(ctx, conn, remoteAddr, &src, probe.SendConfig{
			Raw:            mode == "raw",
			Blast:          mode == "blast",
			Transport:      transport,
			ChunkSize:      parsed.Flags.ChunkSize,
			WindowSize:     parsed.Flags.WindowSize,
			Parallel:       parsed.Flags.Parallel,
			RateMbps:       parsed.Flags.RateMbps,
			RepairPayloads: probeEnvBool("DERPCAT_PROBE_REPAIR_PAYLOADS"),
		})
	}
	punchCancel()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	done := buildClientDone(stats)
	if err := writeMachineLine(stdout, "DONE", done); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

func buildClientDone(stats probe.TransferStats) clientDone {
	done := clientDone{
		BytesSent:    stats.BytesSent,
		DurationMS:   durationMS(stats.StartedAt, stats.CompletedAt),
		FirstByteMS:  durationMS(stats.StartedAt, stats.FirstByteAt),
		Retransmits:  stats.Retransmits,
		PacketsSent:  stats.PacketsSent,
		PacketsAcked: stats.PacketsAcked,
	}
	if stats.FirstByteAt.IsZero() {
		done.FirstByteMeasured = boolPtr(false)
	} else {
		done.FirstByteMeasured = boolPtr(true)
	}
	return done
}

func sendBlastParallelClient(ctx context.Context, conns []net.PacketConn, remoteAddr string, peerCandidates []net.Addr, sizeBytes int64, cfg probe.SendConfig) (probe.TransferStats, error) {
	remotes := parallelRemoteAddrs(remoteAddr, peerCandidates, len(conns))
	if observedByConn := probe.ObservePunchAddrsByConn(ctx, conns, 1200*time.Millisecond); len(observedByConn) > 0 {
		probeTracef("client observed punch addrs by conn: %s", formatClientObservedAddrsByConn(observedByConn))
		remotes = selectClientRemoteAddrsByConn(observedByConn, remotes, len(conns))
	}
	probeTracef("client selected remote addrs: %s", strings.Join(remotes, ","))
	conns, remotes = parallelClientPairs(conns, remotes)
	if len(remotes) == 0 {
		return probe.TransferStats{}, fmt.Errorf("no remote candidates for parallel blast")
	}
	shares := splitClientShares(sizeBytes, len(conns))
	rateMbps := perClientShareRateMbps(cfg.RateMbps, len(conns))
	startedAt := time.Now()
	type result struct {
		stats probe.TransferStats
		err   error
	}
	results := make(chan result, len(conns))
	for i, conn := range conns {
		share := shares[i]
		remote := remotes[i]
		go func(conn net.PacketConn, remote string, share int64) {
			probeTracef("client sending share bytes=%d remote=%s local=%s", share, remote, conn.LocalAddr())
			sendCfg := cfg
			sendCfg.Blast = true
			sendCfg.Raw = false
			sendCfg.Parallel = 1
			sendCfg.RateMbps = rateMbps
			src := sizedReader(share)
			stats, err := probeSend(ctx, conn, remote, &src, sendCfg)
			results <- result{stats: stats, err: err}
		}(conn, remote, share)
	}

	out := probe.TransferStats{StartedAt: startedAt}
	for range conns {
		result := <-results
		if result.err != nil {
			return probe.TransferStats{}, result.err
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

func selectClientRemoteAddrsByConn(observedByConn [][]net.Addr, fallback []string, parallel int) []string {
	if parallel <= 0 {
		parallel = len(fallback)
	}
	out := make([]string, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		for _, candidate := range probe.CandidateStrings(observedByConn[i]) {
			endpoint := clientRemoteCandidateEndpointKey(candidate)
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
			endpoint := clientRemoteCandidateEndpointKey(candidate)
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

func clientRemoteCandidateEndpointKey(candidate string) string {
	addrPort, err := netip.ParseAddrPort(candidate)
	if err != nil {
		return candidate
	}
	return fmt.Sprintf("%d", addrPort.Port())
}

func formatClientObservedAddrsByConn(observedByConn [][]net.Addr) string {
	parts := make([]string, 0, len(observedByConn))
	for i, observed := range observedByConn {
		parts = append(parts, fmt.Sprintf("%d=%s", i, strings.Join(probe.CandidateStrings(observed), "|")))
	}
	return strings.Join(parts, ",")
}

func parallelClientPairs(conns []net.PacketConn, remotes []string) ([]net.PacketConn, []string) {
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

func parallelRemoteAddrs(remoteAddr string, peerCandidates []net.Addr, parallel int) []string {
	if parallel <= 0 {
		parallel = 1
	}
	out := make([]string, 0, parallel)
	seen := make(map[string]bool)
	for _, addr := range peerCandidates {
		if addr == nil {
			continue
		}
		candidate := addr.String()
		if seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) == parallel {
			return out
		}
	}
	if remoteAddr != "" && !seen[remoteAddr] {
		out = append(out, remoteAddr)
	}
	return out
}

func splitClientShares(total int64, parallel int) []int64 {
	if parallel <= 1 {
		return []int64{total}
	}
	if total < 0 {
		total = 0
	}
	base := total / int64(parallel)
	extra := total % int64(parallel)
	shares := make([]int64, parallel)
	for i := range shares {
		shares[i] = base
		if int64(i) < extra {
			shares[i]++
		}
	}
	return shares
}

func perClientShareRateMbps(totalRateMbps int, shares int) int {
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

func probeTracef(format string, args ...any) {
	if strings.TrimSpace(os.Getenv("DERPCAT_PROBE_TRACE")) == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "probe-trace: "+format+"\n", args...)
}

type clientFlags struct {
	Host           string `flag:"host" help:"Remote host to connect to"`
	Mode           string `flag:"mode" help:"Probe mode"`
	Transport      string `flag:"transport" help:"UDP transport: legacy or batched" default:"legacy"`
	SizeBytes      int64  `flag:"size-bytes" help:"Payload size in bytes" default:"1024"`
	ChunkSize      int    `flag:"chunk-size" help:"UDP payload size per packet for raw/blast modes"`
	WindowSize     int    `flag:"window-size" help:"Reliable raw-mode in-flight window"`
	RateMbps       int    `flag:"rate-mbps" help:"Paced blast send rate in Mbps; 0 sends as fast as possible"`
	PeerCandidates string `flag:"peer-candidates" help:"Comma-separated peer candidate addresses"`
	WGPrivateKey   string `flag:"wg-private" help:"WireGuard private key hex"`
	WGPeerPublic   string `flag:"wg-peer-public" help:"WireGuard peer public key hex"`
	WGLocalAddr    string `flag:"wg-local-addr" help:"WireGuard local IP"`
	WGPeerAddr     string `flag:"wg-peer-addr" help:"WireGuard peer IP"`
	WGPort         int    `flag:"wg-port" help:"WireGuard TCP port" default:"7000"`
	Parallel       int    `flag:"parallel" help:"Parallel raw stripes or WireGuard TCP streams" default:"1"`
}

type sizedReader int64

func (r *sizedReader) Read(p []byte) (int, error) {
	if r == nil || *r <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > int64(*r) {
		n = int(*r)
	}
	*r -= sizedReader(n)
	return n, nil
}
