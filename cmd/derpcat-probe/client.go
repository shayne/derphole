package main

import (
	"context"
	"fmt"
	"io"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

var clientTimeout = 5 * time.Minute

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

	conn, err := listenPacket("udp", ":0")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer conn.Close()

	discoverCtx, cancelDiscover := context.WithTimeout(ctx, 750*time.Millisecond)
	candidates, discoverErr := discoverProbeCandidates(discoverCtx, conn)
	cancelDiscover()
	if discoverErr != nil && len(candidates) == 0 {
		fmt.Fprintln(stderr, discoverErr)
		return 1
	}
	ready := serverReady{
		Addr:       conn.LocalAddr().String(),
		Candidates: probe.CandidateStrings(candidates),
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
	go probe.PunchAddrs(punchCtx, conn, peerCandidates, nil, 25*time.Millisecond)

	src := sizedReader(parsed.Flags.SizeBytes)
	var stats probe.TransferStats
	if mode == "wg" {
		stats, err = probe.SendWireGuard(ctx, conn, &src, probe.WireGuardConfig{
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
		stats, err = probe.SendWireGuardOS(ctx, conn, &src, probe.WireGuardConfig{
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
	} else {
		stats, err = probe.Send(ctx, conn, remoteAddr, &src, probe.SendConfig{Raw: mode == "raw", Blast: mode == "blast", Transport: transport})
	}
	punchCancel()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	done := struct {
		BytesSent    int64 `json:"bytes_sent"`
		DurationMS   int64 `json:"duration_ms"`
		FirstByteMS  int64 `json:"first_byte_ms"`
		Retransmits  int64 `json:"retransmits"`
		PacketsSent  int64 `json:"packets_sent"`
		PacketsAcked int64 `json:"packets_acked"`
	}{
		BytesSent:    stats.BytesSent,
		DurationMS:   durationMS(stats.StartedAt, stats.CompletedAt),
		FirstByteMS:  durationMS(stats.StartedAt, stats.FirstByteAt),
		Retransmits:  stats.Retransmits,
		PacketsSent:  stats.PacketsSent,
		PacketsAcked: stats.PacketsAcked,
	}
	if err := writeMachineLine(stdout, "DONE", done); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

type clientFlags struct {
	Host           string `flag:"host" help:"Remote host to connect to"`
	Mode           string `flag:"mode" help:"Probe mode"`
	Transport      string `flag:"transport" help:"UDP transport: legacy or batched" default:"legacy"`
	SizeBytes      int64  `flag:"size-bytes" help:"Payload size in bytes" default:"1024"`
	PeerCandidates string `flag:"peer-candidates" help:"Comma-separated peer candidate addresses"`
	WGPrivateKey   string `flag:"wg-private" help:"WireGuard private key hex"`
	WGPeerPublic   string `flag:"wg-peer-public" help:"WireGuard peer public key hex"`
	WGLocalAddr    string `flag:"wg-local-addr" help:"WireGuard local IP"`
	WGPeerAddr     string `flag:"wg-peer-addr" help:"WireGuard peer IP"`
	WGPort         int    `flag:"wg-port" help:"WireGuard TCP port" default:"7000"`
	Parallel       int    `flag:"parallel" help:"Parallel TCP streams for WireGuard tunnel modes" default:"1"`
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
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	*r -= sizedReader(n)
	return n, nil
}
