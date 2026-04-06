package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/signal"
	"strings"
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
	BytesReceived int64 `json:"bytes_received"`
	DurationMS    int64 `json:"duration_ms"`
	FirstByteMS   int64 `json:"first_byte_ms"`
	Retransmits   int64 `json:"retransmits"`
	PacketsSent   int64 `json:"packets_sent"`
	PacketsAcked  int64 `json:"packets_acked"`
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

	conn, err := listenPacket("udp", listenAddr)
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
		waitStats, waitErr := server.Wait()
		if waitErr != nil {
			fmt.Fprintln(stderr, waitErr)
			return 1
		}
		stats = waitStats
	} else {
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
	done := serverDone{
		BytesReceived: stats.BytesReceived,
		DurationMS:    durationMS(stats.StartedAt, stats.CompletedAt),
		FirstByteMS:   durationMS(stats.StartedAt, stats.FirstByteAt),
		Retransmits:   stats.Retransmits,
		PacketsSent:   stats.PacketsSent,
		PacketsAcked:  stats.PacketsAcked,
	}
	if err := writeMachineLine(stdout, "DONE", done); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
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
	Parallel       int    `flag:"parallel" help:"Parallel TCP streams for WireGuard tunnel modes" default:"1"`
}
