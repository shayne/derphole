package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/signal"
	"strings"
	"syscall"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

var runOrchestrateProbe = probe.RunOrchestrate

func runOrchestrate(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[orchestrateFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}

	flags := parsed.Flags
	flags.Host = strings.TrimSpace(flags.Host)
	if flags.Mode == "aead" {
		fmt.Fprintln(stderr, "aead not implemented yet")
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}
	if strings.TrimSpace(flags.Host) == "" {
		fmt.Fprintln(stderr, "host is required")
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}
	if flags.SizeBytes < 0 {
		fmt.Fprintln(stderr, "size bytes must be non-negative")
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}
	if flags.Mode != "raw" && flags.Mode != "blast" && flags.Mode != "wg" && flags.Mode != "wgos" && flags.Mode != "wgiperf" {
		fmt.Fprintln(stderr, "unsupported mode:", flags.Mode)
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}
	transport, err := probe.NormalizeTransportForCLI(flags.Transport)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}
	if flags.Direction != "" && flags.Direction != "forward" && flags.Direction != "reverse" {
		fmt.Fprintln(stderr, "unsupported direction:", flags.Direction)
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := runOrchestrateProbe(ctx, probe.OrchestrateConfig{
		Host:      flags.Host,
		User:      flags.User,
		Mode:      flags.Mode,
		Transport: transport,
		Direction: flags.Direction,
		SizeBytes: flags.SizeBytes,
		Parallel:  flags.Parallel,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

type orchestrateFlags struct {
	Host      string `flag:"host" help:"Remote host to benchmark"`
	User      string `flag:"user" help:"SSH user" default:"root"`
	Mode      string `flag:"mode" help:"Probe mode: raw, blast, wg, wgos, or wgiperf; AEAD lands in Task 5" default:"raw"`
	Transport string `flag:"transport" help:"UDP transport: legacy or batched" default:"legacy"`
	Direction string `flag:"direction" help:"Transfer direction" default:"forward"`
	SizeBytes int64  `flag:"size-bytes" help:"Payload size in bytes" default:"1048576"`
	Parallel  int    `flag:"parallel" help:"Parallel TCP streams for WireGuard tunnel modes" default:"1"`
}
