// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/signal"
	"strings"
	"syscall"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/yargs"
)

var runOrchestrateProbe = probe.RunOrchestrate

func runOrchestrate(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 0
	}

	cfg, code, failed := parseOrchestrateConfig(args, stderr)
	if failed {
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := runOrchestrateProbe(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func parseOrchestrateConfig(args []string, stderr io.Writer) (probe.OrchestrateConfig, int, bool) {
	parsed, err := yargs.ParseKnownFlags[orchestrateFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		return probe.OrchestrateConfig{}, writeOrchestrateUsageError(stderr, err.Error()), true
	}
	if len(parsed.RemainingArgs) != 0 {
		return probe.OrchestrateConfig{}, writeOrchestrateUsage(stderr), true
	}

	flags := parsed.Flags
	flags.Host = strings.TrimSpace(flags.Host)
	if code, failed := validateOrchestrateFlags(flags, stderr); failed {
		return probe.OrchestrateConfig{}, code, true
	}
	transport, err := probe.NormalizeTransportForCLI(flags.Transport)
	if err != nil {
		return probe.OrchestrateConfig{}, writeOrchestrateUsageError(stderr, err.Error()), true
	}

	return probe.OrchestrateConfig{
		Host:      flags.Host,
		User:      flags.User,
		Mode:      flags.Mode,
		Transport: transport,
		Direction: flags.Direction,
		SizeBytes: flags.SizeBytes,
		Parallel:  flags.Parallel,
	}, 0, false
}

func validateOrchestrateFlags(flags orchestrateFlags, stderr io.Writer) (int, bool) {
	if flags.Mode == "aead" {
		return writeOrchestrateUsageError(stderr, "aead not implemented yet"), true
	}
	if flags.Host == "" {
		return writeOrchestrateUsageError(stderr, "host is required"), true
	}
	if flags.SizeBytes < 0 {
		return writeOrchestrateUsageError(stderr, "size bytes must be non-negative"), true
	}
	if !supportedOrchestrateMode(flags.Mode) {
		return writeOrchestrateUsageError(stderr, fmt.Sprintf("unsupported mode: %s", flags.Mode)), true
	}
	if flags.Direction != "" && flags.Direction != "forward" && flags.Direction != "reverse" {
		return writeOrchestrateUsageError(stderr, fmt.Sprintf("unsupported direction: %s", flags.Direction)), true
	}
	return 0, false
}

func supportedOrchestrateMode(mode string) bool {
	switch mode {
	case "raw", "blast", "wg", "wgos", "wgiperf":
		return true
	default:
		return false
	}
}

func writeOrchestrateUsage(stderr io.Writer) int {
	_, _ = fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
	return 2
}

func writeOrchestrateUsageError(stderr io.Writer, msg string) int {
	_, _ = fmt.Fprintln(stderr, msg)
	return writeOrchestrateUsage(stderr)
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
