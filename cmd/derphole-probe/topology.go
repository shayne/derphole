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
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/yargs"
)

var runTopologyProbe = probe.RunTopologyDiagnostics

func runTopology(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 0
	}

	cfg, code, failed := parseTopologyConfig(args, stderr)
	if failed {
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := runTopologyProbe(ctx, cfg)
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

func parseTopologyConfig(args []string, stderr io.Writer) (probe.TopologyConfig, int, bool) {
	parsed, err := yargs.ParseKnownFlags[topologyFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return probe.TopologyConfig{}, 2, true
	}
	if len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return probe.TopologyConfig{}, 2, true
	}

	flags := parsed.Flags
	flags.Host = strings.TrimSpace(flags.Host)
	flags.User = strings.TrimSpace(flags.User)
	if flags.Host == "" {
		_, _ = fmt.Fprintln(stderr, "host is required")
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return probe.TopologyConfig{}, 2, true
	}
	if flags.UDPPort <= 0 || flags.UDPPort > 65535 {
		_, _ = fmt.Fprintln(stderr, "udp port must be between 1 and 65535")
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return probe.TopologyConfig{}, 2, true
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(flags.Timeout))
	if err != nil || timeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "timeout must be a positive duration")
		_, _ = fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return probe.TopologyConfig{}, 2, true
	}

	return probe.TopologyConfig{
		Host:    flags.Host,
		User:    flags.User,
		UDPPort: flags.UDPPort,
		Timeout: timeout,
	}, 0, false
}

type topologyFlags struct {
	Host    string `flag:"host" help:"Remote host to diagnose"`
	User    string `flag:"user" help:"SSH user" default:"root"`
	UDPPort int    `flag:"udp-port" help:"Remote UDP echo port" default:"47000"`
	Timeout string `flag:"timeout" help:"Per-probe timeout" default:"5s"`
}
