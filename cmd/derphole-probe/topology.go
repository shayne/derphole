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
		fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[topologyFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 2
	}

	flags := parsed.Flags
	flags.Host = strings.TrimSpace(flags.Host)
	flags.User = strings.TrimSpace(flags.User)
	if flags.Host == "" {
		fmt.Fprintln(stderr, "host is required")
		fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 2
	}
	if flags.UDPPort <= 0 || flags.UDPPort > 65535 {
		fmt.Fprintln(stderr, "udp port must be between 1 and 65535")
		fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 2
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(flags.Timeout))
	if err != nil || timeout <= 0 {
		fmt.Fprintln(stderr, "timeout must be a positive duration")
		fmt.Fprint(stderr, subcommandUsageLine("topology"))
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := runTopologyProbe(ctx, probe.TopologyConfig{
		Host:    flags.Host,
		User:    flags.User,
		UDPPort: flags.UDPPort,
		Timeout: timeout,
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

type topologyFlags struct {
	Host    string `flag:"host" help:"Remote host to diagnose"`
	User    string `flag:"user" help:"SSH user" default:"root"`
	UDPPort int    `flag:"udp-port" help:"Remote UDP echo port" default:"47000"`
	Timeout string `flag:"timeout" help:"Per-probe timeout" default:"5s"`
}
