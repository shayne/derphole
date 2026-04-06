package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

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
	if flags.User == "" {
		flags.User = "root"
	}
	if flags.RemotePath == "" {
		flags.RemotePath = "/tmp/derpcat-probe"
	}
	if flags.ListenAddr == "" {
		flags.ListenAddr = ":0"
	}
	if flags.Mode == "" {
		flags.Mode = "raw"
	}
	if flags.Direction == "" {
		flags.Direction = "forward"
	}
	if flags.SizeBytes == 0 {
		flags.SizeBytes = 1 << 20
	}

	report, err := probe.RunOrchestrate(context.Background(), probe.OrchestrateConfig{
		Host:       flags.Host,
		User:       flags.User,
		RemotePath: flags.RemotePath,
		ListenAddr: flags.ListenAddr,
		Mode:       flags.Mode,
		Direction:  flags.Direction,
		SizeBytes:  flags.SizeBytes,
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
	Host       string `flag:"host" help:"Remote host to benchmark"`
	User       string `flag:"user" help:"SSH user"`
	RemotePath string `flag:"remote-path" help:"Path to the probe binary on the remote host"`
	ListenAddr string `flag:"listen" help:"Listen address for the remote server"`
	Mode       string `flag:"mode" help:"Probe mode"`
	Direction  string `flag:"direction" help:"Benchmark direction"`
	SizeBytes  int64  `flag:"size-bytes" help:"Payload size in bytes"`
}
