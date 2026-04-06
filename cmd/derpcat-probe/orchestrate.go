package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/signal"
	"syscall"

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
	if flags.Mode == "" {
		flags.Mode = "raw"
	}
	if flags.SizeBytes == 0 {
		flags.SizeBytes = 1 << 20
	}
	if flags.Mode == "aead" {
		fmt.Fprintln(stderr, "aead not implemented yet")
		fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := probe.RunOrchestrate(ctx, probe.OrchestrateConfig{
		Host:      flags.Host,
		User:      flags.User,
		Mode:      flags.Mode,
		SizeBytes: flags.SizeBytes,
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
	User      string `flag:"user" help:"SSH user"`
	Mode      string `flag:"mode" help:"Probe mode"`
	SizeBytes int64  `flag:"size-bytes" help:"Payload size in bytes"`
}
