package main

import (
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

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

	return 0
}

type serverFlags struct {
	ListenAddr string `flag:"listen" help:"Listen address for the server"`
	Mode       string `flag:"mode" help:"Probe mode"`
}
