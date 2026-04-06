package main

import (
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

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

	return 0
}

type clientFlags struct {
	Host string `flag:"host" help:"Remote host to connect to"`
	Mode string `flag:"mode" help:"Probe mode"`
}
