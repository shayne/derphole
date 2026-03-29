package main

import (
	"fmt"
	"io"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: derpcat <listen|send> [flags]")
		return 2
	}

	switch args[0] {
	case "listen":
		fmt.Fprintln(stderr, "listen not implemented")
		return 2
	case "send":
		fmt.Fprintln(stderr, "send not implemented")
		return 2
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", args[0])
		return 2
	}
}
