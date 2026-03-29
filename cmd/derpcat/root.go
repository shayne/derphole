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

	if args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: derpcat <listen|send> [flags]")
		return 0
	}

	switch args[0] {
	case "listen":
		return runListen(args[1:], stdout, stderr)
	case "send":
		return runSend(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", args[0])
		return 2
	}
}
