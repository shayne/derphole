package main

import (
	"fmt"
	"io"

	"github.com/shayne/derpcat/pkg/telemetry"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	level := telemetry.LevelDefault
	for len(args) > 0 {
		switch args[0] {
		case "-v", "--verbose":
			level = telemetry.LevelVerbose
			args = args[1:]
		case "-q", "--quiet":
			level = telemetry.LevelQuiet
			args = args[1:]
		case "-s", "--silent":
			level = telemetry.LevelSilent
			args = args[1:]
		case "--version":
			fmt.Fprintln(stdout, versionString())
			return 0
		case "-h", "--help":
			fmt.Fprintln(stderr, "usage: derpcat <listen|send> [flags]")
			return 0
		default:
			goto dispatch
		}
	}

	fmt.Fprintln(stderr, "usage: derpcat <listen|send> [flags]")
	return 2

dispatch:
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: derpcat <listen|send> [flags]")
		return 2
	}

	switch args[0] {
	case "listen":
		return runListen(args[1:], level, stdout, stderr)
	case "send":
		return runSend(args[1:], level, stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", args[0])
		return 2
	}
}
