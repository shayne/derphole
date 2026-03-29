package main

import (
	"flag"
	"fmt"
	"io"
)

const sendUsage = "usage: derpcat send <token> [flags...]"

func runSend(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, sendUsage)
	}

	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	if args[0] == "-h" || args[0] == "--help" {
		fs.Usage()
		return 0
	}

	tokenArg := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if tokenArg == "" {
		fs.Usage()
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}

	_ = tokenArg
	_ = stdin
	_ = stdout
	return 0
}
