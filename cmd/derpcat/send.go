package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
)

const sendUsage = "usage: derpcat send <token> [flags...]"

func runSend(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
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
	forceRelay := fs.Bool("force-relay", false, "disable direct probing")
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

	if err := session.Send(context.Background(), session.SendConfig{
		Token:      tokenArg,
		Emitter:    telemetry.New(stderr, level),
		StdioIn:    stdin,
		Attachment: nil,
		ForceRelay: *forceRelay,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}
