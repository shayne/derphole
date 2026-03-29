package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
)

const listenUsage = "usage: derpcat listen [--print-token-only]"

func runListen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, listenUsage)
	}

	printTokenOnly := fs.Bool("print-token-only", false, "print only the session token")
	forceRelay := fs.Bool("force-relay", false, "disable direct probing")
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		return 0
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}

	emitter := telemetry.New(stderr, level)
	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := session.Listen(context.Background(), session.ListenConfig{
			Emitter:    emitter,
			TokenSink:  tokenSink,
			StdioOut:   stdout,
			Attachment: nil,
			ForceRelay: *forceRelay,
		})
		done <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case err := <-done:
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if tok == "" {
		fmt.Fprintln(stderr, "failed to issue session token")
		return 1
	}

	tokenOut := stderr
	if *printTokenOnly {
		tokenOut = stdout
	}
	fmt.Fprintln(tokenOut, tok)

	if err := <-done; err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
