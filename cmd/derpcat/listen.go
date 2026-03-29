package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/yargs"
)

type listenFlags struct {
	PrintTokenOnly bool   `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool   `flag:"force-relay" help:"Disable direct probing"`
	TCPListen      string `flag:"tcp-listen" help:"Accept one local TCP connection and forward its bytes to the session sink"`
	TCPConnect     string `flag:"tcp-connect" help:"Connect to a local TCP service and forward session bytes to it"`
}

var listenHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derpcat",
		Description: "Move one byte stream between hosts over public DERP with direct UDP promotion when available.",
		Examples: []string{
			"derpcat listen",
			"cat file | derpcat send <token>",
			"derpcat version",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"listen": {
			Name:        "listen",
			Description: "Listen for one incoming derpcat session and receive data.",
			Usage:       "[--print-token-only] [--tcp-listen addr | --tcp-connect addr] [--force-relay]",
			Examples: []string{
				"derpcat listen",
				"derpcat listen --tcp-connect 127.0.0.1:9000",
			},
		},
	},
}

func runListen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		fmt.Fprint(stderr, listenHelpText())
	}

	fs.Bool("h", false, "Show this help message")
	fs.Bool("help", false, "Show this help message")
	fs.Bool("help-llm", false, "Show LLM-optimized help")
	printTokenOnly := fs.Bool("print-token-only", false, "Print only the session token")
	forceRelay := fs.Bool("force-relay", false, "Disable direct probing")
	tcpListen := fs.String("tcp-listen", "", "Accept one local TCP connection and forward its bytes to the session sink")
	tcpConnect := fs.String("tcp-connect", "", "Connect to a local TCP service and forward session bytes to it")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		fs.Usage()
		return 2
	}

	if len(fs.Args()) != 0 {
		fs.Usage()
		return 2
	}

	helpRequested := false
	helpLLMRequested := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "h", "help":
			helpRequested = true
		case "help-llm":
			helpLLMRequested = true
		}
	})

	if helpLLMRequested {
		fmt.Fprint(stderr, listenHelpLLMText())
		return 0
	}
	if helpRequested {
		fmt.Fprint(stderr, listenHelpText())
		return 0
	}

	if *tcpListen != "" && *tcpConnect != "" {
		fmt.Fprintln(stderr, "listen: --tcp-listen and --tcp-connect are mutually exclusive")
		return 2
	}

	emitter := telemetry.New(stderr, level)
	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := session.Listen(context.Background(), session.ListenConfig{
			Emitter:       emitter,
			TokenSink:     tokenSink,
			StdioOut:      stdout,
			Attachment:    nil,
			TCPListen:     *tcpListen,
			TCPConnect:    *tcpConnect,
			ForceRelay:    *forceRelay,
			UsePublicDERP: usePublicDERPTransport(),
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

func listenHelpText() string {
	return yargs.GenerateSubCommandHelp(
		listenHelpConfig,
		"listen",
		struct{}{},
		listenFlags{},
		struct{}{},
	)
}

func listenHelpLLMText() string {
	return yargs.GenerateSubCommandHelpLLM(
		listenHelpConfig,
		"listen",
		struct{}{},
		listenFlags{},
		struct{}{},
	)
}
