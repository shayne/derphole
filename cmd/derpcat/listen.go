package main

import (
	"context"
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

type listenParseFlags struct {
	PrintTokenOnly bool   `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool   `flag:"force-relay" help:"Disable direct probing"`
	TCPListen      string `flag:"tcp-listen" help:"Accept one local TCP connection and forward its bytes to the session sink"`
	TCPConnect     string `flag:"tcp-connect" help:"Connect to a local TCP service and forward session bytes to it"`
	Help           bool   `flag:"help" short:"h" help:"Show this help message"`
	HelpLLM        bool   `flag:"help-llm" help:"Show LLM-optimized help"`
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
	parsed, err := yargs.ParseFlags[listenParseFlags](args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	if len(parsed.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	if parsed.Flags.HelpLLM {
		fmt.Fprint(stderr, listenHelpLLMText())
		return 0
	}
	if listenHelpRequested(parsed) {
		fmt.Fprint(stderr, listenHelpText())
		return 0
	}

	if parsed.Flags.TCPListen != "" && parsed.Flags.TCPConnect != "" {
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
			TCPListen:     parsed.Flags.TCPListen,
			TCPConnect:    parsed.Flags.TCPConnect,
			ForceRelay:    parsed.Flags.ForceRelay,
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
	if parsed.Flags.PrintTokenOnly {
		tokenOut = stdout
	}
	fmt.Fprintln(tokenOut, tok)

	if err := <-done; err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func listenHelpRequested(parsed *yargs.ParseResult[listenParseFlags]) bool {
	if parsed.Flags.Help {
		return true
	}
	_, ok := parsed.Parser.Flags["help"]
	return ok
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
