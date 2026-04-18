package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type connectFlags struct {
	Token      string `flag:"token" help:"Durable derptun token"`
	Stdio      bool   `flag:"stdio" help:"Bridge one tunnel stream over stdin/stdout"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
}

var connectHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Connect a single TCP stream through a durable derptun token.",
		Examples: []string{
			"ssh -o ProxyCommand='derptun connect --token <token> --stdio' foo@host1",
			"derptun connect --token <token> --stdio",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"connect": {
			Name:        "connect",
			Description: "Bridge one tunnel stream over stdin/stdout.",
			Usage:       "--token TOKEN --stdio [--force-relay]",
			Examples: []string{
				"ssh -o ProxyCommand='derptun connect --token <token> --stdio' foo@host1",
				"derptun connect --token <token> --stdio",
			},
		},
	},
}

var derptunConnect = session.DerptunConnect

func runConnect(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, connectFlags, struct{}](append([]string{"connect"}, args...), connectHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, connectHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, connectHelpText())
			return 2
		}
	}
	if parsed.SubCommandFlags.Token == "" || !parsed.SubCommandFlags.Stdio || len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, connectHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := derptunConnect(ctx, session.DerptunConnectConfig{
		Token:         parsed.SubCommandFlags.Token,
		StdioIn:       stdin,
		StdioOut:      stdout,
		Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP: usePublicDERPTransport(),
	}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func connectHelpText() string {
	return yargs.GenerateSubCommandHelp(connectHelpConfig, "connect", struct{}{}, connectFlags{}, struct{}{})
}
