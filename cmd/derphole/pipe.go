package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type pipeFlags struct {
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
	Parallel   string `flag:"parallel" short:"P" help:"Direct stripe count (1-16) or auto"`
}

type pipeArgs struct {
	Token string `pos:"0" help:"Token from the listener"`
}

var pipeHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Move one byte stream between hosts over public DERP with direct UDP promotion when available.",
		Examples: []string{
			"derphole listen",
			"cat file | derphole pipe <token>",
			"derphole version",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"pipe": {
			Name:        "pipe",
			Description: "Send stdin as a raw byte stream to a derphole listener.",
			Usage:       "[--force-relay] [--parallel]",
			Examples: []string{
				"cat file | derphole pipe <token>",
				"printf 'hello' | derphole pipe <token>",
			},
		},
	},
}

func runPipe(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, pipeFlags, pipeArgs](append([]string{"pipe"}, args...), pipeHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, pipeHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, pipeHelpText())
			return 2
		}
	}

	if parsed.Args.Token == "" || len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, pipeHelpText())
		return 2
	}

	policy := session.DefaultParallelPolicy()
	if parsed.SubCommandFlags.Parallel != "" {
		policy, err = session.ParseParallelPolicy(parsed.SubCommandFlags.Parallel)
		if err != nil {
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, pipeHelpText())
			return 2
		}
	}

	ctx, stop := commandContext()
	defer stop()
	if err := session.Send(ctx, session.SendConfig{
		Token:          parsed.Args.Token,
		Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		StdioIn:        stdin,
		ForceRelay:     parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP:  usePublicDERPTransport(),
		ParallelPolicy: policy,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

func pipeHelpText() string {
	return yargs.GenerateSubCommandHelp(pipeHelpConfig, "pipe", struct{}{}, pipeFlags{}, pipeArgs{})
}
