package main

import (
	"errors"
	"fmt"
	"io"

	pkgderphole "github.com/shayne/derpcat/pkg/derphole"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/yargs"
)

type receiveFlags struct {
	ForceRelay   bool   `flag:"force-relay" help:"Disable direct probing"`
	HideProgress bool   `flag:"hide-progress" help:"Suppress progress-bar display"`
	Output       string `flag:"output" short:"o" help:"Write a received file to this path or directory"`
}

type receiveArgs struct {
	Code string `pos:"0?" help:"Optional receive code"`
}

var receiveHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Receive text, files, or directories with wormhole-shaped UX on top of derpcat transport.",
		Examples: []string{
			"derphole receive",
			"derphole receive 7-purple-sausages",
			"derphole rx",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"receive": {
			Name:        "receive",
			Description: "Receive text, a file, or a directory.",
			Usage:       "[--force-relay] [code]",
			Examples: []string{
				"derphole receive",
				"derphole receive 7-purple-sausages",
			},
		},
	},
}

var runReceiveTransfer = pkgderphole.Receive

func runReceive(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, receiveFlags, receiveArgs](append([]string{"receive"}, args...), receiveHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, receiveHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, receiveHelpText())
			return 2
		}
	}

	if len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, receiveHelpText())
		return 2
	}

	token := parsed.Args.Code
	if err := runReceiveTransfer(commandContext(), pkgderphole.ReceiveConfig{
		Token:      token,
		Allocate:   token == "",
		OutputPath: parsed.SubCommandFlags.Output,
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		ProgressOutput: func() io.Writer {
			if parsed.SubCommandFlags.HideProgress {
				return nil
			}
			return stderr
		}(),
		Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		UsePublicDERP: usePublicDERPTransport(),
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func receiveHelpText() string {
	return yargs.GenerateSubCommandHelp(receiveHelpConfig, "receive", struct{}{}, receiveFlags{}, receiveArgs{})
}
