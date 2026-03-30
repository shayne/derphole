package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/yargs"
)

type sendFlags struct {
	ForceRelay bool `flag:"force-relay" help:"Disable direct probing"`
}

type sendArgs struct {
	Token string `pos:"0" help:"Token from the listener"`
}

var sendHelpConfig = yargs.HelpConfig{
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
		"send": {
			Name:        "send",
			Description: "Send data to a derpcat listener using its token.",
			Usage:       "[--force-relay]",
			Examples: []string{
				"cat file | derpcat send <token>",
				"printf 'hello' | derpcat send <token>",
			},
		},
	},
}

func runSend(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, sendFlags, sendArgs](append([]string{"send"}, args...), sendHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, sendHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, sendHelpText())
			return 2
		}
	}

	if parsed.Args.Token == "" || len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, sendHelpText())
		return 2
	}

	if err := session.Send(commandContext(), session.SendConfig{
		Token:         parsed.Args.Token,
		Emitter:       telemetry.New(stderr, level),
		StdioIn:       stdin,
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP: usePublicDERPTransport(),
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

func sendHelpText() string {
	return yargs.GenerateSubCommandHelp(sendHelpConfig, "send", struct{}{}, sendFlags{}, sendArgs{})
}

func sendHelpLLMText() string {
	return yargs.GenerateSubCommandHelpLLM(sendHelpConfig, "send", struct{}{}, sendFlags{}, sendArgs{})
}
