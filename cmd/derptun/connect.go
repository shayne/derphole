// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	Token      string `flag:"token" help:"Client token for tunnel access"`
	TokenFile  string `flag:"token-file" help:"Read the client token from a file"`
	TokenStdin bool   `flag:"token-stdin" help:"Read the client token from the first stdin line"`
	Stdio      bool   `flag:"stdio" help:"Bridge one tunnel stream over stdin/stdout"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
}

var connectHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Connect a single TCP stream through a derptun client token.",
		Examples: []string{
			"ssh -o ProxyCommand='derptun connect --token-file ~/.config/derptun/client.dtc --stdio' foo@serverhost",
			"printf '%s\\n' \"$DERPTUN_CLIENT_TOKEN\" | derptun connect --token-stdin --stdio",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"connect": {
			Name:        "connect",
			Description: "Bridge one tunnel stream over stdin/stdout.",
			Usage:       "(--token TOKEN|--token-file PATH|--token-stdin) --stdio [--force-relay]",
			Examples: []string{
				"ssh -o ProxyCommand='derptun connect --token-file ~/.config/derptun/client.dtc --stdio' foo@serverhost",
				"printf '%s\\n' \"$DERPTUN_CLIENT_TOKEN\" | derptun connect --token-stdin --stdio",
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
	if !parsed.SubCommandFlags.Stdio || len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, connectHelpText())
		return 2
	}
	token, streamIn, err := resolveTokenSource(stdin, tokenSource{
		Token:      parsed.SubCommandFlags.Token,
		TokenFile:  parsed.SubCommandFlags.TokenFile,
		TokenStdin: parsed.SubCommandFlags.TokenStdin,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, connectHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := derptunConnect(ctx, session.DerptunConnectConfig{
		ClientToken:   token,
		StdioIn:       streamIn,
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
