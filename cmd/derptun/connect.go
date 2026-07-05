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
	Service    string `flag:"service" help:"Resolve the client token from the local service registry"`
	Registry   string `flag:"registry" help:"Path to the local service registry"`
	Stdio      bool   `flag:"stdio" help:"Bridge one tunnel stream over stdin/stdout"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
}

var connectHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Connect a single TCP stream through a derptun client token.",
		Examples: []string{
			"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | derptun connect --service web --stdio",
			"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | derptun connect --token-file client.dt1 --stdio",
			"printf '%s\\n' \"$DERPTUN_CLIENT_TOKEN\" | derptun connect --token-stdin --stdio",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"connect": {
			Name:        "connect",
			Description: "Bridge one tunnel stream over stdin/stdout.",
			Usage:       "(--service NAME|--token TOKEN|--token-file PATH|--token-stdin) [--registry PATH] --stdio [--force-relay]",
			Examples: []string{
				"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | derptun connect --service web --stdio",
				"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | derptun connect --token-file client.dt1 --stdio",
				"printf '%s\\n' \"$DERPTUN_CLIENT_TOKEN\" | derptun connect --token-stdin --stdio",
			},
		},
	},
}

var derptunConnect = session.DerptunConnect

func runConnect(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, connectFlags, struct{}](append([]string{"connect"}, args...), connectHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, connectHelpText); handled {
		return code
	}
	if !parsed.SubCommandFlags.Stdio || len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, connectHelpText())
		return 2
	}
	ctx, stop := commandContext()
	defer stop()
	token, streamIn, err := resolveClientTokenSource(ctx, stdin, tokenSource{
		Token:      parsed.SubCommandFlags.Token,
		TokenFile:  parsed.SubCommandFlags.TokenFile,
		TokenStdin: parsed.SubCommandFlags.TokenStdin,
	}, serviceSource{
		Service:  parsed.SubCommandFlags.Service,
		Registry: parsed.SubCommandFlags.Registry,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, connectHelpText())
		return 2
	}
	if err := validateClientTokenForCLI(token); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, connectHelpText())
		return 2
	}

	if err := derptunConnect(ctx, session.DerptunConnectConfig{
		ClientToken: token,
		StdioIn:     streamIn,
		StdioOut:    stdout,
		Emitter:     telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		ForceRelay:  parsed.SubCommandFlags.ForceRelay,
	}); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func connectHelpText() string {
	return yargs.GenerateSubCommandHelp(connectHelpConfig, "connect", struct{}{}, connectFlags{}, struct{}{})
}
