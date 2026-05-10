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

type openFlags struct {
	Token      string `flag:"token" help:"Client token for tunnel access"`
	TokenFile  string `flag:"token-file" help:"Read the client token from a file"`
	TokenStdin bool   `flag:"token-stdin" help:"Read the client token from the first stdin line"`
	Listen     string `flag:"listen" help:"Local TCP bind address, for example 127.0.0.1:2222"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
}

var openHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Open a local TCP listener that forwards through a derptun client token.",
		Examples: []string{
			"derptun open --token-file client.dtc --listen 127.0.0.1:2222",
			"ssh -p 2222 foo@127.0.0.1",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"open": {
			Name:        "open",
			Description: "Listen locally and forward each TCP connection through the tunnel.",
			Usage:       "(--token TOKEN|--token-file PATH|--token-stdin) [--listen HOST:PORT] [--force-relay]",
			Examples: []string{
				"derptun open --token-file client.dtc",
				"printf '%s\\n' \"$DERPTUN_CLIENT_TOKEN\" | derptun open --token-stdin --listen 127.0.0.1:2222",
			},
		},
	},
}

var derptunOpen = session.DerptunOpen

func runOpen(args []string, level telemetry.Level, stdin io.Reader, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, openFlags, struct{}](append([]string{"open"}, args...), openHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, openHelpText); handled {
		return code
	}
	if len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, openHelpText())
		return 2
	}
	token, _, err := resolveTokenSource(stdin, tokenSource{
		Token:      parsed.SubCommandFlags.Token,
		TokenFile:  parsed.SubCommandFlags.TokenFile,
		TokenStdin: parsed.SubCommandFlags.TokenStdin,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, openHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	return runOpenSession(ctx, token, parsed, level, stderr)
}

func runOpenSession(ctx context.Context, token string, parsed *yargs.TypedParseResult[struct{}, openFlags, struct{}], level telemetry.Level, stderr io.Writer) int {
	bindSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- derptunOpen(ctx, session.DerptunOpenConfig{
			ClientToken:   token,
			ListenAddr:    parsed.SubCommandFlags.Listen,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
			ForceRelay:    parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP: usePublicDERPTransport(),
		})
	}()

	select {
	case bindAddr := <-bindSink:
		_, _ = fmt.Fprintf(stderr, "listening on %s\n", bindAddr)
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func openHelpText() string {
	return yargs.GenerateSubCommandHelp(openHelpConfig, "open", struct{}{}, openFlags{}, struct{}{})
}
