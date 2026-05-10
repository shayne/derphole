// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type listenFlags struct {
	PrintTokenOnly bool `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool `flag:"force-relay" help:"Disable direct probing"`
}

var listenHelpConfig = yargs.HelpConfig{
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
		"listen": {
			Name:        "listen",
			Description: "Listen for one incoming raw byte stream and write it to stdout.",
			Usage:       "[--print-token-only] [--force-relay]",
			Examples: []string{
				"derphole listen",
				"derphole listen --print-token-only",
			},
		},
	},
}

func runListen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, listenFlags, struct{}](append([]string{"listen"}, args...), listenHelpConfig)
	if err != nil {
		if errors.Is(err, yargs.ErrHelp) || errors.Is(err, yargs.ErrSubCommandHelp) || errors.Is(err, yargs.ErrHelpLLM) {
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else if errors.Is(err, yargs.ErrHelpLLM) {
				fmt.Fprint(stderr, listenHelpLLMText())
			} else {
				fmt.Fprint(stderr, listenHelpText())
			}
			return 0
		}
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	if len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	emitter := telemetry.New(stderr, commandSessionTelemetryLevel(level))
	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	ctx, stop := commandContext()
	defer stop()
	go func() {
		_, err := session.Listen(ctx, session.ListenConfig{
			Emitter:       emitter,
			TokenSink:     tokenSink,
			StdioOut:      stdout,
			ForceRelay:    parsed.SubCommandFlags.ForceRelay,
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
	if parsed.SubCommandFlags.PrintTokenOnly {
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
