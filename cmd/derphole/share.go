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

type shareFlags struct {
	PrintTokenOnly bool `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool `flag:"force-relay" help:"Disable direct probing"`
}

type shareArgs struct {
	Target string `pos:"0" help:"Local TCP service to share, for example 127.0.0.1:3000"`
}

var shareHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Expose a local TCP service over public DERP with direct UDP promotion when available.",
		Examples: []string{
			"derphole share 127.0.0.1:3000",
			"derphole share 127.0.0.1:8080 --print-token-only",
			"derphole open <token>",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"share": {
			Name:        "share",
			Description: "Share a local TCP service until Ctrl-C.",
			Usage:       "[--print-token-only] [--force-relay]",
			Examples: []string{
				"derphole share 127.0.0.1:3000",
				"derphole share 127.0.0.1:8080 --print-token-only",
			},
		},
	},
}

func runShare(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, shareFlags, shareArgs](append([]string{"share"}, args...), shareHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, shareHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, shareHelpText())
			return 2
		}
	}

	if parsed.Args.Target == "" || len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, shareHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()

	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := session.Share(ctx, session.ShareConfig{
			Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
			TokenSink:     tokenSink,
			TargetAddr:    parsed.Args.Target,
			ForceRelay:    parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP: usePublicDERPTransport(),
		})
		done <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if tok == "" {
		fmt.Fprintln(stderr, "failed to issue share token")
		return 1
	}

	tokenOut := stderr
	if parsed.SubCommandFlags.PrintTokenOnly {
		tokenOut = stdout
	}
	fmt.Fprintln(tokenOut, tok)

	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func shareHelpText() string {
	return yargs.GenerateSubCommandHelp(shareHelpConfig, "share", struct{}{}, shareFlags{}, shareArgs{})
}
