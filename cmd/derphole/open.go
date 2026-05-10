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
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
	Parallel   string `flag:"parallel" short:"P" help:"Direct stripe count (1-16) or auto"`
}

type openArgs struct {
	Token    string `pos:"0" help:"Token from the sharer"`
	BindAddr string `pos:"1?" help:"Optional local bind address, for example 127.0.0.1:8080"`
}

var openHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Open a shared TCP service locally over public DERP with direct UDP promotion when available.",
		Examples: []string{
			"derphole open <token>",
			"derphole open <token> 127.0.0.1:8080",
			"derphole share 127.0.0.1:3000",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"open": {
			Name:        "open",
			Description: "Open a shared service locally until Ctrl-C.",
			Usage:       "[--force-relay] [--parallel]",
			Examples: []string{
				"derphole open <token>",
				"derphole open <token> 127.0.0.1:8080",
			},
		},
	},
}

func runOpen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, openFlags, openArgs](append([]string{"open"}, args...), openHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, openHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, openHelpText())
			return 2
		}
	}

	if parsed.Args.Token == "" || len(parsed.Parser.Args) > 2 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, openHelpText())
		return 2
	}

	policy := session.DefaultParallelPolicy()
	if parsed.SubCommandFlags.Parallel != "" {
		policy, err = session.ParseParallelPolicy(parsed.SubCommandFlags.Parallel)
		if err != nil {
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, openHelpText())
			return 2
		}
	}

	ctx, stop := commandContext()
	defer stop()

	bindSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- session.Open(ctx, session.OpenConfig{
			Token:          parsed.Args.Token,
			BindAddr:       parsed.Args.BindAddr,
			BindAddrSink:   bindSink,
			Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
			ForceRelay:     parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP:  usePublicDERPTransport(),
			ParallelPolicy: policy,
		})
	}()

	select {
	case bindAddr := <-bindSink:
		fmt.Fprintf(stderr, "listening on %s\n", bindAddr)
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}

	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	_ = stdout
	return 0
}

func openHelpText() string {
	return yargs.GenerateSubCommandHelp(openHelpConfig, "open", struct{}{}, openFlags{}, openArgs{})
}
