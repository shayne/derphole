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

var openSession = session.Open

func runOpen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, openFlags, openArgs](append([]string{"open"}, args...), openHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, openHelpText, nil); handled {
		return code
	}

	if parsed.Args.Token == "" || len(parsed.Parser.Args) > 2 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, openHelpText())
		return 2
	}

	policy, code, failed := parseParallelPolicy(parsed.SubCommandFlags.Parallel, stderr, openHelpText)
	if failed {
		return code
	}

	ctx, stop := commandContext()
	defer stop()
	return runOpenSession(ctx, parsed, policy, level, stdout, stderr)
}

func runOpenSession(ctx context.Context, parsed *yargs.TypedParseResult[struct{}, openFlags, openArgs], policy session.ParallelPolicy, level telemetry.Level, stdout, stderr io.Writer) int {
	bindSink, done := startOpenSession(ctx, parsed, policy, level, stderr)
	if code, finished := waitOpenBind(bindSink, done, stderr); finished {
		return code
	}

	_ = stdout
	return waitOpenDone(done, stderr)
}

func startOpenSession(ctx context.Context, parsed *yargs.TypedParseResult[struct{}, openFlags, openArgs], policy session.ParallelPolicy, level telemetry.Level, stderr io.Writer) (<-chan string, <-chan error) {
	bindSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- openSession(ctx, session.OpenConfig{
			Token:          parsed.Args.Token,
			BindAddr:       parsed.Args.BindAddr,
			BindAddrSink:   bindSink,
			Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
			ForceRelay:     parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP:  usePublicDERPTransport(),
			ParallelPolicy: policy,
		})
	}()
	return bindSink, done
}

func waitOpenBind(bindSink <-chan string, done <-chan error, stderr io.Writer) (int, bool) {
	select {
	case bindAddr := <-bindSink:
		_, _ = fmt.Fprintf(stderr, "listening on %s\n", bindAddr)
		return 0, false
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintln(stderr, err)
			return 1, true
		}
		return 0, true
	}
}

func waitOpenDone(done <-chan error, stderr io.Writer) int {
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func openHelpText() string {
	return yargs.GenerateSubCommandHelp(openHelpConfig, "open", struct{}{}, openFlags{}, openArgs{})
}
