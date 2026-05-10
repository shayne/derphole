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

var shareSession = session.Share

func runShare(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, shareFlags, shareArgs](append([]string{"share"}, args...), shareHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, shareHelpText, nil); handled {
		return code
	}

	if parsed.Args.Target == "" || len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, shareHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	return runShareSession(ctx, parsed, level, stdout, stderr)
}

func runShareSession(ctx context.Context, parsed *yargs.TypedParseResult[struct{}, shareFlags, shareArgs], level telemetry.Level, stdout, stderr io.Writer) int {
	tokenSink, done := startShareSession(ctx, parsed, level, stderr)
	tok, code, finished := waitShareToken(tokenSink, done, stderr)
	if finished {
		return code
	}
	if tok == "" {
		_, _ = fmt.Fprintln(stderr, "failed to issue share token")
		return 1
	}

	_, _ = fmt.Fprintln(shareTokenWriter(parsed, stdout, stderr), tok)
	return waitShareDone(done, stderr)
}

func startShareSession(ctx context.Context, parsed *yargs.TypedParseResult[struct{}, shareFlags, shareArgs], level telemetry.Level, stderr io.Writer) (<-chan string, <-chan error) {
	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := shareSession(ctx, session.ShareConfig{
			Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
			TokenSink:     tokenSink,
			TargetAddr:    parsed.Args.Target,
			ForceRelay:    parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP: usePublicDERPTransport(),
		})
		done <- err
	}()
	return tokenSink, done
}

func waitShareToken(tokenSink <-chan string, done <-chan error, stderr io.Writer) (string, int, bool) {
	select {
	case tok := <-tokenSink:
		return tok, 0, false
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintln(stderr, err)
			return "", 1, true
		}
		return "", 0, true
	}
}

func shareTokenWriter(parsed *yargs.TypedParseResult[struct{}, shareFlags, shareArgs], stdout, stderr io.Writer) io.Writer {
	if parsed.SubCommandFlags.PrintTokenOnly {
		return stdout
	}
	return stderr
}

func waitShareDone(done <-chan error, stderr io.Writer) int {
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func shareHelpText() string {
	return yargs.GenerateSubCommandHelp(shareHelpConfig, "share", struct{}{}, shareFlags{}, shareArgs{})
}
