// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
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

var listenSession = session.Listen

func runListen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, listenFlags, struct{}](append([]string{"listen"}, args...), listenHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, listenHelpText, listenHelpLLMText); handled {
		return code
	}

	if len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	emitter := telemetry.New(stderr, commandSessionTelemetryLevel(level))
	ctx, stop := commandContext()
	defer stop()
	tokenSink, done := startListenSession(ctx, parsed, emitter, stdout)
	tok, code, finished := waitListenToken(tokenSink, done, stderr)
	if finished {
		return code
	}
	if tok == "" {
		_, _ = fmt.Fprintln(stderr, "failed to issue session token")
		return 1
	}

	_, _ = fmt.Fprintln(listenTokenWriter(parsed, stdout, stderr), tok)
	return waitListenDone(done, stderr)
}

func startListenSession(ctx context.Context, parsed *yargs.TypedParseResult[struct{}, listenFlags, struct{}], emitter *telemetry.Emitter, stdout io.Writer) (<-chan string, <-chan error) {
	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := listenSession(ctx, session.ListenConfig{
			Emitter:       emitter,
			TokenSink:     tokenSink,
			StdioOut:      stdout,
			ForceRelay:    parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP: usePublicDERPTransport(),
		})
		done <- err
	}()
	return tokenSink, done
}

func waitListenToken(tokenSink <-chan string, done <-chan error, stderr io.Writer) (string, int, bool) {
	select {
	case tok := <-tokenSink:
		return tok, 0, false
	case err := <-done:
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return "", 1, true
		}
		return "", 0, true
	}
}

func listenTokenWriter(parsed *yargs.TypedParseResult[struct{}, listenFlags, struct{}], stdout, stderr io.Writer) io.Writer {
	if parsed.SubCommandFlags.PrintTokenOnly {
		return stdout
	}
	return stderr
}

func waitListenDone(done <-chan error, stderr io.Writer) int {
	if err := <-done; err != nil {
		_, _ = fmt.Fprintln(stderr, err)
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
