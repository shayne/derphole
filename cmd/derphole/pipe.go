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

type pipeFlags struct {
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
	Parallel   string `flag:"parallel" short:"P" help:"Direct stripe count (1-16) or auto"`
}

type pipeArgs struct {
	Token string `pos:"0" help:"Token from the listener"`
}

var pipeHelpConfig = yargs.HelpConfig{
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
		"pipe": {
			Name:        "pipe",
			Description: "Send stdin as a raw byte stream to a derphole listener.",
			Usage:       "[--force-relay] [--parallel]",
			Examples: []string{
				"cat file | derphole pipe <token>",
				"printf 'hello' | derphole pipe <token>",
			},
		},
	},
}

var sendSession = session.Send

func runPipe(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, pipeFlags, pipeArgs](append([]string{"pipe"}, args...), pipeHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, pipeHelpText, nil); handled {
		return code
	}
	if !validPipeArgs(parsed) {
		_, _ = fmt.Fprint(stderr, pipeHelpText())
		return 2
	}
	return runParsedPipe(parsed, level, stdin, stdout, stderr)
}

func validPipeArgs(parsed *yargs.TypedParseResult[struct{}, pipeFlags, pipeArgs]) bool {
	return parsed.Args.Token != "" && len(parsed.Parser.Args) <= 1 && len(parsed.RemainingArgs) == 0
}

func runParsedPipe(parsed *yargs.TypedParseResult[struct{}, pipeFlags, pipeArgs], level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	policy, code, failed := parseParallelPolicy(parsed.SubCommandFlags.Parallel, stderr, pipeHelpText)
	if failed {
		return code
	}

	ctx, stop := commandContext()
	defer stop()
	if err := executePipeSession(ctx, parsed, policy, level, stdin, stderr); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

func executePipeSession(ctx context.Context, parsed *yargs.TypedParseResult[struct{}, pipeFlags, pipeArgs], policy session.ParallelPolicy, level telemetry.Level, stdin io.Reader, stderr io.Writer) error {
	return sendSession(ctx, session.SendConfig{
		Token:          parsed.Args.Token,
		Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		StdioIn:        stdin,
		ForceRelay:     parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP:  usePublicDERPTransport(),
		ParallelPolicy: policy,
	})
}

func pipeHelpText() string {
	return yargs.GenerateSubCommandHelp(pipeHelpConfig, "pipe", struct{}{}, pipeFlags{}, pipeArgs{})
}
