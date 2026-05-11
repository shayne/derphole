// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"

	pkgderphole "github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/yargs"
)

type receiveFlags struct {
	ForceRelay   bool   `flag:"force-relay" help:"Disable direct probing"`
	HideProgress bool   `flag:"hide-progress" help:"Suppress progress-bar display"`
	Output       string `flag:"output" short:"o" help:"Write a received file to this path or directory"`
}

type receiveArgs struct {
	Code string `pos:"0?" help:"Optional receive code"`
}

var receiveHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Receive text, files, or directories with wormhole-shaped UX on top of derphole transport.",
		Examples: []string{
			"derphole receive",
			"derphole receive 7-purple-sausages",
			"derphole rx",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"receive": {
			Name:        "receive",
			Description: "Receive text, a file, or a directory.",
			Usage:       "[--force-relay] [code]",
			Examples: []string{
				"derphole receive",
				"derphole receive 7-purple-sausages",
			},
		},
	},
}

var runReceiveTransfer = pkgderphole.Receive

func runReceive(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, receiveFlags, receiveArgs](append([]string{"receive"}, args...), receiveHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, receiveHelpText, nil); handled {
		return code
	}

	if len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, receiveHelpText())
		return 2
	}

	token := parsed.Args.Code
	ctx, stop := commandContext()
	defer stop()
	trace, closeTrace, ok := openTransferTraceFromEnv(transfertrace.RoleReceive, stderr)
	if !ok {
		return 1
	}
	defer closeTrace()
	if err := runReceiveTransfer(ctx, pkgderphole.ReceiveConfig{
		Token:      token,
		Allocate:   token == "",
		OutputPath: parsed.SubCommandFlags.Output,
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		ProgressOutput: func() io.Writer {
			if parsed.SubCommandFlags.HideProgress {
				return nil
			}
			return stderr
		}(),
		Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		UsePublicDERP:  usePublicDERPTransport(),
		ForceRelay:     parsed.SubCommandFlags.ForceRelay,
		ParallelPolicy: session.DefaultParallelPolicy(),
		Trace:          trace,
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func receiveHelpText() string {
	return yargs.GenerateSubCommandHelp(receiveHelpConfig, "receive", struct{}{}, receiveFlags{}, receiveArgs{})
}
