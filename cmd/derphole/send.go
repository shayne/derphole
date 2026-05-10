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
	"github.com/shayne/yargs"
)

type sendFlags struct {
	ForceRelay   bool `flag:"force-relay" help:"Disable direct probing"`
	HideProgress bool `flag:"hide-progress" help:"Suppress progress-bar display"`
	QR           bool `flag:"qr" help:"Render a QR code for the receive token"`
}

type sendArgs struct {
	What string `pos:"0?" help:"Optional text, file, or directory to send"`
}

var sendHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Send text, files, or directories with wormhole-shaped UX on top of derphole transport.",
		Examples: []string{
			"derphole send hello",
			"derphole send ./photo.jpg",
			"derphole tx ./project-dir",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"send": {
			Name:        "send",
			Description: "Send text, a file, or a directory.",
			Usage:       "[--force-relay] [--qr] [what]",
			Examples: []string{
				"derphole send hello",
				"derphole send ./photo.jpg",
			},
		},
	},
}

var runSendTransfer = pkgderphole.Send

func runSend(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, sendFlags, sendArgs](append([]string{"send"}, args...), sendHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, sendHelpText, nil); handled {
		return code
	}

	if len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, sendHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := runSendTransfer(ctx, pkgderphole.SendConfig{
		What:   parsed.Args.What,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		ProgressOutput: func() io.Writer {
			if parsed.SubCommandFlags.HideProgress {
				return nil
			}
			return stderr
		}(),
		Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		UsePublicDERP:  usePublicDERPTransport(),
		ForceRelay:     parsed.SubCommandFlags.ForceRelay,
		QR:             parsed.SubCommandFlags.QR,
		ParallelPolicy: session.DefaultParallelPolicy(),
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func sendHelpText() string {
	return yargs.GenerateSubCommandHelp(sendHelpConfig, "send", struct{}{}, sendFlags{}, sendArgs{})
}
