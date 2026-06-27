// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	derpsshsession "github.com/shayne/derphole/pkg/derpssh/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

type connectSessionConfig = derpsshsession.ConnectConfig

var runConnectSession = derpsshsession.Connect

func runConnect(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		_, _ = fmt.Fprintln(stderr, "Usage: derpssh connect [--name NAME] <invite>")
		return 0
	}
	parsed, ok := parseConnectArgs(args, stderr)
	if !ok {
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := runConnectSession(ctx, connectSessionConfig{
		Invite:      parsed.invite,
		DisplayName: parsed.displayName,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		ForceRelay:  parsed.forceRelay,
		Emitter:     telemetry.New(stderr, commandSessionTelemetryLevel(level)),
	}); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type parsedConnectArgs struct {
	invite      string
	displayName string
	forceRelay  bool
}

func parseConnectArgs(args []string, stderr io.Writer) (parsedConnectArgs, bool) {
	var parsed parsedConnectArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--force-relay":
			parsed.forceRelay = true
		case arg == "--name":
			if i+1 >= len(args) {
				_, _ = fmt.Fprintln(stderr, "--name requires a value")
				_, _ = fmt.Fprintln(stderr, "Usage: derpssh connect [--name NAME] <invite>")
				return parsedConnectArgs{}, false
			}
			i++
			parsed.displayName = args[i]
		case strings.HasPrefix(arg, "--name="):
			parsed.displayName = strings.TrimPrefix(arg, "--name=")
		case strings.HasPrefix(arg, "-"):
			_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
			_, _ = fmt.Fprintln(stderr, "Usage: derpssh connect [--name NAME] <invite>")
			return parsedConnectArgs{}, false
		default:
			if parsed.invite != "" {
				_, _ = fmt.Fprintln(stderr, "Usage: derpssh connect [--name NAME] <invite>")
				return parsedConnectArgs{}, false
			}
			parsed.invite = arg
		}
	}
	if parsed.invite == "" {
		_, _ = fmt.Fprintln(stderr, "Usage: derpssh connect [--name NAME] <invite>")
		return parsedConnectArgs{}, false
	}
	return parsed, true
}
