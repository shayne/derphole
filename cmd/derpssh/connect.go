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
		_, _ = fmt.Fprintln(stderr, connectUsage())
		return 0
	}
	parsed, ok := parseConnectArgs(args, stderr)
	if !ok {
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	invite := parsed.invite
	if parsed.service != "" {
		resolved, err := resolveDerpsshServiceInvite(ctx, parsed.service, parsed.registry)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return serviceErrorCode(err)
		}
		invite = resolved
	}
	if err := runConnectSession(ctx, connectSessionConfig{
		Invite:      invite,
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
	service     string
	registry    string
	displayName string
	forceRelay  bool
}

func parseConnectArgs(args []string, stderr io.Writer) (parsedConnectArgs, bool) {
	var parsed parsedConnectArgs
	for i := 0; i < len(args); i++ {
		if !parseConnectArg(args, &i, stderr, &parsed) {
			return parsedConnectArgs{}, false
		}
	}
	return validateConnectArgs(parsed, stderr)
}

func parseConnectArg(args []string, index *int, stderr io.Writer, parsed *parsedConnectArgs) bool {
	arg := args[*index]
	if handled, ok := parseConnectFlagArg(args, index, stderr, parsed); handled {
		return ok
	}
	if strings.HasPrefix(arg, "-") {
		_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
		_, _ = fmt.Fprintln(stderr, connectUsage())
		return false
	}
	return parseConnectInvite(arg, stderr, parsed)
}

func parseConnectFlagArg(args []string, index *int, stderr io.Writer, parsed *parsedConnectArgs) (bool, bool) {
	arg := args[*index]
	switch {
	case arg == "--force-relay":
		parsed.forceRelay = true
		return true, true
	case arg == "--service":
		value, ok := connectFlagValue(args, index, "--service", stderr)
		parsed.service = value
		return true, ok
	case strings.HasPrefix(arg, "--service="):
		parsed.service = strings.TrimPrefix(arg, "--service=")
		return true, true
	case arg == "--registry":
		value, ok := connectFlagValue(args, index, "--registry", stderr)
		parsed.registry = value
		return true, ok
	case strings.HasPrefix(arg, "--registry="):
		parsed.registry = strings.TrimPrefix(arg, "--registry=")
		return true, true
	case arg == "--name":
		value, ok := connectFlagValue(args, index, "--name", stderr)
		parsed.displayName = value
		return true, ok
	case strings.HasPrefix(arg, "--name="):
		parsed.displayName = strings.TrimPrefix(arg, "--name=")
		return true, true
	default:
		return false, false
	}
}

func parseConnectInvite(arg string, stderr io.Writer, parsed *parsedConnectArgs) bool {
	if parsed.invite != "" {
		_, _ = fmt.Fprintln(stderr, connectUsage())
		return false
	}
	parsed.invite = arg
	return true
}

func validateConnectArgs(parsed parsedConnectArgs, stderr io.Writer) (parsedConnectArgs, bool) {
	if parsed.service != "" && parsed.invite != "" {
		_, _ = fmt.Fprintln(stderr, "--service and invite argument are mutually exclusive")
		_, _ = fmt.Fprintln(stderr, connectUsage())
		return parsedConnectArgs{}, false
	}
	if parsed.service == "" && parsed.invite == "" {
		_, _ = fmt.Fprintln(stderr, connectUsage())
		return parsedConnectArgs{}, false
	}
	return parsed, true
}

func connectFlagValue(args []string, index *int, flag string, stderr io.Writer) (string, bool) {
	if *index+1 >= len(args) {
		_, _ = fmt.Fprintf(stderr, "%s requires a value\n", flag)
		_, _ = fmt.Fprintln(stderr, connectUsage())
		return "", false
	}
	*index = *index + 1
	return args[*index], true
}

func connectUsage() string {
	return "Usage: derpssh connect [--name NAME] (--service NAME|<invite>) [--registry PATH]"
}
