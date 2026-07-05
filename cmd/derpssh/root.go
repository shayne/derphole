// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type rootGlobalFlags struct {
	Verbose bool `flag:"verbose" short:"v" help:"Show tunnel status updates"`
	Quiet   bool `flag:"quiet" short:"q" help:"Reduce tunnel status output"`
	Silent  bool `flag:"silent" short:"s" help:"Suppress tunnel status output"`
}

var rootRegistry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derpssh",
		Description: "Share an interactive terminal through DERP rendezvous and direct-path promotion.",
		Examples: []string{
			"derpssh share",
			"derpssh connect <invite>",
			"derpssh service set ops-shell <invite>",
			"derpssh version",
		},
	},
	SubCommands: map[string]yargs.CommandSpec{
		"share":   {Info: yargs.SubCommandInfo{Name: "share", Description: "Share a fresh host PTY."}},
		"connect": {Info: yargs.SubCommandInfo{Name: "connect", Description: "Connect to a derpssh invite."}},
		"service": {Info: yargs.SubCommandInfo{Name: "service", Description: "Manage local service-name lookup entries."}},
		"version": {Info: yargs.SubCommandInfo{Name: "version", Description: "Print the derpssh version."}},
	},
}

var rootHelpConfig = rootRegistry.HelpConfig()

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseKnownFlags[rootGlobalFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	level, err := rootTelemetryLevel(parsed.Flags)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	remaining := parsed.RemainingArgs
	if len(remaining) == 0 || isRootHelpRequest(remaining) {
		_, _ = fmt.Fprint(stderr, rootHelpText())
		return 0
	}
	if strings.HasPrefix(remaining[0], "-") {
		_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", remaining[0])
		_, _ = fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	if handler, ok := rootCommandHandlers()[remaining[0]]; ok {
		return handler(remaining[1:], level, stdin, stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "unknown command: %s\nRun 'derpssh --help' for usage\n", remaining[0])
	return 2
}

type rootCommandHandler func(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int

func rootCommandHandlers() map[string]rootCommandHandler {
	return map[string]rootCommandHandler{
		"share": func(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
			return runShare(args, level, stdin, stdout, stderr)
		},
		"connect": runConnect,
		"service": func(args []string, _ telemetry.Level, _ io.Reader, stdout, stderr io.Writer) int {
			return runService(args, stdout, stderr)
		},
		"version": func(_ []string, _ telemetry.Level, _ io.Reader, stdout, stderr io.Writer) int {
			return runVersion(stdout, stderr)
		},
	}
}

func rootHelpText() string {
	return yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{})
}

func isRootHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help")
}

func rootTelemetryLevel(flags rootGlobalFlags) (telemetry.Level, error) {
	count := 0
	level := telemetry.LevelDefault
	if flags.Verbose {
		count++
		level = telemetry.LevelVerbose
	}
	if flags.Quiet {
		count++
		level = telemetry.LevelQuiet
	}
	if flags.Silent {
		count++
		level = telemetry.LevelSilent
	}
	if count > 1 {
		return telemetry.LevelDefault, fmt.Errorf("only one of --verbose, --quiet, or --silent may be set")
	}
	return level, nil
}
