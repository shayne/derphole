// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

var registry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derphole-probe",
		Description: "Production benchmark and UDP topology diagnostics.",
	},
	SubCommands: map[string]yargs.CommandSpec{
		"matrix": {
			Info: yargs.SubCommandInfo{
				Name:        "matrix",
				Description: "Run the production promotion benchmark matrix.",
			},
		},
		"topology": {
			Info: yargs.SubCommandInfo{
				Name:        "topology",
				Description: "Diagnose UDP direct-path topology between this host and an SSH target.",
			},
		},
	},
}

var helpConfig = registry.HelpConfig()

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		_, _ = fmt.Fprint(stderr, yargs.GenerateGlobalHelp(helpConfig, struct{}{}))
		return 0
	}

	switch args[0] {
	case "help":
		return runHelp(args[1:], stderr)
	case "matrix":
		return runMatrixCmd(args[1:], stdout, stderr)
	case "topology":
		return runTopology(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}

func isRootHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help")
}

func runHelp(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, yargs.GenerateGlobalHelp(helpConfig, struct{}{}))
		return 0
	}

	switch args[0] {
	case "matrix", "topology":
		_, _ = fmt.Fprint(stderr, subcommandUsageLine(args[0]))
		if len(args) > 1 {
			return 2
		}
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}

func subcommandUsageLine(name string) string {
	return fmt.Sprintf("usage: derphole-probe %s\n", name)
}
