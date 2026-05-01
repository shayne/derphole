package main

import (
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

var registry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derphole-probe",
		Description: "Experimental direct UDP benchmark probe.",
	},
	SubCommands: map[string]yargs.CommandSpec{
		"server": {
			Info: yargs.SubCommandInfo{
				Name:        "server",
				Description: "Run remote server mode.",
			},
		},
		"client": {
			Info: yargs.SubCommandInfo{
				Name:        "client",
				Description: "Run local client mode.",
			},
		},
		"orchestrate": {
			Info: yargs.SubCommandInfo{
				Name:        "orchestrate",
				Description: "Run end-to-end proof benchmark.",
			},
		},
		"matrix": {
			Info: yargs.SubCommandInfo{
				Name:        "matrix",
				Description: "Run the production promotion benchmark matrix.",
			},
		},
		"topology": {
			Info: yargs.SubCommandInfo{
				Name:        "topology",
				Description: "Diagnose direct UDP topology between this host and an SSH target.",
			},
		},
	},
}

var helpConfig = registry.HelpConfig()

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(helpConfig, struct{}{}))
		return 0
	}

	switch args[0] {
	case "help":
		return runHelp(args[1:], stderr)
	case "server":
		return runServer(args[1:], stdout, stderr)
	case "client":
		return runClient(args[1:], stdout, stderr)
	case "orchestrate":
		return runOrchestrate(args[1:], stdout, stderr)
	case "matrix":
		return runMatrixCmd(args[1:], stdout, stderr)
	case "topology":
		return runTopology(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}

func isRootHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help")
}

func runHelp(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(helpConfig, struct{}{}))
		return 0
	}

	switch args[0] {
	case "server", "client", "orchestrate", "matrix", "topology":
		fmt.Fprint(stderr, subcommandUsageLine(args[0]))
		if len(args) > 1 {
			return 2
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}

func subcommandUsageLine(name string) string {
	return fmt.Sprintf("usage: derphole-probe %s\n", name)
}
