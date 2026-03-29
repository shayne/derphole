package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/yargs"
)

type rootGlobalFlags struct {
	Verbose bool `flag:"verbose" short:"v" help:"Show relay status updates"`
	Quiet   bool `flag:"quiet" short:"q" help:"Reduce relay status output"`
	Silent  bool `flag:"silent" short:"s" help:"Suppress relay status output"`
}

const versionUsage = "usage: derpcat version"

var rootRegistry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derpcat",
		Description: "Relay payloads through a public DERP server or a private listener.",
		Examples: []string{
			"derpcat listen",
			"derpcat send <token>",
			"derpcat version",
		},
	},
	SubCommands: map[string]yargs.CommandSpec{
		"listen": {
			Info: yargs.SubCommandInfo{
				Name:        "listen",
				Description: "Listen for a claim token and stream payloads to stdout.",
			},
		},
		"send": {
			Info: yargs.SubCommandInfo{
				Name:        "send",
				Description: "Claim a token and stream stdin to a relay listener.",
			},
		},
		"version": {
			Info: yargs.SubCommandInfo{
				Name:        "version",
				Description: "Print the derpcat version.",
			},
		},
	},
}

var rootHelpConfig = rootRegistry.HelpConfig()

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseKnownFlags[rootGlobalFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	level := rootTelemetryLevel(parsed.Flags)

	remaining, malformedHelp := rewriteRootHelpArgs(parsed.RemainingArgs)
	if len(remaining) == 0 {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		return 2
	}
	if malformedHelp {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		return 2
	}
	if isRootHelpRequest(remaining) {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		return 0
	}

	resolved, ok, err := yargs.ResolveCommandWithRegistry(remaining, rootRegistry)
	if err != nil || !ok {
		if len(remaining) > 0 && strings.HasPrefix(remaining[0], "-") {
			fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
			return 2
		}
		if len(remaining) > 0 {
			fmt.Fprintf(stderr, "unknown subcommand %q\n", remaining[0])
		} else {
			fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		}
		return 2
	}

	switch resolved.Path[0] {
	case "listen":
		return runListen(resolved.Args, level, stdout, stderr)
	case "send":
		return runSend(resolved.Args, level, stdin, stdout, stderr)
	case "version":
		return runVersion(resolved.Args, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", resolved.Path[0])
		return 2
	}
}

func isRootHelpRequest(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return args[0] == "-h" || args[0] == "--help" || (args[0] == "help" && len(args) == 1)
}

func rewriteRootHelpArgs(args []string) ([]string, bool) {
	if len(args) < 2 || args[0] != "help" {
		return args, false
	}

	if len(args) > 2 {
		return args, true
	}

	return []string{args[1], "--help"}, false
}

func rootTelemetryLevel(flags rootGlobalFlags) telemetry.Level {
	switch {
	case flags.Silent:
		return telemetry.LevelSilent
	case flags.Quiet:
		return telemetry.LevelQuiet
	case flags.Verbose:
		return telemetry.LevelVerbose
	default:
		return telemetry.LevelDefault
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, versionUsage)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}

	fmt.Fprintln(stdout, versionString())
	return 0
}
