package main

import (
	"flag"
	"fmt"
	"io"
	"strconv"
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
	level, commandArgs, err := parseRootArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		return 2
	}

	remaining, malformedHelp := rewriteRootHelpArgs(commandArgs)
	if len(remaining) == 0 {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		return 2
	}
	if malformedHelp {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{}))
		return 2
	}
	if isRootHelpLLMRequest(remaining) {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelpLLM(rootHelpConfig, rootGlobalFlags{}))
		return 0
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

func isRootHelpLLMRequest(args []string) bool {
	return len(args) > 0 && args[0] == "--help-llm"
}

func parseRootArgs(args []string) (telemetry.Level, []string, error) {
	level := telemetry.LevelDefault
	for i, arg := range args {
		if isRootHelpToken(arg) {
			return level, args[i:], nil
		}
		if nextLevel, ok, err := parseRootGlobalArg(arg, level); ok {
			if err != nil {
				return telemetry.LevelDefault, nil, err
			}
			level = nextLevel
			continue
		} else if strings.HasPrefix(arg, "-") {
			return telemetry.LevelDefault, nil, fmt.Errorf("flag provided but not defined: %s", arg)
		} else {
			return level, args[i:], nil
		}
	}
	return level, nil, nil
}

func isRootHelpToken(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "--help-llm" || arg == "help"
}

func parseRootGlobalArg(arg string, current telemetry.Level) (telemetry.Level, bool, error) {
	apply := func(next telemetry.Level, ok bool) telemetry.Level {
		if ok {
			return next
		}
		return current
	}

	switch arg {
	case "-v", "--verbose":
		return telemetry.LevelVerbose, true, nil
	case "-q", "--quiet":
		return telemetry.LevelQuiet, true, nil
	case "-s", "--silent":
		return telemetry.LevelSilent, true, nil
	}

	for _, spec := range []struct {
		prefix string
		level  telemetry.Level
	}{
		{prefix: "-v=", level: telemetry.LevelVerbose},
		{prefix: "--verbose=", level: telemetry.LevelVerbose},
		{prefix: "-q=", level: telemetry.LevelQuiet},
		{prefix: "--quiet=", level: telemetry.LevelQuiet},
		{prefix: "-s=", level: telemetry.LevelSilent},
		{prefix: "--silent=", level: telemetry.LevelSilent},
	} {
		if strings.HasPrefix(arg, spec.prefix) {
			value := strings.TrimPrefix(arg, spec.prefix)
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return current, true, fmt.Errorf("invalid boolean value %q for %s", value, strings.TrimSuffix(spec.prefix, "="))
			}
			return apply(spec.level, parsed), true, nil
		}
	}

	return current, false, nil
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

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--help-llm" {
		fmt.Fprint(stderr, yargs.GenerateSubCommandHelpLLMFromConfig(rootHelpConfig, "version", rootGlobalFlags{}))
		return 0
	}

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
