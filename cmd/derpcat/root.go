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
	state := rootVerbosityState{}
	for i, arg := range args {
		if isRootHelpToken(arg) {
			return state.level(), args[i:], nil
		}
		if ok, err := state.applyArg(arg, i); ok {
			if err != nil {
				return telemetry.LevelDefault, nil, err
			}
			continue
		} else if strings.HasPrefix(arg, "-") {
			return telemetry.LevelDefault, nil, fmt.Errorf("flag provided but not defined: %s", arg)
		} else {
			return state.level(), args[i:], nil
		}
	}
	return state.level(), nil, nil
}

func isRootHelpToken(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "--help-llm" || arg == "help"
}

type rootVerbosityState struct {
	verboseActive bool
	verboseOrder  int
	quietActive   bool
	quietOrder    int
	silentActive  bool
	silentOrder   int
}

func (s *rootVerbosityState) applyArg(arg string, order int) (bool, error) {
	switch arg {
	case "-v", "--verbose":
		s.verboseActive = true
		s.verboseOrder = order
		return true, nil
	case "-q", "--quiet":
		s.quietActive = true
		s.quietOrder = order
		return true, nil
	case "-s", "--silent":
		s.silentActive = true
		s.silentOrder = order
		return true, nil
	}

	for _, spec := range []struct {
		prefix string
		set    func()
		clear  func()
	}{
		{prefix: "-v=", set: func() { s.verboseActive = true; s.verboseOrder = order }, clear: func() { s.verboseActive = false }},
		{prefix: "--verbose=", set: func() { s.verboseActive = true; s.verboseOrder = order }, clear: func() { s.verboseActive = false }},
		{prefix: "-q=", set: func() { s.quietActive = true; s.quietOrder = order }, clear: func() { s.quietActive = false }},
		{prefix: "--quiet=", set: func() { s.quietActive = true; s.quietOrder = order }, clear: func() { s.quietActive = false }},
		{prefix: "-s=", set: func() { s.silentActive = true; s.silentOrder = order }, clear: func() { s.silentActive = false }},
		{prefix: "--silent=", set: func() { s.silentActive = true; s.silentOrder = order }, clear: func() { s.silentActive = false }},
	} {
		if strings.HasPrefix(arg, spec.prefix) {
			value := strings.TrimPrefix(arg, spec.prefix)
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return true, fmt.Errorf("invalid boolean value %q for %s", value, strings.TrimSuffix(spec.prefix, "="))
			}
			if parsed {
				spec.set()
			} else {
				spec.clear()
			}
			return true, nil
		}
	}

	return false, nil
}

func (s rootVerbosityState) level() telemetry.Level {
	level := telemetry.LevelDefault
	order := -1

	if s.verboseActive && s.verboseOrder >= order {
		level = telemetry.LevelVerbose
		order = s.verboseOrder
	}
	if s.quietActive && s.quietOrder >= order {
		level = telemetry.LevelQuiet
		order = s.quietOrder
	}
	if s.silentActive && s.silentOrder >= order {
		level = telemetry.LevelSilent
	}

	return level
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
