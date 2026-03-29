package main

import (
	"fmt"
	"io"
	"reflect"
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

type rootFlagSpec struct {
	name  string
	short string
	kind  reflect.Kind
}

type rootFlagActivation struct {
	active bool
	order  int
}

var rootGlobalFlagSpecs = deriveRootGlobalFlagSpecs()

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
	state := newRootVerbosityState()
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
	flags []rootFlagActivation
}

func newRootVerbosityState() rootVerbosityState {
	return rootVerbosityState{flags: make([]rootFlagActivation, len(rootGlobalFlagSpecs))}
}

func (s *rootVerbosityState) applyArg(arg string, order int) (bool, error) {
	for i, spec := range rootGlobalFlagSpecs {
		matched, value, err := spec.matchBoolArg(arg)
		if !matched {
			continue
		}
		if err != nil {
			return true, err
		}
		s.flags[i].active = value
		s.flags[i].order = order
		return true, nil
	}

	return false, nil
}

func (s rootVerbosityState) level() telemetry.Level {
	level := telemetry.LevelDefault
	order := -1

	for i, flag := range s.flags {
		if !flag.active || flag.order < order {
			continue
		}
		switch i {
		case 0:
			level = telemetry.LevelVerbose
		case 1:
			level = telemetry.LevelQuiet
		case 2:
			level = telemetry.LevelSilent
		}
		order = flag.order
	}

	return level
}

func deriveRootGlobalFlagSpecs() []rootFlagSpec {
	t := reflect.TypeOf(rootGlobalFlags{})
	specs := make([]rootFlagSpec, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := field.Tag.Get("flag")
		if name == "" {
			name = strings.ToLower(field.Name)
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}
		specs = append(specs, rootFlagSpec{
			name:  name,
			short: field.Tag.Get("short"),
			kind:  fieldType.Kind(),
		})
	}
	return specs
}

func (spec rootFlagSpec) matchBoolArg(arg string) (matched bool, value bool, err error) {
	if spec.kind != reflect.Bool {
		return false, false, nil
	}

	for _, candidate := range spec.syntax() {
		if arg == candidate {
			return true, true, nil
		}
		if strings.HasPrefix(arg, candidate+"=") {
			raw := strings.TrimPrefix(arg, candidate+"=")
			parsed, parseErr := strconv.ParseBool(raw)
			if parseErr != nil {
				return true, false, fmt.Errorf("invalid boolean value %q for %s", raw, candidate)
			}
			return true, parsed, nil
		}
	}

	return false, false, nil
}

func (spec rootFlagSpec) syntax() []string {
	syntax := []string{"--" + spec.name}
	if spec.short != "" {
		syntax = append([]string{"-" + spec.short}, syntax...)
	}
	return syntax
}

func rewriteRootHelpArgs(args []string) ([]string, bool) {
	if len(args) < 2 || args[0] != "help" {
		return args, false
	}

	if args[1] == "listen" {
		if len(args) == 2 {
			return []string{"listen", "--help"}, false
		}
		helpLLM, help := listenRequestedHelp(args[2:])
		if helpLLM || help {
			return append([]string{"listen"}, args[2:]...), false
		}
		return args, true
	}

	if len(args) == 3 && args[1] == "version" && args[2] == "--help-llm" {
		return []string{"version", "--help-llm"}, false
	}

	if len(args) == 3 && args[1] == "version" && args[2] == "--help" {
		return []string{"version", "--help"}, false
	}

	if len(args) == 3 && (args[2] == "--help" || args[2] == "--help-llm") {
		return []string{args[1], args[2]}, false
	}

	if len(args) > 2 {
		return args, true
	}

	return []string{args[1], "--help"}, false
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--help-llm" {
		fmt.Fprint(stderr, yargs.GenerateSubCommandHelpLLMFromConfig(rootHelpConfig, "version", rootGlobalFlags{}))
		return 0
	}

	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(stderr, versionUsage)
		return 0
	}

	if len(args) != 0 {
		fmt.Fprintln(stderr, versionUsage)
		return 2
	}

	fmt.Fprintln(stdout, versionString())
	return 0
}
