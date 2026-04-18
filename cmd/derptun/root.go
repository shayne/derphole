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
		Name:        "derptun",
		Description: "Open durable TCP tunnels through DERP rendezvous and direct UDP promotion.",
		Examples: []string{
			"derptun token server > server.dts",
			"derptun token client --token \"$(cat server.dts)\" > client.dtc",
			"derptun serve --token \"$(cat server.dts)\" --tcp 127.0.0.1:22",
			"derptun open --token \"$(cat client.dtc)\" --listen 127.0.0.1:2222",
			"ssh -o ProxyCommand='derptun connect --token ~/.config/derptun/client.dtc --stdio' foo@serverhost",
		},
	},
	SubCommands: map[string]yargs.CommandSpec{
		"token":   {Info: yargs.SubCommandInfo{Name: "token", Description: "Generate server credentials or client access tokens."}},
		"serve":   {Info: yargs.SubCommandInfo{Name: "serve", Description: "Serve a local TCP target using a server token."}},
		"open":    {Info: yargs.SubCommandInfo{Name: "open", Description: "Open a local TCP listener using a client token."}},
		"connect": {Info: yargs.SubCommandInfo{Name: "connect", Description: "Connect one client tunnel stream over stdin/stdout."}},
		"version": {Info: yargs.SubCommandInfo{Name: "version", Description: "Print the derptun version."}},
	},
}

var rootHelpConfig = rootRegistry.HelpConfig()

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseKnownFlags[rootGlobalFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	level, err := rootTelemetryLevel(parsed.Flags)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	remaining := parsed.RemainingArgs
	if len(remaining) == 0 || isRootHelpRequest(remaining) {
		fmt.Fprint(stderr, rootHelpText())
		return 0
	}
	if strings.HasPrefix(remaining[0], "-") {
		fmt.Fprintf(stderr, "unknown flag: %s\n", remaining[0])
		fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	switch remaining[0] {
	case "token":
		return runToken(remaining[1:], stdout, stderr)
	case "serve":
		return runServe(remaining[1:], level, stderr)
	case "open":
		return runOpen(remaining[1:], level, stderr)
	case "connect":
		return runConnect(remaining[1:], level, stdin, stdout, stderr)
	case "version":
		return runVersion(stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\nRun 'derptun --help' for usage\n", remaining[0])
		return 2
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
