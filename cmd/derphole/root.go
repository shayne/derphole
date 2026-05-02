package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type rootGlobalFlags struct {
	Verbose bool `flag:"verbose" short:"v" help:"Show relay status updates"`
	Quiet   bool `flag:"quiet" short:"q" help:"Reduce relay status output"`
	Silent  bool `flag:"silent" short:"s" help:"Suppress relay status output"`
}

var rootRegistry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Move text, files, directories, and SSH invites over derphole transport with wormhole-shaped commands.",
		Examples: []string{
			"derphole send ./photo.jpg",
			"derphole receive",
			"derphole listen",
			"cat file | derphole pipe <token>",
			"derphole share 127.0.0.1:3000",
			"derphole open <token>",
			"derphole ssh invite ~/.ssh/id_ed25519.pub",
			"derphole netcheck",
			"derphole version",
		},
	},
	SubCommands: map[string]yargs.CommandSpec{
		"send": {
			Info: yargs.SubCommandInfo{
				Name:        "send",
				Description: "Send text, a file, or a directory.",
			},
		},
		"receive": {
			Info: yargs.SubCommandInfo{
				Name:        "receive",
				Description: "Receive text, a file, or a directory.",
			},
		},
		"listen": {
			Info: yargs.SubCommandInfo{
				Name:        "listen",
				Description: "Listen for one incoming raw byte stream.",
			},
		},
		"pipe": {
			Info: yargs.SubCommandInfo{
				Name:        "pipe",
				Description: "Send stdin as one raw byte stream.",
			},
		},
		"share": {
			Info: yargs.SubCommandInfo{
				Name:        "share",
				Description: "Share a local TCP service until Ctrl-C.",
			},
		},
		"open": {
			Info: yargs.SubCommandInfo{
				Name:        "open",
				Description: "Open a shared service locally until Ctrl-C.",
			},
		},
		"ssh": {
			Info: yargs.SubCommandInfo{
				Name:        "ssh",
				Description: "Exchange SSH access invites.",
			},
		},
		"version": {
			Info: yargs.SubCommandInfo{
				Name:        "version",
				Description: "Print the derphole version.",
			},
		},
		"netcheck": {
			Info: yargs.SubCommandInfo{
				Name:        "netcheck",
				Description: "Check local direct UDP network capabilities.",
			},
		},
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
	if len(remaining) == 1 && remaining[0] == "--help-llm" {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelpLLM(rootHelpConfig, rootGlobalFlags{}))
		return 0
	}
	if strings.HasPrefix(remaining[0], "-") {
		fmt.Fprintf(stderr, "unknown flag: %s\n", remaining[0])
		fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	if remaining[0] == "help" {
		return runHelpCommand(remaining[1:], stderr)
	}

	switch canonicalRootCommand(remaining[0]) {
	case "send":
		return runSend(remaining[1:], level, stdin, stdout, stderr)
	case "receive":
		return runReceive(remaining[1:], level, stdin, stdout, stderr)
	case "listen":
		return runListen(remaining[1:], level, stdout, stderr)
	case "pipe":
		return runPipe(remaining[1:], level, stdin, stdout, stderr)
	case "share":
		return runShare(remaining[1:], level, stdout, stderr)
	case "open":
		return runOpen(remaining[1:], level, stdout, stderr)
	case "ssh":
		return runSSH(remaining[1:], level, stdin, stdout, stderr)
	case "version":
		return runVersion(stdout, stderr)
	case "netcheck":
		return runNetcheckCmd(remaining[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\nRun 'derphole --help' for usage\n", remaining[0])
		return 2
	}
}

func rootHelpText() string {
	return yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{})
}

func isRootHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help")
}

func canonicalRootCommand(name string) string {
	switch name {
	case "tx":
		return "send"
	case "rx", "recv", "recieve":
		return "receive"
	default:
		return name
	}
}

func runHelpCommand(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rootHelpText())
		return 0
	}

	switch canonicalRootCommand(args[0]) {
	case "send":
		fmt.Fprint(stderr, sendHelpText())
		return 0
	case "receive":
		fmt.Fprint(stderr, receiveHelpText())
		return 0
	case "listen":
		fmt.Fprint(stderr, listenHelpText())
		return 0
	case "pipe":
		fmt.Fprint(stderr, pipeHelpText())
		return 0
	case "share":
		fmt.Fprint(stderr, shareHelpText())
		return 0
	case "open":
		fmt.Fprint(stderr, openHelpText())
		return 0
	case "ssh":
		fmt.Fprint(stderr, sshHelpText())
		return 0
	case "version":
		fmt.Fprint(stderr, versionHelpText())
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\nRun 'derphole --help' for usage\n", args[0])
		return 2
	}
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
