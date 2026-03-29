package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/yargs"
)

type listenFlags struct {
	PrintTokenOnly bool   `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool   `flag:"force-relay" help:"Disable direct probing"`
	TCPListen      string `flag:"tcp-listen" help:"Accept one local TCP connection and forward its bytes to the session sink"`
	TCPConnect     string `flag:"tcp-connect" help:"Connect to a local TCP service and forward session bytes to it"`
}

var listenHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derpcat",
		Description: "Move one byte stream between hosts over public DERP with direct UDP promotion when available.",
		Examples: []string{
			"derpcat listen",
			"cat file | derpcat send <token>",
			"derpcat version",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"listen": {
			Name:        "listen",
			Description: "Listen for one incoming derpcat session and receive data.",
			Usage:       "[--print-token-only] [--tcp-listen addr | --tcp-connect addr] [--force-relay]",
			Examples: []string{
				"derpcat listen",
				"derpcat listen --tcp-connect 127.0.0.1:9000",
			},
		},
	},
}

var listenFlagKinds = deriveListenFlagKinds()

func runListen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	preScan := listenPreScan(args)
	if preScan.unknownFlagAfterLateBoundary {
		fmt.Fprintln(stderr, "unknown flag:", preScan.unknownFlag)
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}
	if preScan.positionalBeforeLateFlag {
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}
	if preScan.positionalAfterDoubleDash {
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	if preScan.helpLLM || preScan.help {
		if preScan.helpLLM {
			fmt.Fprint(stderr, listenHelpLLMText())
		} else {
			fmt.Fprint(stderr, listenHelpText())
		}
		return 0
	}

	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, listenFlags, struct{}](append([]string{"listen"}, preScan.parseArgs...), listenHelpConfig)
	if err != nil {
		if errors.Is(err, yargs.ErrHelp) || errors.Is(err, yargs.ErrSubCommandHelp) || errors.Is(err, yargs.ErrHelpLLM) {
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else if errors.Is(err, yargs.ErrHelpLLM) {
				fmt.Fprint(stderr, listenHelpLLMText())
			} else {
				fmt.Fprint(stderr, listenHelpText())
			}
			return 0
		}
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	if len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, listenHelpText())
		return 2
	}

	if parsed.SubCommandFlags.TCPListen != "" && parsed.SubCommandFlags.TCPConnect != "" {
		fmt.Fprintln(stderr, "listen: --tcp-listen and --tcp-connect are mutually exclusive")
		return 2
	}

	emitter := telemetry.New(stderr, level)
	tokenSink := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := session.Listen(context.Background(), session.ListenConfig{
			Emitter:       emitter,
			TokenSink:     tokenSink,
			StdioOut:      stdout,
			Attachment:    nil,
			TCPListen:     parsed.SubCommandFlags.TCPListen,
			TCPConnect:    parsed.SubCommandFlags.TCPConnect,
			ForceRelay:    parsed.SubCommandFlags.ForceRelay,
			UsePublicDERP: usePublicDERPTransport(),
		})
		done <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case err := <-done:
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if tok == "" {
		fmt.Fprintln(stderr, "failed to issue session token")
		return 1
	}

	tokenOut := stderr
	if parsed.SubCommandFlags.PrintTokenOnly {
		tokenOut = stdout
	}
	fmt.Fprintln(tokenOut, tok)

	if err := <-done; err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func listenHelpText() string {
	return yargs.GenerateSubCommandHelp(
		listenHelpConfig,
		"listen",
		struct{}{},
		listenFlags{},
		struct{}{},
	)
}

func listenHelpLLMText() string {
	return yargs.GenerateSubCommandHelpLLM(
		listenHelpConfig,
		"listen",
		struct{}{},
		listenFlags{},
		struct{}{},
	)
}

type listenPreScanResult struct {
	help                         bool
	helpLLM                      bool
	positionalBeforeLateFlag     bool
	positionalAfterDoubleDash    bool
	unknownFlagAfterLateBoundary bool
	unknownFlag                  string
	parseArgs                    []string
}

func listenPreScan(args []string) listenPreScanResult {
	result := listenPreScanResult{parseArgs: make([]string, 0, len(args))}
	sawPositional := false
	sawUnknownFlag := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if sawUnknownFlag {
				result.unknownFlagAfterLateBoundary = true
				result.parseArgs = append(result.parseArgs, args[i+1:]...)
				return result
			}
			result.parseArgs = append(result.parseArgs, arg)
			for j := i + 1; j < len(args); j++ {
				result.parseArgs = append(result.parseArgs, args[j])
			}
			if i+1 < len(args) {
				result.positionalAfterDoubleDash = true
			}
			return result
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if sawUnknownFlag {
				result.unknownFlagAfterLateBoundary = true
			}
			sawPositional = true
			result.parseArgs = append(result.parseArgs, arg)
			continue
		}
		if sawPositional && !sawUnknownFlag {
			result.positionalBeforeLateFlag = true
			return result
		}

		flagName := listenFlagName(arg)
		kind, ok := listenFlagKinds[flagName]
		if ok && kind != reflect.Bool && !strings.Contains(arg, "=") {
			if i+1 < len(args) {
				result.parseArgs = append(result.parseArgs, arg+"="+args[i+1])
				i++
			} else {
				result.parseArgs = append(result.parseArgs, arg)
			}
			continue
		}

		switch {
		case arg == "--help-llm":
			if !sawUnknownFlag {
				result.helpLLM = true
				return result
			}
			continue
		case listenParserHelpToken(arg):
			if !sawUnknownFlag {
				result.help = true
				return result
			}
			continue
		}
		if !ok {
			sawUnknownFlag = true
			if result.unknownFlag == "" {
				result.unknownFlag = arg
			}
		}
		result.parseArgs = append(result.parseArgs, arg)
	}
	return result
}

func listenRequestedHelp(args []string) (helpLLM bool, help bool) {
	preScan := listenPreScan(args)
	return preScan.helpLLM, preScan.help
}

func listenParserHelpToken(arg string) bool {
	switch arg {
	case "-h", "--help", "-help", "-h=false", "--help=false", "-help=true", "--help=true", "--help=0":
		return true
	default:
		return false
	}
}

func deriveListenFlagKinds() map[string]reflect.Kind {
	t := reflect.TypeOf(listenFlags{})
	kinds := make(map[string]reflect.Kind, t.NumField()+2)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		flagName := field.Tag.Get("flag")
		if flagName == "" {
			flagName = strings.ToLower(field.Name)
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}
		kinds[flagName] = fieldType.Kind()
	}
	kinds["h"] = reflect.Bool
	kinds["help"] = reflect.Bool
	kinds["help-llm"] = reflect.Bool
	return kinds
}

func listenFlagName(arg string) string {
	flagName := strings.TrimLeft(arg, "-")
	if idx := strings.Index(flagName, "="); idx > 0 {
		return flagName[:idx]
	}
	return flagName
}
