// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/yargs"
)

type tokenCommonFlags struct {
	Days    int    `flag:"days" help:"Token lifetime in days; server default is 180 days"`
	Expires string `flag:"expires" help:"Absolute expiry as RFC3339 or YYYY-MM-DD"`
}

type tokenClientFlags struct {
	Token      string `flag:"token" help:"Server token used to mint a client token"`
	TokenFile  string `flag:"token-file" help:"Read the server token from a file"`
	TokenStdin bool   `flag:"token-stdin" help:"Read the server token from the first stdin line"`
	Days       int    `flag:"days" help:"Token lifetime in days; client default is 90 days"`
	Expires    string `flag:"expires" help:"Absolute expiry as RFC3339 or YYYY-MM-DD"`
}

var tokenHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Generate derptun server and client tokens.",
		Examples: []string{
			"derptun token server",
			"derptun token client --token-file server.dts",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"token": {
			Name:        "token",
			Description: "Generate a server credential or client access token.",
			Usage:       "server [--days N|--expires DATE] | client (--token TOKEN|--token-file PATH|--token-stdin) [--days N|--expires DATE]",
			Examples: []string{
				"derptun token server",
				"derptun token client --token-file server.dts",
				"printf '%s\\n' \"$DERPTUN_SERVER_TOKEN\" | derptun token client --token-stdin",
			},
		},
	},
}

func runToken(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, tokenHelpText())
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "server":
		return runTokenServer(args[1:], stdout, stderr)
	case "client":
		return runTokenClient(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprint(stderr, tokenHelpText())
		return 2
	}
}

func runTokenServer(args []string, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, tokenCommonFlags, struct{}](append([]string{"server"}, args...), tokenHelpConfig)
	if err != nil {
		return handleTokenParseError(parsed, err, stderr)
	}
	if len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, tokenHelpText())
		return 2
	}
	expires, ok := parseOptionalTokenExpires(parsed.SubCommandFlags.Expires, stderr)
	if !ok {
		fmt.Fprint(stderr, tokenHelpText())
		return 2
	}
	tokenValue, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Days: parsed.SubCommandFlags.Days, Expires: expires})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, tokenValue)
	return 0
}

func runTokenClient(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, tokenClientFlags, struct{}](append([]string{"client"}, args...), tokenHelpConfig)
	if err != nil {
		return handleTokenParseError(parsed, err, stderr)
	}
	if len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, tokenHelpText())
		return 2
	}
	serverToken, _, err := resolveTokenSource(stdin, tokenSource{
		Token:      parsed.SubCommandFlags.Token,
		TokenFile:  parsed.SubCommandFlags.TokenFile,
		TokenStdin: parsed.SubCommandFlags.TokenStdin,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, tokenHelpText())
		return 2
	}
	expires, ok := parseOptionalTokenExpires(parsed.SubCommandFlags.Expires, stderr)
	if !ok {
		fmt.Fprint(stderr, tokenHelpText())
		return 2
	}
	tokenValue, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		ServerToken: serverToken,
		Days:        parsed.SubCommandFlags.Days,
		Expires:     expires,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, tokenValue)
	return 0
}

func handleTokenParseError[S any](parsed *yargs.TypedParseResult[struct{}, S, struct{}], err error, stderr io.Writer) int {
	if errors.Is(err, yargs.ErrHelp) || errors.Is(err, yargs.ErrSubCommandHelp) || errors.Is(err, yargs.ErrHelpLLM) {
		if parsed != nil && parsed.HelpText != "" {
			fmt.Fprint(stderr, parsed.HelpText)
		} else {
			fmt.Fprint(stderr, tokenHelpText())
		}
		return 0
	}
	fmt.Fprintln(stderr, err)
	fmt.Fprint(stderr, tokenHelpText())
	return 2
}

func parseOptionalTokenExpires(value string, stderr io.Writer) (time.Time, bool) {
	if value == "" {
		return time.Time{}, true
	}
	expires, err := parseTokenExpires(value)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return time.Time{}, false
	}
	return expires, true
}

func parseTokenExpires(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	t, err := time.ParseInLocation("2006-01-02", value, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --expires value %q; use RFC3339 or YYYY-MM-DD", value)
	}
	return t, nil
}

func tokenHelpText() string {
	return yargs.GenerateSubCommandHelp(tokenHelpConfig, "token", struct{}{}, tokenCommonFlags{}, struct{}{})
}
