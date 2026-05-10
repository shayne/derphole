// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shayne/derphole/pkg/netcheck"
	"github.com/shayne/yargs"
)

var runNetcheck = netcheck.Run

type netcheckFlags struct {
	JSON    bool   `flag:"json" help:"Print JSON output"`
	Timeout string `flag:"timeout" help:"Total diagnostic timeout" default:"5s"`
}

func runNetcheckCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, _ = fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return 0
	}
	flags, code, failed := parseNetcheckFlags(args, stderr)
	if failed {
		return code
	}
	report, err := runNetcheck(context.Background(), netcheck.Config{Timeout: flags.timeout})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return writeNetcheckReport(stdout, stderr, report, flags.json)
}

type parsedNetcheckFlags struct {
	json    bool
	timeout time.Duration
}

func parseNetcheckFlags(args []string, stderr io.Writer) (parsedNetcheckFlags, int, bool) {
	parsed, err := yargs.ParseKnownFlags[netcheckFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return parsedNetcheckFlags{}, 2, true
	}
	if len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return parsedNetcheckFlags{}, 2, true
	}
	flags := parsed.Flags
	timeout, err := time.ParseDuration(strings.TrimSpace(flags.Timeout))
	if err != nil || timeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "timeout must be a positive duration")
		_, _ = fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return parsedNetcheckFlags{}, 2, true
	}
	return parsedNetcheckFlags{json: flags.JSON, timeout: timeout}, 0, false
}

func writeNetcheckReport(stdout, stderr io.Writer, report netcheck.Report, asJSON bool) int {
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	_, _ = fmt.Fprint(stderr, netcheck.FormatHuman(report))
	return 0
}
