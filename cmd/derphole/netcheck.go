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
		fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return 0
	}
	parsed, err := yargs.ParseKnownFlags[netcheckFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return 2
	}
	flags := parsed.Flags
	timeout, err := time.ParseDuration(strings.TrimSpace(flags.Timeout))
	if err != nil || timeout <= 0 {
		fmt.Fprintln(stderr, "timeout must be a positive duration")
		fmt.Fprint(stderr, "usage: derphole netcheck\n")
		return 2
	}
	report, err := runNetcheck(context.Background(), netcheck.Config{Timeout: timeout})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if flags.JSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprint(stderr, netcheck.FormatHuman(report))
	return 0
}
