// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
)

var errUsage = errors.New("usage")

type options struct {
	Role          string
	ExpectedBytes int64
	StallWindow   time.Duration
	Path          string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, errUsage) {
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "transfertracecheck: %v\n", err)
		return 1
	}

	result, err := checkPath(opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "transfertracecheck: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "trace-ok rows=%d final_app_bytes=%d max_flatline=%s\n", result.Rows, result.FinalAppBytes, result.MaxFlatline)
	return 0
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var role string
	var expectedBytes int64
	var stallWindow time.Duration
	flags := flag.NewFlagSet("transfertracecheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&role, "role", "", "trace role to check")
	flags.Int64Var(&expectedBytes, "expected-bytes", 0, "expected final app byte count")
	flags.DurationVar(&stallWindow, "stall-window", time.Second, "maximum active-phase app byte stall")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: transfertracecheck -role receive [-expected-bytes N] trace.csv")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return options{}, errUsage
	}
	if role == "" || flags.NArg() != 1 {
		flags.Usage()
		return options{}, errUsage
	}
	if role != string(transfertrace.RoleSend) && role != string(transfertrace.RoleReceive) {
		_, _ = fmt.Fprintln(stderr, "role must be send or receive")
		flags.Usage()
		return options{}, errUsage
	}
	return options{
		Role:          role,
		ExpectedBytes: expectedBytes,
		StallWindow:   stallWindow,
		Path:          flags.Arg(0),
	}, nil
}

func checkPath(opts options) (transfertrace.Result, error) {
	f, err := os.Open(opts.Path)
	if err != nil {
		return transfertrace.Result{}, fmt.Errorf("open %s: %w", opts.Path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	return transfertrace.Check(f, transfertrace.Options{
		Role:          transfertrace.Role(opts.Role),
		ExpectedBytes: opts.ExpectedBytes,
		StallWindow:   opts.StallWindow,
	})
}
