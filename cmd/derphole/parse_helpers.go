// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/yargs"
)

func handleYargsError[S any, A any](parsed *yargs.TypedParseResult[struct{}, S, A], err error, stderr io.Writer, helpText func() string, helpLLM func() string) (int, bool) {
	if err == nil {
		return 0, false
	}
	if yargsHelpRequested(err) {
		writeYargsHelp(parsed, err, stderr, helpText, helpLLM)
		return 0, true
	}
	_, _ = fmt.Fprintln(stderr, err)
	_, _ = fmt.Fprint(stderr, helpText())
	return 2, true
}

func yargsHelpRequested(err error) bool {
	return errors.Is(err, yargs.ErrHelp) || errors.Is(err, yargs.ErrSubCommandHelp) || errors.Is(err, yargs.ErrHelpLLM)
}

func writeYargsHelp[S any, A any](parsed *yargs.TypedParseResult[struct{}, S, A], err error, stderr io.Writer, helpText func() string, helpLLM func() string) {
	switch {
	case parsed != nil && parsed.HelpText != "":
		_, _ = fmt.Fprint(stderr, parsed.HelpText)
	case errors.Is(err, yargs.ErrHelpLLM) && helpLLM != nil:
		_, _ = fmt.Fprint(stderr, helpLLM())
	default:
		_, _ = fmt.Fprint(stderr, helpText())
	}
}

func parseParallelPolicy(value string, stderr io.Writer, helpText func() string) (session.ParallelPolicy, int, bool) {
	policy := session.DefaultParallelPolicy()
	if value == "" {
		return policy, 0, false
	}
	policy, err := session.ParseParallelPolicy(value)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, helpText())
		return session.ParallelPolicy{}, 2, true
	}
	return policy, 0, false
}
