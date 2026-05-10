// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

func handleYargsError[S any, A any](parsed *yargs.TypedParseResult[struct{}, S, A], err error, stderr io.Writer, helpText func() string) (int, bool) {
	if err == nil {
		return 0, false
	}
	if yargsHelpRequested(err) {
		if parsed != nil && parsed.HelpText != "" {
			_, _ = fmt.Fprint(stderr, parsed.HelpText)
		} else {
			_, _ = fmt.Fprint(stderr, helpText())
		}
		return 0, true
	}
	_, _ = fmt.Fprintln(stderr, err)
	_, _ = fmt.Fprint(stderr, helpText())
	return 2, true
}

func yargsHelpRequested(err error) bool {
	return errors.Is(err, yargs.ErrHelp) || errors.Is(err, yargs.ErrSubCommandHelp) || errors.Is(err, yargs.ErrHelpLLM)
}
