// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/telemetry"
)

func runConnect(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	_, _, _ = level, stdin, stdout
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		_, _ = fmt.Fprintln(stderr, "Usage: derpssh connect [--name NAME] <invite>")
		return 0
	}
	_, _ = fmt.Fprintln(stderr, "derpssh connect is not wired yet")
	return 1
}
