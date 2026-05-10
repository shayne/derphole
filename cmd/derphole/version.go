// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func versionString() string {
	_, _ = commit, buildDate
	return version
}

func runVersion(stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, versionString())
	_ = stderr
	return 0
}

func versionHelpText() string {
	return yargs.GenerateSubCommandHelp(rootHelpConfig, "version", rootGlobalFlags{}, struct{}{}, struct{}{})
}
