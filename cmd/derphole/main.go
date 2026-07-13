// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	stopProfile, err := startDerpholeTestCPUProfile(os.Getenv(derpholeTestCPUProfileEnv))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "derphole: start test CPU profile: %v\n", err)
		return 1
	}
	code := run(args, stdin, stdout, stderr)
	if err := stopProfile(); err != nil {
		_, _ = fmt.Fprintf(stderr, "derphole: close test CPU profile: %v\n", err)
		return 1
	}
	return code
}
