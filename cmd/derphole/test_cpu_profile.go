// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"runtime/pprof"
	"strings"
)

const derpholeTestCPUProfileEnv = "DERPHOLE_TEST_CPU_PROFILE"

func startDerpholeTestCPUProfile(path string) (func() error, error) {
	if strings.TrimSpace(path) == "" {
		return func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() error {
		pprof.StopCPUProfile()
		return file.Close()
	}, nil
}
