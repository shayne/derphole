// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux

package main

import (
	"os"
	"runtime"
	"syscall"
)

func maxRSSBytes(state *os.ProcessState) (uint64, bool) {
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss < 0 {
		return 0, false
	}
	value := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		value *= 1024
	}
	return value, true
}

func forwardedSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
