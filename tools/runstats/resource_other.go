// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin && !linux

package main

import "os"

func maxRSSBytes(*os.ProcessState) (uint64, bool) {
	return 0, false
}

func forwardedSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
