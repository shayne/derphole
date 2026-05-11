// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
)

const transferTraceCSVEnv = "DERPHOLE_TRANSFER_TRACE_CSV"

func openTransferTraceFromEnv(role transfertrace.Role, stderr io.Writer) (*transfertrace.Recorder, func(), bool) {
	path := os.Getenv(transferTraceCSVEnv)
	if path == "" {
		return nil, func() {}, true
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "open %s: %v\n", transferTraceCSVEnv, err)
		return nil, func() {}, false
	}
	rec, err := transfertrace.NewRecorder(f, role, time.Now())
	if err != nil {
		_ = f.Close()
		_, _ = fmt.Fprintf(stderr, "initialize %s: %v\n", transferTraceCSVEnv, err)
		return nil, func() {}, false
	}
	return rec, func() {
		_ = rec.Close()
		_ = f.Close()
	}, true
}
