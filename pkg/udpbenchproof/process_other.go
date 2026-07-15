//go:build !darwin && !linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

func observePlatformProcess(context.Context, string, int, time.Duration) (ProcessRef, error) {
	return ProcessRef{}, fmt.Errorf("process identity is unsupported on %s", runtime.GOOS)
}
