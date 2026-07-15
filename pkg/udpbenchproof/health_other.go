//go:build !darwin && !linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"fmt"
	"runtime"
)

func capturePlatformHealth(context.Context, HealthCaptureOptions) (HealthSnapshot, error) {
	return HealthSnapshot{}, fmt.Errorf("health capture is unsupported on %s", runtime.GOOS)
}
