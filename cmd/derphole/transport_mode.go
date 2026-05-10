// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/shayne/derphole/pkg/telemetry"
)

var commandContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func usePublicDERPTransport() bool {
	return os.Getenv("DERPHOLE_TEST_LOCAL_RELAY") != "1"
}

func commandSessionTelemetryLevel(level telemetry.Level) telemetry.Level {
	if level == telemetry.LevelDefault {
		return telemetry.LevelQuiet
	}
	return level
}
