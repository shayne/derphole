package main

import (
	"context"
	"os"

	"github.com/shayne/derpcat/pkg/telemetry"
)

var commandContext = context.Background

func usePublicDERPTransport() bool {
	return os.Getenv("DERPCAT_TEST_LOCAL_RELAY") != "1"
}

func commandSessionTelemetryLevel(level telemetry.Level) telemetry.Level {
	if level == telemetry.LevelDefault {
		return telemetry.LevelQuiet
	}
	return level
}
