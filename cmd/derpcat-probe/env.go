package main

import (
	"os"
	"strings"
)

func probeEnvBool(key string) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	return raw == "1" || strings.EqualFold(raw, "true") || strings.EqualFold(raw, "yes")
}
