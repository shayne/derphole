package main

import (
	"testing"
	"time"
)

func TestParseByteCount(t *testing.T) {
	t.Parallel()

	got, err := parseByteCount("128MiB")
	if err != nil {
		t.Fatalf("parseByteCount() error = %v", err)
	}
	if got != 128<<20 {
		t.Fatalf("parseByteCount() = %d, want %d", got, int64(128<<20))
	}
}

func TestThroughputMbps(t *testing.T) {
	t.Parallel()

	got := throughputMbps(64<<20, 4*time.Second)
	if got != 134.217728 {
		t.Fatalf("throughputMbps() = %f, want %f", got, 134.217728)
	}
}
