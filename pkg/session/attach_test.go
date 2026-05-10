// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestSendConfigWithInferredExpectedBytesUsesRemainingRegularFileBytes(t *testing.T) {
	f := writeTempFile(t, bytes.Repeat([]byte("x"), 1024))
	defer f.Close()
	if _, err := f.Seek(128, io.SeekStart); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}

	cfg := sendConfigWithInferredExpectedBytes(SendConfig{StdioIn: f})

	if got, want := cfg.StdioExpectedBytes, int64(896); got != want {
		t.Fatalf("StdioExpectedBytes = %d, want %d", got, want)
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("Seek(current) error = %v", err)
	}
	if got, want := pos, int64(128); got != want {
		t.Fatalf("file offset = %d, want %d", got, want)
	}
}

func TestSendConfigWithInferredExpectedBytesPreservesExplicitValue(t *testing.T) {
	f := writeTempFile(t, bytes.Repeat([]byte("x"), 1024))
	defer f.Close()

	cfg := sendConfigWithInferredExpectedBytes(SendConfig{
		StdioIn:            f,
		StdioExpectedBytes: 42,
	})

	if got, want := cfg.StdioExpectedBytes, int64(42); got != want {
		t.Fatalf("StdioExpectedBytes = %d, want %d", got, want)
	}
}

func TestSendConfigWithInferredExpectedBytesIgnoresNonFiles(t *testing.T) {
	cfg := sendConfigWithInferredExpectedBytes(SendConfig{StdioIn: bytes.NewReader([]byte("not a file"))})

	if got, want := cfg.StdioExpectedBytes, int64(0); got != want {
		t.Fatalf("StdioExpectedBytes = %d, want %d", got, want)
	}
}

func writeTempFile(t *testing.T, payload []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}
	return f
}
