// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTarRejectsParentTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0600, Size: int64(len("x"))}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := ExtractTar(bytes.NewReader(buf.Bytes()), t.TempDir(), "photos"); err == nil {
		t.Fatal("ExtractTar() error = nil, want traversal rejection")
	}
}

func TestStreamTarAndExtractTarRoundTrip(t *testing.T) {
	srcRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcRoot, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "nested", "child.txt"), []byte("child"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var buf bytes.Buffer
	if err := StreamTar(&buf, srcRoot); err != nil {
		t.Fatalf("StreamTar() error = %v", err)
	}

	destRoot := t.TempDir()
	if err := ExtractTar(bytes.NewReader(buf.Bytes()), destRoot, "payload"); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destRoot, "payload", "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("hello.txt = %q, want %q", got, "hello")
	}

	got, err = os.ReadFile(filepath.Join(destRoot, "payload", "nested", "child.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "child" {
		t.Fatalf("child.txt = %q, want %q", got, "child")
	}
}

func TestTarSizeMatchesStreamTarOutput(t *testing.T) {
	srcRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcRoot, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "nested", "child.txt"), []byte("child"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	size, err := TarSize(srcRoot)
	if err != nil {
		t.Fatalf("TarSize() error = %v", err)
	}

	var buf bytes.Buffer
	if err := StreamTar(&buf, srcRoot); err != nil {
		t.Fatalf("StreamTar() error = %v", err)
	}

	if got, want := int64(buf.Len()), size; got != want {
		t.Fatalf("streamed tar size = %d, want %d", got, want)
	}
}
