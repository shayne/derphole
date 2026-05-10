// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestArchiveRejectsNonDirectoriesAndUnsupportedEntries(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := DescribeTar(filePath); err == nil {
		t.Fatal("DescribeTar(file) error = nil, want non-directory rejection")
	}
	if err := StreamTar(&bytes.Buffer{}, filePath); err == nil {
		t.Fatal("StreamTar(file) error = nil, want non-directory rejection")
	}

	srcRoot := t.TempDir()
	linkPath := filepath.Join(srcRoot, "link")
	if err := os.Symlink("missing-target", linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := DescribeTar(srcRoot); err == nil || !strings.Contains(err.Error(), "unsupported directory entry") {
		t.Fatalf("DescribeTar(symlink) error = %v, want unsupported entry", err)
	}
	if err := StreamTar(&bytes.Buffer{}, srcRoot); err == nil || !strings.Contains(err.Error(), "unsupported directory entry") {
		t.Fatalf("StreamTar(symlink) error = %v, want unsupported entry", err)
	}
}

func TestArchivePathAndSizeHelpers(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{".", "/abs/path", "../escape", "nested/../../escape"} {
		if _, err := safeTarTarget(base, name); err == nil {
			t.Fatalf("safeTarTarget(%q) error = nil, want unsafe path rejection", name)
		}
	}
	target, err := safeTarTarget(base, "nested/file.txt")
	if err != nil {
		t.Fatalf("safeTarTarget(valid) error = %v", err)
	}
	if !strings.HasPrefix(target, base) || !strings.HasSuffix(target, filepath.Join("nested", "file.txt")) {
		t.Fatalf("safeTarTarget(valid) = %q, want path under %q", target, base)
	}

	if got := padded512(0); got != 0 {
		t.Fatalf("padded512(0) = %d, want 0", got)
	}
	if got := padded512(512); got != 512 {
		t.Fatalf("padded512(512) = %d, want 512", got)
	}
	if got := padded512(513); got != 1024 {
		t.Fatalf("padded512(513) = %d, want 1024", got)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target"}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := ExtractTar(bytes.NewReader(buf.Bytes()), t.TempDir(), "payload"); err == nil || !strings.Contains(err.Error(), "unsupported tar entry type") {
		t.Fatalf("ExtractTar(symlink) error = %v, want unsupported entry", err)
	}
}
