// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDirDetectsPrivateHostLeak(t *testing.T) {
	root := t.TempDir()
	writeLocalInstructions(t, root)
	writeFile(t, root, "docs/example.md", "connect with "+exampleTarget()+"\n")

	findings, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %#v", len(findings), findings)
	}
	if findings[0].Path != "docs/example.md" {
		t.Fatalf("finding path = %q", findings[0].Path)
	}
}

func TestScanDirExcludesAgentsLocal(t *testing.T) {
	root := t.TempDir()
	writeLocalInstructions(t, root)

	findings, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Fatalf("got findings for AGENTS.local.md: %#v", findings)
	}
}

func TestScanDirIgnoresGeneratedDirs(t *testing.T) {
	root := t.TempDir()
	writeLocalInstructions(t, root)
	writeFile(t, root, ".git/config", "url = "+exampleTarget()+"\n")
	writeFile(t, root, ".tmp/work.txt", exampleTarget()+"\n")
	writeFile(t, root, "bin/output.txt", exampleTarget()+"\n")
	writeFile(t, root, "website/node_modules/pkg/index.js", exampleTarget()+"\n")
	writeFile(t, root, "website/.next/server.js", exampleTarget()+"\n")

	findings, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Fatalf("got findings in ignored dirs: %#v", findings)
	}
}

func TestScanDirSkipsBinaryFiles(t *testing.T) {
	root := t.TempDir()
	writeLocalInstructions(t, root)
	writeBytes(t, root, "artifact.bin", append([]byte{0x00}, []byte(exampleTarget())...))

	findings, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Fatalf("got findings in binary file: %#v", findings)
	}
}

func writeLocalInstructions(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, "AGENTS.local.md", strings.Join([]string{
		"## Host reference",
		"",
		"| Host label | Real hostname | Host Tailscale DNS | Service Tailscale DNS | Install / SSH target |",
		"| --- | --- | --- | --- | --- |",
		"| sample-a | `" + exampleHost() + "` | `" + exampleHost() + ".example.invalid.` | `" + exampleService() + ".example.invalid.` | `" + exampleTarget() + "` |",
	}, "\n"))
}

func exampleHost() string {
	return "edge-a"
}

func exampleService() string {
	return "svc-edge-a"
}

func exampleTarget() string {
	return "ops@" + exampleService()
}

func writeFile(t *testing.T, root, name, data string) {
	t.Helper()
	writeBytes(t, root, name, []byte(data))
}

func writeBytes(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
