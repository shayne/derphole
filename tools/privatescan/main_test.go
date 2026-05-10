// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
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

func TestScanRepoUsesGitCandidateFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	runGit(t, root, "init")
	writeLocalInstructions(t, root)
	writeFile(t, root, "tracked.txt", "safe\n")
	writeFile(t, root, "leak.txt", "host "+exampleHost()+"\n")

	findings, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Path != "leak.txt" {
		t.Fatalf("ScanRepo() findings = %#v, want leak.txt through git candidate path", findings)
	}
}

func TestScanRepoSkipsDeletedTrackedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "test@example.invalid")
	runGit(t, root, "config", "user.name", "Test User")
	writeLocalInstructions(t, root)
	writeFile(t, root, "deleted.txt", "safe\n")
	runGit(t, root, "add", "AGENTS.local.md", "deleted.txt")
	runGit(t, root, "commit", "-m", "seed")
	if err := os.Remove(filepath.Join(root, "deleted.txt")); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("ScanRepo() findings = %#v, want none for deleted file", findings)
	}
}

func TestParsePrivatePatternsCleansAndDeduplicatesHostTable(t *testing.T) {
	got := parsePrivatePatterns(strings.Join([]string{
		"before",
		"## Host reference",
		"| Host label | Real hostname | Host Tailscale DNS | Service Tailscale DNS | Install / SSH target |",
		"| --- | --- | --- | --- | --- |",
		"| sample | `edge.example.invalid.` | `edge.example.invalid.` | `svc.example.invalid.` | `ops@svc.example.invalid` |",
		"| ignored words | host with spaces | | | |",
		"## Other section",
		"| outside | `not-included.example.invalid` |",
	}, "\n"))
	joined := strings.Join(got, "\n")
	for _, want := range []string{"edge.example.invalid", "edge", "svc.example.invalid", "svc", "ops@svc.example.invalid"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("parsePrivatePatterns() = %v, missing %q", got, want)
		}
	}
	if strings.Contains(joined, "not-included") || strings.Contains(joined, "host with spaces") {
		t.Fatalf("parsePrivatePatterns() = %v, included ignored tokens", got)
	}
}

func TestIgnorePathHelpers(t *testing.T) {
	for _, rel := range []string{
		"AGENTS.local.md",
		"dist/package/index.js",
		"website/node_modules/pkg/index.js",
		"coverage/report.out",
	} {
		if !shouldIgnorePath(rel) {
			t.Fatalf("shouldIgnorePath(%q) = false, want true", rel)
		}
	}
	if shouldIgnorePath("docs/readme.md") {
		t.Fatal("shouldIgnorePath(docs/readme.md) = true, want false")
	}
	if got, want := pathBase("a/b/c.txt"), "c.txt"; got != want {
		t.Fatalf("pathBase() = %q, want %q", got, want)
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

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
