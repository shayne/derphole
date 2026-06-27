// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPublishNpmIfMissingSkipsOnlyUnclaimedPackage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "pkg")
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"derpssh","version":"0.0.0-dev.test"}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}
	fakeNPM := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "view" && "$2" == "derpssh" ]]; then
  echo derpssh
  exit 0
fi
if [[ "$1" == "view" && "$2" == "derpssh@0.0.0-dev.test" ]]; then
  echo "npm error code E404" >&2
  exit 1
fi
if [[ "$1" == "publish" ]]; then
  echo "npm error code E404" >&2
  echo "npm error 404 Not Found - PUT https://registry.npmjs.org/derpssh - Not found" >&2
  exit 1
fi
echo "unexpected npm invocation: $*" >&2
exit 2
`
	fakePath := filepath.Join(binDir, "npm")
	if runtime.GOOS == "windows" {
		fakePath += ".sh"
	}
	if err := os.WriteFile(fakePath, []byte(fakeNPM), 0o755); err != nil {
		t.Fatalf("write fake npm: %v", err)
	}

	cmd := exec.Command("bash", filepath.Join("..", "tools", "packaging", "publish-npm-if-missing.sh"), "--tag", "dev", "--skip-unclaimed", pkgDir)
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected publish-time E404 to fail, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "Not Found - PUT") {
		t.Fatalf("expected publish error in output, got:\n%s", out)
	}
	if strings.Contains(string(out), "skipping npm publish") {
		t.Fatalf("publish-time E404 was incorrectly skipped:\n%s", out)
	}
}
