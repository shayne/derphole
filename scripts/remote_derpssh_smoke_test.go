// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteDerpsshSmokeScriptExercisesShareConnect(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join(".", "smoke-remote-derpssh.sh"))
	if err != nil {
		t.Fatalf("read smoke-remote-derpssh.sh: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"dist/derpssh-linux-amd64",
		"DERPSSH_TEST_AUTO_APPROVE=read",
		"DERPSSH_TEST_COMMAND=",
		"derpssh share",
		"connect --name smoke",
		"input:hello",
		"sidechat",
		"role write",
		"host terminal echo",
		"remote_target",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("remote derpssh smoke script missing %q", want)
		}
	}
}

func TestMiseHasRemoteDerpsshSmokeTask(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", ".mise.toml"))
	if err != nil {
		t.Fatalf("read .mise.toml: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"[tasks.smoke-remote-derpssh]",
		"./scripts/smoke-remote-derpssh.sh \"${REMOTE_HOST}\"",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf(".mise.toml missing %q", want)
		}
	}
}
