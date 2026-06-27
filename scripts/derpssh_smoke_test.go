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

func TestDerpsshLocalSmokeScriptUsesBuiltBinary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "smoke-derpssh-local.sh"))
	if err != nil {
		t.Fatalf("read smoke script: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"dist/derpssh",
		"derpssh share",
		"derpssh connect",
		"DERPSSH_TEST_HARNESS=1",
		"DERPSSH_TEST_AUTO_APPROVE=write",
		"DERPSSH_TEST_COMMAND=",
		"DERPSSH_TEST_HOST_ACTIONS=",
		"DERPSSH_TEST_GUEST_ACTIONS=",
		"input hello\\\\n",
		"host terminal echo",
		"sidechat",
		"role: write",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("smoke script missing %q", want)
		}
	}
	for _, forbidden := range []string{":chat", ":write", ":read", ":kick"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("smoke script still writes old stdin command %q", forbidden)
		}
	}
}
