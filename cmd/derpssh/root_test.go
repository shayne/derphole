// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpListsDerpsshCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"--help"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMain(--help) = %d, want 0", code)
	}
	out := stderr.String()
	for _, want := range []string{"derpssh", "share", "connect", "version"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q:\n%s", want, out)
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}
