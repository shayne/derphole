// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpShowsDerptunCommands(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := stderr.String()
	for _, want := range []string{"derptun", "token", "serve", "open", "connect", "netcheck"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q in:\n%s", want, out)
		}
	}
}
