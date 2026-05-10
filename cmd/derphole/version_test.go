// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runVersion(&stdout, &stderr)
	if code != 0 {
		t.Fatalf("runVersion() = %d, want 0", code)
	}
	if got := stdout.String(); got != versionString()+"\n" {
		t.Fatalf("stdout = %q, want version", got)
	}
}

func TestVersionHelpTextMentionsVersionCommand(t *testing.T) {
	if got := versionHelpText(); !strings.Contains(got, "Print the derphole version") {
		t.Fatalf("versionHelpText() = %q, want version command help", got)
	}
}
