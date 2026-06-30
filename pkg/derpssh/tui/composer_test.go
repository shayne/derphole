// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"
)

func TestComposerGrowsToThreeLinesBeforeScrolling(t *testing.T) {
	composer := NewComposer(ComposerOptions{Width: 20, MaxVisibleLines: 3})
	composer.SetText("first line wraps here second line wraps here third line wraps here")

	lines := composer.VisibleLines()
	if len(lines) != 3 {
		t.Fatalf("visible lines = %d, want 3: %#v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "first") {
		t.Fatalf("first line should remain visible before max height, got %#v", lines)
	}
}

func TestFocusedEmptyComposerCursorStartsAtPlaceholderStart(t *testing.T) {
	composer := NewComposer(ComposerOptions{Width: 20, Placeholder: "Message", MaxVisibleLines: 3})
	composer.Focus()
	line := composer.RenderLines(newTheme(SchemeDark))[0]

	if !strings.Contains(line, "Message") {
		t.Fatalf("placeholder missing from %q", line)
	}
	if cursorColumn(line) != 0 {
		t.Fatalf("cursor column = %d, want 0", cursorColumn(line))
	}
}

func cursorColumn(line string) int {
	stripped := ansiPattern.ReplaceAllString(line, "")
	return strings.Index(stripped, " ")
}
