// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestEncodeTerminalPasteTracksEmbeddedMode(t *testing.T) {
	msg := tea.PasteMsg{Content: "one\ntwo"}
	if got := string(EncodeTerminalPaste(msg, TerminalInputMode{})); got != "one\ntwo" {
		t.Fatalf("plain paste = %q", got)
	}
	mode := TerminalInputMode{BracketedPaste: true}
	if got := string(EncodeTerminalPaste(msg, mode)); got != "\x1b[200~one\ntwo\x1b[201~" {
		t.Fatalf("bracketed paste = %q", got)
	}
}
