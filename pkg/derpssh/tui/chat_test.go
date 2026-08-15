// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"
)

func TestChatPaneSuppressesDuplicateLocalEcho(t *testing.T) {
	chat := NewChatPane(ChatPaneOptions{Width: 32})
	chat.Append(ChatLine{ID: "local-1", Author: "root@hetz", Text: "hello", Local: true})
	chat.Append(ChatLine{ID: "remote-echo", Author: "root@hetz", Text: "hello"})

	lines := chat.RenderLines(newTheme(SchemeDark))
	if got := strings.Count(strings.Join(lines, "\n"), "you: hello"); got != 1 {
		t.Fatalf("rendered local echo %d times, want once: %#v", got, lines)
	}
	if !chat.messages[0].Local {
		t.Fatal("absorbed transport echo changed the local message to remote")
	}
}

func TestChatPaneLabelsLocalMessagesAsYou(t *testing.T) {
	chat := NewChatPane(ChatPaneOptions{Width: 32})
	chat.Append(ChatLine{ID: "local-1", Author: "shayne", Text: "hello", Local: true})
	chat.Append(ChatLine{ID: "remote-1", Author: "alex", Text: "hi"})

	got := strings.Join(chat.RenderLines(newTheme(SchemeDark)), "\n")
	if !strings.Contains(got, "you: hello") || !strings.Contains(got, "alex: hi") {
		t.Fatalf("chat labels = %q, want local you and remote username", got)
	}
}

func TestChatPaneWrapsMessages(t *testing.T) {
	chat := NewChatPane(ChatPaneOptions{Width: 18})
	chat.Append(ChatLine{ID: "m1", Author: "alex", Text: "this message wraps across rows"})

	lines := chat.RenderLines(newTheme(SchemeDark))
	if len(lines) < 2 {
		t.Fatalf("wrapped lines = %d, want at least 2: %#v", len(lines), lines)
	}
}

func TestChatPaneCompactsDuplicateDisplayNames(t *testing.T) {
	chat := NewChatPane(ChatPaneOptions{
		Width: 40,
		Peers: []DisplayName{"root@hetz", "root@pve1"},
	})
	chat.Append(ChatLine{ID: "m1", Author: "root@hetz", Text: "hi"})
	chat.Append(ChatLine{ID: "m2", Author: "root@pve1", Text: "yo"})

	got := strings.Join(chat.RenderLines(newTheme(SchemeDark)), "\n")
	if !strings.Contains(got, "root@hetz: hi") || !strings.Contains(got, "root@pve1: yo") {
		t.Fatalf("duplicate user display names were not host-qualified:\n%s", got)
	}
}
