// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"
)

func TestChatRowsGroupAuthorAndBodyBySourceMessage(t *testing.T) {
	app := NewApp(Options{DisplayName: "shayne", Terminal: &fakePane{view: "ok"}})
	app.chatMessages = []ChatMessage{
		{Author: "alex", Body: "run this command: systemctl status derphole"},
		{Author: "shayne", Body: "checking", Local: true},
	}

	rows := app.chatRows(24)
	var remote, local int
	for _, row := range rows {
		switch row.messageIndex {
		case 0:
			remote++
		case 1:
			local++
		}
	}
	if remote < 3 || local < 2 {
		t.Fatalf("message rows = remote %d local %d, want grouped author/body rows", remote, local)
	}
}

func TestChatRowsLabelLocalAsYouAndRemoteByUsername(t *testing.T) {
	app := NewApp(Options{DisplayName: "shayne", Terminal: &fakePane{view: "ok"}})
	app.chatMessages = []ChatMessage{
		{Author: "alex", Body: "remote"},
		{Author: "shayne", Body: "local", Local: true},
	}

	rows := app.chatRows(24)
	remote := ansiPattern.ReplaceAllString(rows[0].content, "")
	local := ""
	for _, row := range rows {
		if row.messageIndex == 1 {
			local = ansiPattern.ReplaceAllString(row.content, "")
			break
		}
	}
	if strings.TrimSpace(remote) != "alex" || strings.TrimSpace(local) != "you" {
		t.Fatalf("authors = remote %q local %q, want alex/you", remote, local)
	}
}

func TestVisibleChatBlocksPreserveMessageIndexesWhenClipped(t *testing.T) {
	rows := []chatRenderRow{
		{messageIndex: 0, content: "alex"},
		{messageIndex: 0, content: "one"},
		{messageIndex: -1},
		{messageIndex: 1, content: "shayne"},
		{messageIndex: 1, content: "two"},
	}
	blocks := visibleChatBlocks(rows, Rect{X: 70, Y: 2, W: 24, H: 3}, 0)
	if len(blocks) != 1 || blocks[0].messageIndex != 1 {
		t.Fatalf("blocks = %+v, want clipped block for message 1", blocks)
	}
}

func TestChatMessageTargetRoundTripsIndexes(t *testing.T) {
	for _, index := range []int{0, 1, 42} {
		target := chatMessageTarget(index)
		got, ok := chatMessageIndex(target)
		if !ok || got != index {
			t.Errorf("chatMessageIndex(%q) = %d, %v; want %d, true", target, got, ok, index)
		}
	}
}

func TestChatMessageTargetRejectsMalformedAndNegativeTargets(t *testing.T) {
	for _, target := range []layerTarget{
		"",
		"action:toggle-chat",
		"chat-message:",
		"chat-message:nope",
		"chat-message:-1",
		"chat-message:1:2",
	} {
		if index, ok := chatMessageIndex(target); ok {
			t.Errorf("chatMessageIndex(%q) = %d, true; want false", target, index)
		}
	}
	if _, ok := chatMessageIndex(chatMessageTarget(-1)); ok {
		t.Fatal("negative chat message target parsed successfully")
	}
}

func TestPrefixChatBlockPreservesANSIAndBodyWhitespace(t *testing.T) {
	content := "\x1b[1malex\x1b[0m\n  body  "
	if got, want := prefixChatBlock(content, "\x1b[31m┃\x1b[0m "),
		"\x1b[31m┃\x1b[0m \x1b[1malex\x1b[0m\n\x1b[31m┃\x1b[0m   body  "; got != want {
		t.Fatalf("prefixChatBlock() = %q, want %q", got, want)
	}
}
