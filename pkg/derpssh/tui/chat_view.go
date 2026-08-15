// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

const chatSpacerMessageIndex = -1

type chatRenderRow struct {
	messageIndex int
	content      string
	author       bool
}

type chatRenderBlock struct {
	messageIndex int
	rect         Rect
	content      string
	rows         []chatRenderRow
}

func chatMessageTarget(index int) layerTarget {
	return layerTarget(fmt.Sprintf("chat-message:%d", index))
}

func chatMessageIndex(target layerTarget) (int, bool) {
	value, ok := strings.CutPrefix(string(target), "chat-message:")
	if !ok {
		return 0, false
	}
	index, err := strconv.Atoi(value)
	return index, err == nil && index >= 0
}

func (a *App) chatRows(width int) []chatRenderRow {
	contentWidth := maxInt(width-2, 1)
	counts := a.identityCounts()
	rows := make([]chatRenderRow, 0, len(a.chatMessages)*3)
	for index, msg := range a.chatMessages {
		author := "you"
		if !msg.Local {
			author = a.displayHandleWithCounts(msg.Author, 16, counts)
		}
		if author == "" {
			author = "peer"
		}
		authorRow := author
		if a.copiedChatActive && a.copiedChatIndex == index {
			copied := "✓ Copied"
			copiedWidth := ansi.StringWidth(copied)
			if copiedWidth <= contentWidth {
				authorRow = ansi.Truncate(authorRow, maxInt(contentWidth-copiedWidth-1, 0), "")
				gap := contentWidth - ansi.StringWidth(authorRow) - copiedWidth
				authorRow += strings.Repeat(" ", maxInt(gap, 0)) + copied
			}
		}
		rows = append(rows, chatRenderRow{messageIndex: index, content: authorRow, author: true})
		for _, line := range wrapPlainLines(msg.Body, contentWidth) {
			rows = append(rows, chatRenderRow{messageIndex: index, content: line})
		}
		rows = append(rows, chatRenderRow{messageIndex: chatSpacerMessageIndex})
	}
	return rows
}

func visibleChatBlocks(rows []chatRenderRow, viewport Rect, scroll int) []chatRenderBlock {
	if viewport.empty() || len(rows) == 0 {
		return nil
	}
	start := chatWindowStart(len(rows), viewport.H, scroll)
	end := minInt(start+viewport.H, len(rows))
	blocks := make([]chatRenderBlock, 0)
	for rowIndex := start; rowIndex < end; rowIndex++ {
		row := rows[rowIndex]
		if row.messageIndex < 0 {
			continue
		}
		y := viewport.Y + rowIndex - start
		last := len(blocks) - 1
		if last >= 0 && blocks[last].messageIndex == row.messageIndex &&
			blocks[last].rect.Y+blocks[last].rect.H == y {
			blocks[last].rect.H++
			blocks[last].content += "\n" + row.content
			blocks[last].rows = append(blocks[last].rows, row)
			continue
		}
		blocks = append(blocks, chatRenderBlock{
			messageIndex: row.messageIndex,
			rect:         Rect{X: viewport.X, Y: y, W: viewport.W, H: 1},
			content:      row.content,
			rows:         []chatRenderRow{row},
		})
	}
	return blocks
}

func prefixChatBlock(content string, prefix string) string {
	lines := strings.Split(content, "\n")
	for index := range lines {
		lines[index] = prefix + lines[index]
	}
	return strings.Join(lines, "\n")
}
