// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"unicode"

	uv "github.com/charmbracelet/ultraviolet"
)

type terminalSelectionPhase uint8

const (
	selectionNone terminalSelectionPhase = iota
	selectionAnchored
	selectionDragging
	selectionDone
)

type terminalBufferPosition struct {
	Row int // combined history + live-grid row
	Col int
}

type terminalSelection struct {
	anchor terminalBufferPosition
	cursor terminalBufferPosition
	phase  terminalSelectionPhase
}

func (s terminalSelection) ordered() (terminalBufferPosition, terminalBufferPosition) {
	if s.cursor.Row < s.anchor.Row || s.cursor.Row == s.anchor.Row && s.cursor.Col < s.anchor.Col {
		return s.cursor, s.anchor
	}
	return s.anchor, s.cursor
}

func (s terminalSelection) contains(position terminalBufferPosition) bool {
	if s.phase != selectionDragging && s.phase != selectionDone {
		return false
	}
	start, end := s.ordered()
	return (position.Row > start.Row || position.Row == start.Row && position.Col >= start.Col) &&
		(position.Row < end.Row || position.Row == end.Row && position.Col <= end.Col)
}

func (s *vtTerminalSurface) BeginSelection(x, y int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	position, ok := s.viewportPositionLocked(x, y)
	if !ok {
		return false
	}
	s.selection = terminalSelection{anchor: position, cursor: position, phase: selectionAnchored}
	return true
}

func (s *vtTerminalSurface) UpdateSelection(x, y int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.selection.phase != selectionAnchored && s.selection.phase != selectionDragging {
		return false
	}
	position, ok := s.viewportPositionLocked(x, y)
	if !ok {
		return false
	}
	if position != s.selection.cursor {
		s.selection.phase = selectionDragging
	}
	s.selection.cursor = position
	return true
}

func (s *vtTerminalSurface) FinishSelection() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selection.phase != selectionDragging {
		s.selection = terminalSelection{}
		return "", false
	}
	s.selection.phase = selectionDone
	text := s.selectionTextLocked()
	if text == "" {
		s.selection = terminalSelection{}
		return "", false
	}
	return text, true
}

func (s *vtTerminalSurface) ClearSelection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selection = terminalSelection{}
}

func (s *vtTerminalSurface) SelectionActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selection.phase != selectionNone
}

func (s *vtTerminalSurface) SelectWord(x, y int) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", false
	}
	position, ok := s.viewportPositionLocked(x, y)
	if !ok {
		return "", false
	}
	cell, ownerCol := s.cellAtCombinedLocked(position.Row, position.Col)
	if !terminalCellIsWord(cell) {
		s.selection = terminalSelection{}
		return "", false
	}

	start := ownerCol
	for col := ownerCol - 1; col >= 0; {
		candidate, candidateCol := s.cellAtCombinedLocked(position.Row, col)
		if !terminalCellIsWord(candidate) {
			break
		}
		start = candidateCol
		col = candidateCol - 1
	}

	end := ownerCol + maxInt(cell.Width, 1) - 1
	for col := end + 1; col < s.term.Width(); {
		candidate, candidateCol := s.cellAtCombinedLocked(position.Row, col)
		if !terminalCellIsWord(candidate) {
			break
		}
		end = candidateCol + maxInt(candidate.Width, 1) - 1
		col = end + 1
	}

	s.selection = terminalSelection{
		anchor: terminalBufferPosition{Row: position.Row, Col: start},
		cursor: terminalBufferPosition{Row: position.Row, Col: end},
		phase:  selectionDone,
	}
	text := s.selectionTextLocked()
	return text, text != ""
}

func terminalCellIsWord(cell *uv.Cell) bool {
	if cell == nil || cell.Content == "" {
		return false
	}
	for _, r := range cell.Content {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' {
			return false
		}
	}
	return true
}

func (s *vtTerminalSurface) viewportPositionLocked(x, y int) (terminalBufferPosition, bool) {
	cols, rows := s.term.Width(), s.term.Height()
	if x < 0 || y < 0 || x >= cols || y >= rows {
		return terminalBufferPosition{}, false
	}
	row := y
	if !s.term.IsAltScreen() {
		row = s.term.ScrollbackLen() - s.offsetFromBottom + y
	}
	_, col := s.cellAtCombinedLocked(row, x)
	return terminalBufferPosition{Row: row, Col: col}, true
}

func (s *vtTerminalSurface) selectionTextLocked() string {
	start, end := s.selection.ordered()
	lines := make([]string, 0, end.Row-start.Row+1)
	for row := start.Row; row <= end.Row; row++ {
		firstCol, lastCol := 0, s.term.Width()-1
		if row == start.Row {
			firstCol = start.Col
		}
		if row == end.Row {
			lastCol = end.Col
		}
		var line strings.Builder
		for col := firstCol; col <= lastCol; {
			cell, ownerCol := s.cellAtCombinedLocked(row, col)
			if ownerCol < firstCol {
				ownerCol = col
			}
			if cell.Width > 0 {
				line.WriteString(cell.Content)
			}
			col = maxInt(col+1, ownerCol+maxInt(cell.Width, 1))
		}
		lines = append(lines, strings.TrimRight(line.String(), " "))
	}
	return strings.Join(lines, "\n")
}
