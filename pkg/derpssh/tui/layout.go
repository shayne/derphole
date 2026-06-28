// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

type Rect struct {
	X int
	Y int
	W int
	H int
}

type HitTarget int

const (
	HitNone HitTarget = iota
	HitTopBar
	HitTerminal
	HitDivider
	HitSidebar
	HitStatus
	HitComposer
	HitApprovalRead
	HitApprovalWrite
	HitApprovalDeny
)

type Layout struct {
	Outer       Rect
	TopBar      Rect
	Terminal    Rect
	Divider     Rect
	Sidebar     Rect
	Status      Rect
	Composer    Rect
	SidebarOpen bool
}

func ComputeLayout(cols int, rows int, sidebarOpen bool) Layout {
	return ComputeLayoutWithSidebarWidth(cols, rows, sidebarOpen, 0)
}

func ComputeLayoutWithSidebarWidth(cols int, rows int, sidebarOpen bool, preferredSidebarWidth int) Layout {
	cols = nonNegative(cols)
	rows = nonNegative(rows)

	l := Layout{
		Outer:       Rect{W: cols, H: rows},
		SidebarOpen: sidebarOpen,
	}
	if cols == 0 || rows == 0 {
		return l
	}

	l.TopBar = Rect{W: cols, H: 1}
	if rows == 1 {
		return l
	}
	contentY, contentH := contentRect(rows)

	if shouldCollapseSidebar(cols, sidebarOpen) {
		l.SidebarOpen = false
		l.Terminal = Rect{X: 0, Y: contentY, W: cols, H: contentH}
		return l
	}

	sidebarW := computeSidebarWidth(cols, preferredSidebarWidth)
	terminalW := cols - sidebarW - 1
	l.Terminal = Rect{X: 0, Y: contentY, W: terminalW, H: contentH}
	l.Divider = Rect{X: terminalW, Y: contentY, W: 1, H: contentH}
	l.Sidebar = Rect{X: terminalW + 1, Y: contentY, W: sidebarW, H: contentH}
	if sidebarW > 0 && contentH >= 1 {
		l.Composer = Rect{X: l.Sidebar.X, Y: rows - 1, W: sidebarW, H: 1}
	}
	return l
}

func nonNegative(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func contentRect(rows int) (int, int) {
	return 1, nonNegative(rows - 1)
}

func shouldCollapseSidebar(cols int, open bool) bool {
	return !open || cols < 56
}

func computeSidebarWidth(cols int, preferred int) int {
	sidebarW := preferred
	if sidebarW <= 0 {
		sidebarW = cols / 3
	}
	sidebarW = clampMin(sidebarW, minSidebarWidth(cols))
	sidebarW = clampMax(sidebarW, maxSidebarWidth(cols))
	return nonNegative(sidebarW)
}

func clampSidebarWidth(cols int, width int) int {
	return computeSidebarWidth(cols, width)
}

func minSidebarWidth(cols int) int {
	if cols < 72 {
		return 24
	}
	return 28
}

func maxSidebarWidth(cols int) int {
	max := cols - 24
	if max < 24 {
		return max
	}
	return max
}

func clampMin(v int, min int) int {
	if v < min {
		return min
	}
	return v
}

func clampMax(v int, max int) int {
	if v > max {
		return max
	}
	return v
}

func (l Layout) Hit(x int, y int) HitTarget {
	switch {
	case !l.Outer.contains(x, y):
		return HitNone
	case l.TopBar.contains(x, y):
		return HitTopBar
	case l.Status.contains(x, y):
		return HitStatus
	case l.Composer.contains(x, y):
		return HitComposer
	case l.Divider.contains(x, y):
		return HitDivider
	case l.Sidebar.contains(x, y):
		return HitSidebar
	case l.Terminal.contains(x, y):
		return HitTerminal
	default:
		return HitNone
	}
}

func (r Rect) contains(x int, y int) bool {
	return r.W > 0 && r.H > 0 && x >= r.X && y >= r.Y && x < r.X+r.W && y < r.Y+r.H
}

func (r Rect) empty() bool {
	return r.W <= 0 || r.H <= 0
}
