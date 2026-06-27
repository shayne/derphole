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
	Sidebar     Rect
	Status      Rect
	Composer    Rect
	SidebarOpen bool
}

func ComputeLayout(cols int, rows int, sidebarOpen bool) Layout {
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
	l.Status = Rect{Y: rows - 1, W: cols, H: 1}
	contentY, contentH := contentRect(rows)

	if shouldCollapseSidebar(cols, sidebarOpen) {
		l.SidebarOpen = false
		l.Terminal = Rect{X: 0, Y: contentY, W: cols, H: contentH}
		return l
	}

	sidebarW := computeSidebarWidth(cols)
	terminalW := cols - sidebarW
	l.Terminal = Rect{X: 0, Y: contentY, W: terminalW, H: contentH}
	l.Sidebar = Rect{X: terminalW, Y: contentY, W: sidebarW, H: contentH}
	if sidebarW > 0 && contentH >= 3 {
		l.Composer = Rect{X: l.Sidebar.X, Y: l.Status.Y - 3, W: sidebarW, H: 3}
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
	return 1, nonNegative(rows - 2)
}

func shouldCollapseSidebar(cols int, open bool) bool {
	return !open || cols < 56
}

func computeSidebarWidth(cols int) int {
	sidebarW := cols / 3
	sidebarW = clampMin(sidebarW, 24)
	sidebarW = clampMax(sidebarW, 36)
	sidebarW = clampMax(sidebarW, cols-20)
	return nonNegative(sidebarW)
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
