// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "testing"

func TestComputeLayoutExpandedSidebar(t *testing.T) {
	l := ComputeLayout(100, 30, true)

	if l.Outer != (Rect{X: 0, Y: 0, W: 100, H: 30}) {
		t.Fatalf("Outer = %+v, want 100x30 at origin", l.Outer)
	}
	if !l.SidebarOpen {
		t.Fatalf("SidebarOpen = false, want true")
	}
	if l.TopBar != (Rect{X: 0, Y: 0, W: 100, H: 1}) {
		t.Fatalf("TopBar = %+v, want full-width first row", l.TopBar)
	}
	if l.Status != (Rect{}) {
		t.Fatalf("Status = %+v, want no bottom status row", l.Status)
	}
	if l.Terminal.X != 0 || l.Terminal.Y != 1 || l.Terminal.H != 29 {
		t.Fatalf("Terminal = %+v, want left content area", l.Terminal)
	}
	if l.Divider != (Rect{X: l.Terminal.W, Y: 1, W: 1, H: 29}) {
		t.Fatalf("Divider = %+v, want one-column divider after terminal", l.Divider)
	}
	if l.Sidebar.W == 0 || l.Sidebar.X <= l.Terminal.X {
		t.Fatalf("Sidebar = %+v, want right-hand sidebar", l.Sidebar)
	}
	if l.Terminal.W+l.Divider.W+l.Sidebar.W != 100 {
		t.Fatalf("terminal/divider/sidebar widths = %d+%d+%d, want 100", l.Terminal.W, l.Divider.W, l.Sidebar.W)
	}
	if l.Composer.X != l.Sidebar.X || l.Composer.W != l.Sidebar.W || l.Composer.H != 1 {
		t.Fatalf("Composer = %+v, want one-line composer inside sidebar", l.Composer)
	}
	if l.Composer.Y+l.Composer.H != l.Outer.H {
		t.Fatalf("Composer = %+v, want flush with bottom edge", l.Composer)
	}
}

func TestComputeLayoutCollapsedSidebar(t *testing.T) {
	l := ComputeLayout(80, 24, false)

	if l.SidebarOpen {
		t.Fatalf("SidebarOpen = true, want false")
	}
	if l.Terminal != (Rect{X: 0, Y: 1, W: 80, H: 23}) {
		t.Fatalf("Terminal = %+v, want all content rows", l.Terminal)
	}
	if l.Divider != (Rect{}) {
		t.Fatalf("Divider = %+v, want zero rect", l.Divider)
	}
	if l.Sidebar != (Rect{}) {
		t.Fatalf("Sidebar = %+v, want zero rect", l.Sidebar)
	}
	if l.Composer != (Rect{}) {
		t.Fatalf("Composer = %+v, want zero rect", l.Composer)
	}
}

func TestComputeLayoutUsesPreferredSidebarWidth(t *testing.T) {
	l := ComputeLayoutWithSidebarWidth(120, 32, true, 48)

	if l.Sidebar.W != 48 {
		t.Fatalf("Sidebar.W = %d, want preferred width 48", l.Sidebar.W)
	}
	if l.Terminal.W+l.Divider.W+l.Sidebar.W != 120 {
		t.Fatalf("terminal/divider/sidebar widths = %d+%d+%d, want 120", l.Terminal.W, l.Divider.W, l.Sidebar.W)
	}
}
