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
	if l.Status != (Rect{X: 0, Y: 29, W: 100, H: 1}) {
		t.Fatalf("Status = %+v, want full-width last row", l.Status)
	}
	if l.Terminal.X != 0 || l.Terminal.Y != 1 || l.Terminal.H != 28 {
		t.Fatalf("Terminal = %+v, want left content area", l.Terminal)
	}
	if l.Sidebar.W == 0 || l.Sidebar.X <= l.Terminal.X {
		t.Fatalf("Sidebar = %+v, want right-hand sidebar", l.Sidebar)
	}
	if l.Terminal.W+l.Sidebar.W != 100 {
		t.Fatalf("terminal/sidebar widths = %d+%d, want 100", l.Terminal.W, l.Sidebar.W)
	}
	if l.Composer.X != l.Sidebar.X || l.Composer.W != l.Sidebar.W || l.Composer.H != 3 {
		t.Fatalf("Composer = %+v, want 3-line composer inside sidebar", l.Composer)
	}
	if l.Composer.Y+l.Composer.H != l.Status.Y {
		t.Fatalf("Composer = %+v, want flush above status row %+v", l.Composer, l.Status)
	}
}

func TestComputeLayoutCollapsedSidebar(t *testing.T) {
	l := ComputeLayout(80, 24, false)

	if l.SidebarOpen {
		t.Fatalf("SidebarOpen = true, want false")
	}
	if l.Terminal != (Rect{X: 0, Y: 1, W: 80, H: 22}) {
		t.Fatalf("Terminal = %+v, want all content rows", l.Terminal)
	}
	if l.Sidebar != (Rect{}) {
		t.Fatalf("Sidebar = %+v, want zero rect", l.Sidebar)
	}
	if l.Composer != (Rect{}) {
		t.Fatalf("Composer = %+v, want zero rect", l.Composer)
	}
}

func TestLayoutHitTargets(t *testing.T) {
	l := ComputeLayout(100, 30, true)

	tests := []struct {
		name string
		x    int
		y    int
		want HitTarget
	}{
		{name: "top bar", x: 5, y: 0, want: HitTopBar},
		{name: "terminal", x: l.Terminal.X + 1, y: l.Terminal.Y + 1, want: HitTerminal},
		{name: "sidebar", x: l.Sidebar.X + 1, y: l.Sidebar.Y + 1, want: HitSidebar},
		{name: "composer", x: l.Composer.X + 1, y: l.Composer.Y + 1, want: HitComposer},
		{name: "status", x: 5, y: l.Status.Y, want: HitStatus},
		{name: "outside negative", x: -1, y: 0, want: HitNone},
		{name: "outside after edge", x: 100, y: 30, want: HitNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := l.Hit(tt.x, tt.y); got != tt.want {
				t.Fatalf("Hit(%d, %d) = %v, want %v", tt.x, tt.y, got, tt.want)
			}
		})
	}
}
