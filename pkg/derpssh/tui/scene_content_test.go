// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/shayne/derphole/pkg/derpssh/brand"
)

func TestSceneTargetsHeaderTerminalSidebarAndDivider(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	scene := app.buildScene()

	if got := scene.TargetAt(1, 1); got != targetTerminal {
		t.Fatalf("terminal target = %q", got)
	}
	if got := scene.TargetAt(app.layout.Divider.X, app.layout.Divider.Y+1); got != targetDivider {
		t.Fatalf("divider target = %q", got)
	}
	var dividerContent string
	for _, layer := range app.buildBaseLayers(app.layout) {
		if layer.GetID() == string(targetDivider) {
			dividerContent = layer.GetContent()
			break
		}
	}
	if !strings.Contains(dividerContent, "│") {
		t.Fatalf("divider content = %q, want vertical separator", dividerContent)
	}
	if got := scene.TargetAt(app.layout.Sidebar.X+1, app.layout.Sidebar.Y+1); got != targetSidebar {
		t.Fatalf("sidebar target = %q", got)
	}
	if got := scene.TargetAt(app.layout.Composer.X+1, app.layout.Composer.Y); got != targetComposer {
		t.Fatalf("composer target = %q", got)
	}
	if got := scene.TargetAt(app.width-2, 0); !strings.HasPrefix(string(got), "action:") {
		t.Fatalf("top bar target = %q, want action", got)
	}
}

func TestInviteLayerCoversHeader(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "derpssh connect invite", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.inviteOpen = true

	firstLine := strings.Split(app.buildScene().Content, "\n")[0]
	firstLine = ansiPattern.ReplaceAllString(firstLine, "")
	if want := brand.WordmarkLines()[0]; !strings.Contains(firstLine, want) {
		t.Fatalf("invite first line = %q, want %q", firstLine, want)
	}
}

func TestTwoRowSceneLeavesVisibleSidebarRowOwnedBySidebar(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 2})
	app.setSidebarOpen(true)
	scene := app.buildScene()

	if got := scene.TargetAt(app.layout.Sidebar.X+1, app.layout.Sidebar.Y); got != targetSidebar {
		t.Fatalf("visible sidebar row target = %q, want %q", got, targetSidebar)
	}
}
