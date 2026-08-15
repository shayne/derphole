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
	app.chatMessages = []ChatMessage{{Author: "alex", Body: "hello"}}
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
	if !strings.Contains(dividerContent, "┃") {
		t.Fatalf("divider content = %q, want vertical separator", dividerContent)
	}
	if got := scene.TargetAt(app.layout.Sidebar.X+1, app.layout.Sidebar.Y+3); got != targetSidebar {
		t.Fatalf("sidebar target = %q", got)
	}
	if got := scene.TargetAt(app.layout.Sidebar.X+1, app.layout.Sidebar.Y+1); got != chatMessageTarget(0) {
		t.Fatalf("message target = %q, want %q", got, chatMessageTarget(0))
	}
	if got := scene.TargetAt(app.layout.Sidebar.X+app.layout.Sidebar.W-1, app.layout.Sidebar.Y); got != actionTarget(ActionToggleChat) {
		t.Fatalf("sidebar close target = %q, want %q", got, actionTarget(ActionToggleChat))
	}
	if got := scene.TargetAt(app.layout.Composer.X+1, app.layout.Composer.Y); got != targetComposer {
		t.Fatalf("composer target = %q", got)
	}
	if got := scene.TargetAt(app.width-2, 0); !strings.HasPrefix(string(got), "action:") {
		t.Fatalf("top bar target = %q, want action", got)
	}
}

func TestChatMessageHoverChangesStyleWithoutChangingText(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	app.chatMessages = []ChatMessage{{Author: "alex", Body: "hello"}}

	normal := app.buildScene().Content
	app.hoverTarget = chatMessageTarget(0)
	hovered := app.buildScene().Content
	if normal == hovered {
		t.Fatal("message hover did not change rendered style")
	}
	if ansiPattern.ReplaceAllString(normal, "") != ansiPattern.ReplaceAllString(hovered, "") {
		t.Fatal("message hover changed visible text")
	}
}

func TestLocalMessageAndComposerHoverChangeANSIOnlyInBothSchemes(t *testing.T) {
	for _, scheme := range []ColorScheme{SchemeDark, SchemeLight} {
		t.Run(string(scheme), func(t *testing.T) {
			app := NewApp(Options{DisplayName: "local", Terminal: &fakePane{view: "shell$"}})
			app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
			app.styles = NewStyleSet(scheme)
			app.configureComposerStyles()
			app.setSidebarOpen(true)
			app.chatMessages = []ChatMessage{{Author: "local", Body: "hover me", Local: true}}
			app.composer.SetValue("draft")

			assertHover := func(t *testing.T, target layerTarget) {
				t.Helper()
				app.hoverTarget = ""
				normalScene := app.buildScene()
				normal := normalScene.Compositor.GetLayer(string(target))
				if normal == nil {
					t.Fatalf("normal layer %q missing", target)
				}
				normalANSI := normal.GetContent()
				normalPlain := ansiPattern.ReplaceAllString(normalANSI, "")
				normalGeometry := [4]int{normal.GetX(), normal.GetY(), normal.Width(), normal.Height()}

				app.hoverTarget = target
				hoverScene := app.buildScene()
				hovered := hoverScene.Compositor.GetLayer(string(target))
				if hovered == nil {
					t.Fatalf("hovered layer %q missing", target)
				}
				hoverANSI := hovered.GetContent()
				if hoverANSI == normalANSI {
					t.Fatalf("%s %q hover left ANSI rendering unchanged", scheme, target)
				}
				if hoverPlain := ansiPattern.ReplaceAllString(hoverANSI, ""); hoverPlain != normalPlain {
					t.Fatalf("%s %q hover changed visible text: %q -> %q", scheme, target, normalPlain, hoverPlain)
				}
				hoverGeometry := [4]int{hovered.GetX(), hovered.GetY(), hovered.Width(), hovered.Height()}
				if hoverGeometry != normalGeometry {
					t.Fatalf("%s %q hover changed geometry: %v -> %v", scheme, target, normalGeometry, hoverGeometry)
				}
			}

			t.Run("local message", func(t *testing.T) {
				assertHover(t, chatMessageTarget(0))
			})
			t.Run("composer", func(t *testing.T) {
				assertHover(t, targetComposer)
			})
		})
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
