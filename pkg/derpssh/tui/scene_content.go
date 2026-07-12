// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	targetBase     layerTarget = "base"
	targetTerminal layerTarget = "terminal"
	targetSidebar  layerTarget = "sidebar"
	targetComposer layerTarget = "composer"
	targetDivider  layerTarget = "divider:chat"
)

const (
	baseLayerZ = iota
	terminalLayerZ
	sidebarLayerZ
	composerLayerZ
)

const inviteLayerZ = 100

func (a *App) buildBaseLayers(layout Layout) []*lipgloss.Layer {
	if layout.Outer.empty() {
		return nil
	}

	base := sceneLayer(targetBase, layout.Outer, baseLayerZ, sceneFill(lipgloss.NewStyle(), layout.Outer))
	if a.inviteOpen {
		return []*lipgloss.Layer{
			base,
			sceneLayer(targetBase, layout.Outer, inviteLayerZ, a.inviteView()),
		}
	}

	a.setTerminalCursorActive(a.focus == FocusTerminal && !a.copyMode && !a.modalActive())
	layers := []*lipgloss.Layer{base}
	if terminal := a.buildTerminalLayer(layout); terminal != nil {
		layers = append(layers, terminal)
	}
	return append(layers, a.buildSidebarLayers(layout)...)
}

func (a *App) buildTerminalLayer(layout Layout) *lipgloss.Layer {
	terminal := layout.Terminal
	if a.guestChatOverlay() {
		terminal = Rect{
			X: layout.Outer.X,
			Y: layout.Terminal.Y,
			W: layout.Outer.W,
			H: layout.Terminal.H,
		}
	}
	if terminal.empty() {
		return nil
	}
	return sceneLayer(
		targetTerminal,
		terminal,
		terminalLayerZ,
		a.terminal.View(terminal.W, terminal.H),
	)
}

func (a *App) buildSidebarLayers(layout Layout) []*lipgloss.Layer {
	if !layout.SidebarOpen || layout.Sidebar.empty() {
		return nil
	}

	sidebar := a.sidebarLines(layout.Sidebar.W, layout.Sidebar.H)
	layers := []*lipgloss.Layer{sceneLayer(
		targetSidebar,
		layout.Sidebar,
		sidebarLayerZ,
		strings.Join(sidebar, "\n"),
	)}
	if !layout.Divider.empty() {
		layers = append(layers, a.buildDividerLayer(layout.Divider))
	}
	if composer := a.composerLayer(layout); composer != nil {
		layers = append(layers, composer)
	}
	return layers
}

func (a *App) buildDividerLayer(rect Rect) *lipgloss.Layer {
	line := a.styles.Separator.Render(strings.Repeat("│", rect.W))
	content := make([]string, rect.H)
	for i := range content {
		content[i] = line
	}
	return sceneLayer(targetDivider, rect, composerLayerZ, strings.Join(content, "\n"))
}

func (a *App) composerLayer(layout Layout) *lipgloss.Layer {
	if !a.prepareComposerViewport(layout) {
		return nil
	}
	rect := layout.Composer
	content := fitSceneContent(a.composer.View(), rect.W, rect.H)
	return sceneLayer(targetComposer, rect, composerLayerZ, content)
}

func (a *App) composerCursor() *tea.Cursor {
	if a.focus != FocusChat || !a.prepareComposerViewport(a.layout) {
		return nil
	}
	cursor := a.composer.Cursor()
	if cursor == nil {
		return nil
	}
	cursor.X += a.layout.Composer.X
	cursor.Y += a.layout.Composer.Y
	return cursor
}

func (a *App) prepareComposerViewport(layout Layout) bool {
	if !a.composerLayerVisible(layout) {
		return false
	}
	a.composer.SetWidth(maxInt(layout.Composer.W, 1))
	height := maxInt(layout.Composer.H, 1)
	if a.composer.Height() != height {
		_ = a.composer.View()
		a.composer.SetHeight(height)
	}
	return true
}

func (a *App) composerLayerVisible(layout Layout) bool {
	return !a.copyMode && !a.inviteOpen && !a.modalActive() &&
		layout.SidebarOpen && !layout.Sidebar.empty() &&
		!layout.Composer.empty() && layout.Sidebar.H >= 2
}

func sceneFill(style lipgloss.Style, rect Rect) string {
	if rect.empty() {
		return ""
	}
	line := style.Render(strings.Repeat(" ", rect.W))
	lines := make([]string, rect.H)
	for i := range lines {
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
