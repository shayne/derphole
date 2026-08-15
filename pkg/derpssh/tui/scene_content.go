// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
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

	layers := []*lipgloss.Layer{
		sceneLayer(targetSidebar, layout.Sidebar, sidebarLayerZ, sceneFill(a.styles.Sidebar, layout.Sidebar)),
	}
	layers = append(layers, a.buildSidebarHeaderLayers(layout.Sidebar)...)
	layers = append(layers, a.buildChatMessageLayers(layout.Sidebar)...)
	if !layout.Divider.empty() {
		layers = append(layers, a.buildDividerLayer(layout.Divider))
	}
	if composer := a.composerLayer(layout); composer != nil {
		layers = append(layers, composer)
	}
	return layers
}

func (a *App) buildChatMessageLayers(sidebar Rect) []*lipgloss.Layer {
	reserved := a.sidebarComposerRows(sidebar.H)
	messageViewport := Rect{
		X: sidebar.X,
		Y: sidebar.Y + 1,
		W: sidebar.W,
		H: maxInt(sidebar.H-1-reserved, 0),
	}
	blocks := visibleChatBlocks(a.chatRows(messageViewport.W), messageViewport, a.chatScroll)
	layers := make([]*lipgloss.Layer, 0, len(blocks))
	for _, block := range blocks {
		if block.messageIndex < 0 || block.messageIndex >= len(a.chatMessages) {
			continue
		}
		target := chatMessageTarget(block.messageIndex)
		accent := a.styles.MessageAccentRemote
		surface := a.styles.MessageRemote
		local := a.chatMessages[block.messageIndex].Local
		if local {
			accent = a.styles.MessageAccentLocal
			surface = a.styles.MessageLocal
		}
		if a.hoverTarget == target {
			if local {
				surface = a.styles.MessageLocalHover
			} else {
				surface = a.styles.MessageHover
			}
		}
		if a.pressedTarget == target {
			surface = a.styles.MessagePressed
		}
		content := prefixChatBlock(block.content, accent.Render("┃")+" ")
		content = surface.Width(block.rect.W).Height(block.rect.H).Render(content)
		layers = append(layers, sceneLayer(target, block.rect, sidebarLayerZ+1, content))
	}
	return layers
}

func (a *App) buildSidebarHeaderLayers(sidebar Rect) []*lipgloss.Layer {
	if sidebar.empty() {
		return nil
	}
	headerRect := Rect{X: sidebar.X, Y: sidebar.Y, W: maxInt(sidebar.W-1, 0), H: 1}
	header := a.styles.SidebarHeader.Render("◈ Chat") +
		a.styles.TopBarMuted.Render(fmt.Sprintf(" %d peers", len(a.peers)))
	layers := []*lipgloss.Layer{
		sceneLayer(targetSidebar, headerRect, sidebarLayerZ+1, header),
	}
	closeTarget := actionTarget(ActionToggleChat)
	closeStyle := a.styles.SidebarHeaderAction
	if a.hoverTarget == closeTarget {
		closeStyle = a.styles.SidebarHeaderActionHover
	}
	if a.pressedTarget == closeTarget {
		closeStyle = a.styles.TopBarPressed
	}
	closeRect := Rect{X: sidebar.X + sidebar.W - 1, Y: sidebar.Y, W: 1, H: 1}
	return append(layers, sceneLayer(closeTarget, closeRect, sidebarLayerZ+2, closeStyle.Render("×")))
}

func (a *App) buildDividerLayer(rect Rect) *lipgloss.Layer {
	style := a.styles.Divider
	if a.draggingDivider {
		style = a.styles.DividerDragging
	} else if a.hoverTarget == targetDivider {
		style = a.styles.DividerHover
	}
	line := style.Render(strings.Repeat("┃", rect.W))
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
	contentRect := composerContentRect(rect)
	content := fitSceneContent(a.composer.View(), contentRect.W, contentRect.H)
	if contentRect.X > rect.X {
		content = prefixChatBlock(content, a.styles.MessageAccentLocal.Render("┃")+" ")
	}
	surface := a.styles.Composer
	if a.hoverTarget == targetComposer {
		surface = a.styles.ComposerHover
	}
	content = surface.Width(rect.W).Height(rect.H).Render(content)
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
	contentRect := composerContentRect(a.layout.Composer)
	cursor.X += contentRect.X
	cursor.Y += contentRect.Y
	return cursor
}

func (a *App) prepareComposerViewport(layout Layout) bool {
	if !a.composerLayerVisible(layout) {
		return false
	}
	contentRect := composerContentRect(layout.Composer)
	a.composer.SetWidth(maxInt(contentRect.W, 1))
	height := maxInt(contentRect.H, 1)
	if a.composer.Height() != height {
		_ = a.composer.View()
		a.composer.SetHeight(height)
	}
	return true
}

func composerContentRect(rect Rect) Rect {
	if rect.W <= 2 {
		return rect
	}
	return Rect{X: rect.X + 2, Y: rect.Y, W: rect.W - 2, H: rect.H}
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
