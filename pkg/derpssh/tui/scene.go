// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type Scene struct {
	Width      int
	Height     int
	Content    string
	Canvas     *lipgloss.Canvas
	Compositor *lipgloss.Compositor
	Cursor     *tea.Cursor
}

func composeScene(width int, height int, layers ...*lipgloss.Layer) Scene {
	width = maxInt(width, 1)
	height = maxInt(height, 1)
	canvas := lipgloss.NewCanvas(width, height)
	compositor := lipgloss.NewCompositor(layers...)
	canvas.Compose(compositor)
	return Scene{
		Width:      width,
		Height:     height,
		Content:    canvas.Render(),
		Canvas:     canvas,
		Compositor: compositor,
	}
}

func (s Scene) TargetAt(x int, y int) layerTarget {
	if s.Compositor == nil {
		return ""
	}
	hit := s.Compositor.Hit(x, y)
	if hit.Empty() {
		return ""
	}
	return layerTarget(hit.ID())
}

func (s Scene) PointerCmd(capture layerTarget, msg tea.MouseMsg) tea.Cmd {
	target := capture
	if target == "" {
		mouse := msg.Mouse()
		target = s.TargetAt(mouse.X, mouse.Y)
	}
	return func() tea.Msg { return newPointerMsg(target, msg) }
}

func sceneLayer(id layerTarget, rect Rect, z int, content string) *lipgloss.Layer {
	return lipgloss.NewLayer(fitSceneContent(content, rect.W, rect.H)).
		ID(string(id)).
		X(rect.X).
		Y(rect.Y).
		Z(z)
}

func fitSceneContent(content string, width int, height int) string {
	width = maxInt(width, 0)
	height = maxInt(height, 0)
	if height == 0 {
		return ""
	}

	source := strings.Split(content, "\n")
	lines := make([]string, height)
	for i := range lines {
		if i < len(source) {
			lines[i] = ansi.Truncate(source[i], width, "")
		}
		lines[i] += strings.Repeat(" ", maxInt(width-ansi.StringWidth(lines[i]), 0))
	}
	return strings.Join(lines, "\n")
}
