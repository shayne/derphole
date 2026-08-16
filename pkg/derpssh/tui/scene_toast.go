// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	targetToast layerTarget = "toast"
	toastLayerZ int         = 2000
)

func (a *App) buildToastLayers() []*lipgloss.Layer {
	text := strings.TrimSpace(a.toast.text)
	if text == "" || a.width < 12 || a.height < 4 {
		return nil
	}
	text = ansi.Truncate(text, maxInt(a.width-8, 1), "…")
	content := a.styles.Toast.Render(text)
	rect := Rect{
		X: maxInt(a.width-displayWidth(content)-1, 0),
		Y: 1,
		W: displayWidth(content),
		H: strings.Count(content, "\n") + 1,
	}
	return []*lipgloss.Layer{sceneLayer(targetToast, rect, toastLayerZ, content)}
}
