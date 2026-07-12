// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"

	tea "charm.land/bubbletea/v2"
)

func keyCode(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code}
}

func textKey(text string) tea.KeyPressMsg {
	runes := []rune(text)
	var code rune
	if len(runes) == 1 {
		code = runes[0]
	} else {
		code = tea.KeyExtended
	}
	return tea.KeyPressMsg{Code: code, Text: text}
}

func modifiedKey(code rune, text string, mod tea.KeyMod) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code, Text: text, Mod: mod}
}

func clickAt(x, y int, button tea.MouseButton) tea.MouseClickMsg {
	return tea.MouseClickMsg{X: x, Y: y, Button: button}
}

func releaseAt(x, y int, button tea.MouseButton) tea.MouseReleaseMsg {
	return tea.MouseReleaseMsg{X: x, Y: y, Button: button}
}

func backgroundMsg(c color.Color) tea.BackgroundColorMsg {
	return tea.BackgroundColorMsg{Color: c}
}

func appContent(app *App) string {
	if app == nil {
		return ""
	}
	return app.View().Content
}
