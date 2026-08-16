// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

const notificationMaxRunes = 160

func desktopNotification(title string, body string) tea.Cmd {
	title = sanitizeNotification(title)
	body = sanitizeNotification(body)
	payload := body
	if title != "" && body != "" {
		payload = title + ": " + body
	} else if title != "" {
		payload = title
	}
	if payload == "" {
		return nil
	}
	runes := []rune(payload)
	if len(runes) > notificationMaxRunes {
		runes = append(runes[:notificationMaxRunes-1], '…')
		payload = string(runes)
	}
	return tea.Raw(ansi.Notify(payload))
}

func sanitizeNotification(value string) string {
	value = ansi.Strip(value)
	var b strings.Builder
	space := false
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
