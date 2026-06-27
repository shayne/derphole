// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strings"
)

func (m Model) View() string {
	var b strings.Builder

	fmt.Fprintf(&b, "derpssh %s | host %dx%d | role %s | transport %s", m.mode, m.cols, m.rows, m.role, valueOr(m.transport, "starting"))
	if m.peerName != "" {
		fmt.Fprintf(&b, " | peer %s/%s", m.peerName, m.peerRole)
	}
	fmt.Fprintf(&b, " | focus %s\n", valueOr(m.focus, "terminal"))

	if m.inviteCommand != "" {
		fmt.Fprintf(&b, "invite: %s\n", m.inviteCommand)
	}

	b.WriteString("\nterminal\n")
	b.WriteString(strings.Repeat("-", 72))
	b.WriteString("\n")

	if m.terminalText == "" {
		b.WriteString("[terminal idle]\n")
	} else {
		b.WriteString(m.terminalText)
		if !strings.HasSuffix(m.terminalText, "\n") {
			b.WriteString("\n")
		}
	}

	b.WriteString("\nsidechat\n")
	b.WriteString(strings.Repeat("-", 72))
	b.WriteString("\n")
	if len(m.sidechatLines) == 0 {
		b.WriteString("(no messages)\n")
	} else {
		for _, line := range m.sidechatLines {
			b.WriteString(line)
			if !strings.HasSuffix(line, "\n") {
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("\nstatus\n")
	b.WriteString(strings.Repeat("-", 72))
	b.WriteString("\n")
	b.WriteString(":chat MESSAGE sends sidechat | host: :read :write :kick | terminal input goes to shared PTY\n")

	if m.pendingGuest.id != "" {
		fmt.Fprintf(&b, "\napprove %s (%s): [r]ead [w]rite [n]o\n", m.pendingGuest.name, m.pendingGuest.id)
	}

	return b.String()
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
