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

	fmt.Fprintf(&b, "derpssh %s | %dx%d | role %s\n", m.mode, m.cols, m.rows, m.role)
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

	if m.pendingGuest.id != "" {
		fmt.Fprintf(&b, "\napprove %s (%s): [r]ead [w]rite\n", m.pendingGuest.name, m.pendingGuest.id)
	}

	return b.String()
}
