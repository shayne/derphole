// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/charmbracelet/lipgloss"

var (
	topBarStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F8FAFC")).
			Background(lipgloss.Color("#155E75"))
	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E2E8F0")).
			Background(lipgloss.Color("#1E293B"))
	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#22D3EE"))
	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748B"))
	separatorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#334155")).
			Background(lipgloss.Color("#0F172A"))
	sidebarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E2E8F0")).
			Background(lipgloss.Color("#0F172A"))
	localChatStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#BBF7D0"))
	modalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8FAFC")).
			Background(lipgloss.Color("#111827")).
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#38BDF8")).
			Padding(0, 1)
)
