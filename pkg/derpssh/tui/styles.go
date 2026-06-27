// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/charmbracelet/lipgloss"

var (
	topBarStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#083344", Dark: "#F8FAFC"}).
			Background(lipgloss.AdaptiveColor{Light: "#A5F3FC", Dark: "#155E75"})
	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"}).
			Background(lipgloss.AdaptiveColor{Light: "#E2E8F0", Dark: "#1E293B"})
	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#22D3EE"})
	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#94A3B8"})
	separatorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#CBD5E1", Dark: "#334155"}).
			Background(lipgloss.AdaptiveColor{Light: "#F8FAFC", Dark: "#0F172A"})
	sidebarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#1E293B", Dark: "#E2E8F0"}).
			Background(lipgloss.AdaptiveColor{Light: "#F8FAFC", Dark: "#0F172A"})
	localChatStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#166534", Dark: "#BBF7D0"})
	modalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#111827", Dark: "#F8FAFC"}).
			Background(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#111827"}).
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.AdaptiveColor{Light: "#0284C7", Dark: "#38BDF8"}).
			Padding(0, 1)
)
