// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/charmbracelet/lipgloss"

var (
	topBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"}).
			Background(lipgloss.AdaptiveColor{Light: "#E2E8F0", Dark: "#1E293B"})
	topBarBrandStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.AdaptiveColor{Light: "#083344", Dark: "#F8FAFC"}).
				Background(lipgloss.AdaptiveColor{Light: "#A5F3FC", Dark: "#155E75"})
	topBarQuitStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#7F1D1D", Dark: "#FEE2E2"}).
			Background(lipgloss.AdaptiveColor{Light: "#FECACA", Dark: "#7F1D1D"})
	topBarChipStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"}).
			Background(lipgloss.AdaptiveColor{Light: "#E0F2FE", Dark: "#1E3A5F"})
	topBarMutedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "#334155", Dark: "#CBD5E1"}).
				Background(lipgloss.AdaptiveColor{Light: "#E2E8F0", Dark: "#243044"})
	topBarWarnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#713F12", Dark: "#FEF3C7"}).
			Background(lipgloss.AdaptiveColor{Light: "#FEF3C7", Dark: "#92400E"})
	topBarActionStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.AdaptiveColor{Light: "#064E3B", Dark: "#D1FAE5"}).
				Background(lipgloss.AdaptiveColor{Light: "#CCFBF1", Dark: "#065F46"})
	topBarSeparatorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#94A3B8"}).
				Background(lipgloss.AdaptiveColor{Light: "#E2E8F0", Dark: "#1E293B"})
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
	sidebarHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#22D3EE"}).
				Background(lipgloss.AdaptiveColor{Light: "#F8FAFC", Dark: "#0F172A"})
	localChatStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#166534", Dark: "#BBF7D0"})
	approvalButtonStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "#334155", Dark: "#CBD5E1"}).
				Background(lipgloss.AdaptiveColor{Light: "#F1F5F9", Dark: "#1F2937"})
	approvalButtonSelectedStyle = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#08111F"}).
					Background(lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#67E8F9"})
	modalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#111827", Dark: "#F8FAFC"}).
			Background(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#111827"}).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.AdaptiveColor{Light: "#0284C7", Dark: "#38BDF8"}).
			Padding(0, 1)
)
