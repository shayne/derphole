// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/charmbracelet/lipgloss"

var (
	catText     = adaptive("#4C4F69", "#CDD6F4")
	catSubtext  = adaptive("#6C6F85", "#A6ADC8")
	catOverlay  = adaptive("#9CA0B0", "#6C7086")
	catSurface0 = adaptive("#CCD0DA", "#313244")
	catSurface1 = adaptive("#BCC0CC", "#45475A")
	catSurface2 = adaptive("#ACB0BE", "#585B70")
	catMantle   = adaptive("#E6E9EF", "#181825")
	catSapphire = adaptive("#209FB5", "#74C7EC")
	catGreen    = adaptive("#40A02B", "#A6E3A1")
	catYellow   = adaptive("#DF8E1D", "#F9E2AF")
	catRed      = adaptive("#D20F39", "#F38BA8")
)

var (
	topBarStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catSurface0)
	topBarBrandStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(adaptive("#EFF1F5", "#11111B")).
				Background(catSapphire)
	topBarQuitStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(adaptive("#EFF1F5", "#11111B")).
			Background(catRed)
	topBarChipStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catSurface1)
	topBarMutedStyle = lipgloss.NewStyle().
				Foreground(catSubtext).
				Background(catSurface0)
	topBarWarnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(adaptive("#4C4F69", "#11111B")).
			Background(catYellow)
	topBarActionStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(adaptive("#EFF1F5", "#11111B")).
				Background(catGreen)
	topBarSeparatorStyle = lipgloss.NewStyle().
				Foreground(catOverlay).
				Background(catSurface0)
	statusBarStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catSurface0)
	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(catSapphire).
			Background(catMantle)
	dimStyle = lipgloss.NewStyle().
			Foreground(catSubtext).
			Background(catMantle)
	separatorStyle = lipgloss.NewStyle().
			Foreground(catSurface2)
	sidebarStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catMantle)
	sidebarHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(catSapphire).
				Background(catSurface0)
	composerBorderStyle = lipgloss.NewStyle().
				Foreground(catSurface2).
				Background(catMantle)
	composerStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catSurface0)
	localChatStyle = lipgloss.NewStyle().
			Foreground(catGreen)
	approvalButtonStyle = lipgloss.NewStyle().
				Foreground(catText).
				Background(catSurface0)
	approvalButtonSelectedStyle = lipgloss.NewStyle().
					Bold(true).
					Foreground(adaptive("#EFF1F5", "#11111B")).
					Background(catSapphire)
	modalStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catMantle).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(catSapphire).
			Padding(0, 1)
	modalBorderStyle = lipgloss.NewStyle().
				Foreground(catSapphire).
				Background(catMantle)
	modalInteriorStyle = lipgloss.NewStyle().
				Foreground(catText).
				Background(catMantle)
	menuLabelStyle = lipgloss.NewStyle().
			Foreground(catText).
			Background(catMantle)
	menuShortcutStyle = lipgloss.NewStyle().
				Foreground(catSubtext).
				Background(catMantle)
)

func adaptive(light string, dark string) lipgloss.AdaptiveColor {
	return lipgloss.AdaptiveColor{Light: light, Dark: dark}
}
