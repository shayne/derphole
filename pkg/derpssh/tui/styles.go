// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/charmbracelet/lipgloss"

var (
	catText     = adaptive("#4C4F69", "#CDD6F4")
	catSubtext1 = adaptive("#5C5F77", "#BAC2DE")
	catOverlay  = adaptive("#9CA0B0", "#6C7086")
	catSurface0 = adaptive("#CCD0DA", "#313244")
	catSurface2 = adaptive("#ACB0BE", "#585B70")
	catMantle   = adaptive("#E6E9EF", "#181825")
	catSapphire = adaptive("#209FB5", "#74C7EC")
	catGreen    = adaptive("#40A02B", "#A6E3A1")
	catRed      = adaptive("#D20F39", "#F38BA8")
)

var (
	chromeText      = catText
	chromeMuted     = catSubtext1
	chromeBar       = adaptive("#DCE0E8", "#313244")
	chromeChip      = catSurface0
	chromePanel     = adaptive("#E6E9EF", "#1E1E2E")
	chromePanelAlt  = adaptive("#DCE0E8", "#313244")
	chromeBorder    = adaptive("#7C7F93", "#74C7EC")
	chromeWarningBg = adaptive("#E6E9EF", "#45475A")
	chromeWarningFg = adaptive("#D20F39", "#F9E2AF")
	chromeOnAccent  = adaptive("#EFF1F5", "#11111B")
)

var (
	topBarStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(chromeBar)
	topBarBrandStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(chromeOnAccent).
				Background(catSapphire)
	topBarQuitStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(chromeOnAccent).
			Background(catRed)
	topBarChipStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(chromeChip)
	topBarMutedStyle = lipgloss.NewStyle().
				Foreground(chromeMuted).
				Background(chromeBar)
	topBarWarnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(chromeWarningFg).
			Background(chromeWarningBg)
	topBarActionStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(chromeOnAccent).
				Background(catGreen)
	topBarSeparatorStyle = lipgloss.NewStyle().
				Foreground(catOverlay).
				Background(chromeBar)
	statusBarStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(chromeBar)
	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(catSapphire).
			Background(chromePanel)
	dimStyle = lipgloss.NewStyle().
			Foreground(chromeMuted).
			Background(chromePanel)
	separatorStyle = lipgloss.NewStyle().
			Foreground(catSurface2)
	sidebarStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(catMantle)
	sidebarHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(catSapphire).
				Background(chromeBar)
	composerBorderStyle = lipgloss.NewStyle().
				Foreground(catSurface2).
				Background(catMantle)
	composerStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(chromeChip)
	composerPlaceholderStyle = lipgloss.NewStyle().
					Foreground(chromeMuted).
					Background(chromeChip)
	composerCursorStyle = composerStyle.Reverse(true)
	localChatStyle      = lipgloss.NewStyle().
				Foreground(catGreen)
	approvalButtonStyle = lipgloss.NewStyle().
				Foreground(chromeText).
				Background(chromePanelAlt)
	approvalButtonSelectedStyle = lipgloss.NewStyle().
					Bold(true).
					Foreground(chromeOnAccent).
					Background(catSapphire)
	modalStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(chromePanel).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(chromeBorder).
			Padding(0, 1)
	modalBorderStyle = lipgloss.NewStyle().
				Foreground(chromeBorder).
				Background(chromePanel)
	modalInteriorStyle = lipgloss.NewStyle().
				Foreground(chromeText).
				Background(chromePanel)
	menuLabelStyle = lipgloss.NewStyle().
			Foreground(chromeText).
			Background(chromePanel)
	menuShortcutStyle = lipgloss.NewStyle().
				Foreground(chromeMuted).
				Background(chromePanel)
)

func adaptive(light string, dark string) lipgloss.AdaptiveColor {
	return lipgloss.AdaptiveColor{Light: light, Dark: dark}
}
