// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/charmbracelet/lipgloss"

var (
	topBarStyle       = adaptiveRoleStyle(ChromeBase)
	topBarBrandStyle  = adaptiveRoleStyle(ChromeActive).Bold(true)
	topBarQuitStyle   = adaptiveRoleStyle(ChromeDanger).Bold(true)
	topBarChipStyle   = adaptiveRoleStyle(ComposerBase)
	topBarMutedStyle  = adaptiveRoleStyle(ChromeMuted)
	topBarWarnStyle   = adaptiveRoleStyle(ChromeNotice).Bold(true)
	topBarActionStyle = adaptiveRoleStyle(ButtonFocused).
				Bold(true)
	topBarSeparatorStyle = lipgloss.NewStyle().
				Foreground(adaptiveRoleColor(DialogBorder, true)).
				Background(adaptiveRoleColor(ChromeBase, false))
	statusBarStyle = adaptiveRoleStyle(ChromeBase)
	labelStyle     = adaptiveRoleStyle(DialogText).
			Bold(true).
			Foreground(adaptiveRoleColor(ChromeActive, false))
	dimStyle       = adaptiveRoleStyle(DialogMuted)
	separatorStyle = lipgloss.NewStyle().
			Foreground(adaptiveRoleColor(DialogBorder, true))
	sidebarStyle        = adaptiveRoleStyle(ChatBase)
	sidebarHeaderStyle  = adaptiveRoleStyle(ChatHeader).Bold(true)
	composerBorderStyle = lipgloss.NewStyle().
				Foreground(adaptiveRoleColor(DialogBorder, true)).
				Background(adaptiveRoleColor(ChatBase, false))
	composerStyle            = adaptiveRoleStyle(ComposerBase)
	composerPlaceholderStyle = adaptiveRoleStyle(ChatPlaceholder)
	composerCursorStyle      = composerStyle.Reverse(true)
	localChatStyle           = lipgloss.NewStyle().
					Foreground(adaptiveRoleColor(ChatMessageUser, true))
	approvalButtonStyle         = adaptiveRoleStyle(ButtonDefault)
	approvalButtonSelectedStyle = adaptiveRoleStyle(ButtonFocused).Bold(true)
	modalStyle                  = adaptiveRoleStyle(DialogBase).
					Border(lipgloss.RoundedBorder()).
					BorderForeground(adaptiveRoleColor(DialogBorder, true)).
					Padding(0, 1)
	modalBorderStyle   = adaptiveRoleStyle(DialogBorder)
	modalInteriorStyle = adaptiveRoleStyle(DialogBase)
	menuLabelStyle     = adaptiveRoleStyle(DialogText)
	menuShortcutStyle  = adaptiveRoleStyle(DialogMuted)
)
