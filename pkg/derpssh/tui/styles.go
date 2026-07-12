// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

type StyleSet struct {
	Scheme                         ColorScheme
	TopBar, TopBarBrand            lipgloss.Style
	TopBarQuit, TopBarChip         lipgloss.Style
	TopBarMuted, TopBarWarn        lipgloss.Style
	TopBarAction, TopBarSeparator  lipgloss.Style
	StatusBar                      lipgloss.Style
	Sidebar, SidebarHeader         lipgloss.Style
	Composer, ComposerPlaceholder  lipgloss.Style
	ComposerCursor, ComposerBorder lipgloss.Style
	LocalChat                      lipgloss.Style
	Modal, ModalInterior           lipgloss.Style
	Label, Dim, Separator          lipgloss.Style
	ApprovalButton                 lipgloss.Style
	ApprovalButtonSelected         lipgloss.Style
	MenuLabel, MenuShortcut        lipgloss.Style
}

func NewStyleSet(scheme ColorScheme) StyleSet {
	theme := newTheme(scheme)
	role := func(r ThemeRole) lipgloss.Style { return theme.Role(r) }
	pickColor := func(r ThemeRole, foreground bool) color.Color {
		return theme.RoleColor(r, foreground)
	}
	composer := role(ComposerBase)
	composerPlaceholder := role(ChatPlaceholder).
		Background(pickColor(ComposerBase, false))
	return StyleSet{
		Scheme:       theme.scheme,
		TopBar:       role(ChromeBase),
		TopBarBrand:  role(ChromeActive).Bold(true),
		TopBarQuit:   role(ChromeDanger).Bold(true),
		TopBarChip:   role(ComposerBase),
		TopBarMuted:  role(ChromeMuted),
		TopBarWarn:   role(ChromeNotice).Bold(true),
		TopBarAction: role(ButtonFocused).Bold(true),
		TopBarSeparator: lipgloss.NewStyle().
			Foreground(pickColor(DialogBorder, true)).
			Background(pickColor(ChromeBase, false)),
		StatusBar:           role(ChromeBase),
		Sidebar:             role(ChatBase),
		SidebarHeader:       role(ChatHeader).Bold(true),
		Composer:            composer,
		ComposerPlaceholder: composerPlaceholder,
		ComposerCursor:      role(ComposerCursor),
		ComposerBorder: lipgloss.NewStyle().
			Foreground(pickColor(DialogBorder, true)).
			Background(pickColor(ChatBase, false)),
		LocalChat: lipgloss.NewStyle().
			Foreground(pickColor(ChatMessageUser, true)),
		Modal: role(DialogBase).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pickColor(DialogBorder, true)).
			Padding(0, 1),
		ModalInterior: role(DialogBase),
		Label: role(DialogText).Bold(true).
			Foreground(pickColor(ChromeActive, false)),
		Dim: role(DialogMuted),
		Separator: lipgloss.NewStyle().
			Foreground(pickColor(DialogBorder, true)),
		ApprovalButton:         role(ButtonDefault),
		ApprovalButtonSelected: role(ButtonFocused).Bold(true),
		MenuLabel:              role(DialogText),
		MenuShortcut:           role(DialogMuted),
	}
}
