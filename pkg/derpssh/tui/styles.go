// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

type StyleSet struct {
	Scheme                                                                         ColorScheme
	TopBar, TopBarBrand, TopBarHover, TopBarPressed                                lipgloss.Style
	TopBarActive, TopBarDangerHover, TopBarSuccess                                 lipgloss.Style
	TopBarQuit, TopBarChip, TopBarMuted, TopBarWarn                                lipgloss.Style
	TopBarAction, TopBarSeparator, StatusBar                                       lipgloss.Style
	Sidebar, SidebarHeader, SidebarHeaderAction                                    lipgloss.Style
	SidebarHeaderActionHover                                                       lipgloss.Style
	Composer, ComposerHover, ComposerPlaceholder, ComposerCursor                   lipgloss.Style
	ComposerBorder, LocalChat                                                      lipgloss.Style
	MessageRemote, MessageLocal, MessageHover, MessageLocalHover, MessagePressed   lipgloss.Style
	MessageCopiedSurface                                                           lipgloss.Style
	MessageAuthorRemote, MessageAuthorLocal                                        lipgloss.Style
	MessageAccentRemote, MessageAccentLocal, MessageCopied                         lipgloss.Style
	Divider, DividerHover, DividerDragging                                         lipgloss.Style
	Modal, ModalInterior, ModalFooter, ModalBackdrop, Toast, Label, Dim, Separator lipgloss.Style
	ApprovalButton, ApprovalButtonSelected, ApprovalButtonHover                    lipgloss.Style
	ApprovalButtonPressed                                                          lipgloss.Style
	MenuLabel, MenuShortcut                                                        lipgloss.Style
}

func NewStyleSet(scheme ColorScheme) StyleSet {
	return newStyleSet(newTheme(scheme))
}

func NewTerminalStyleSet(background color.Color, foreground color.Color) StyleSet {
	return newStyleSet(newTerminalTheme(background, foreground))
}

func newStyleSet(theme Theme) StyleSet {
	role := func(r ThemeRole) lipgloss.Style { return theme.Role(r) }
	pickColor := func(r ThemeRole, foreground bool) color.Color {
		return theme.RoleColor(r, foreground)
	}
	composer := role(ComposerBase)
	composerPlaceholder := role(ChatPlaceholder).
		Background(pickColor(ComposerBase, false))
	return StyleSet{
		Scheme:            theme.scheme,
		TopBar:            role(ChromeBase),
		TopBarBrand:       role(ChromeBase).Foreground(pickColor(AccentPrimary, true)).Bold(true),
		TopBarHover:       role(SurfaceHover),
		TopBarPressed:     role(MessagePressed).Bold(true),
		TopBarActive:      role(MessageHover).Foreground(pickColor(AccentPrimary, true)).Bold(true),
		TopBarDangerHover: role(MessageHover).Foreground(pickColor(ChromeDanger, true)).Bold(true),
		TopBarSuccess:     role(StateSuccess),
		TopBarQuit:        role(ChromeDanger).Bold(true),
		TopBarChip:        role(ChromeBase),
		TopBarMuted:       role(ChromeMuted),
		TopBarWarn:        role(ChromeNotice).Bold(true),
		TopBarAction:      role(ChromeBase).Foreground(pickColor(AccentPrimary, true)).Bold(true),
		TopBarSeparator: lipgloss.NewStyle().
			Foreground(pickColor(BorderBase, true)).
			Background(pickColor(ChromeBase, false)),
		StatusBar:                role(ChromeBase),
		Sidebar:                  role(ChatBase),
		SidebarHeader:            role(ChatHeader).Bold(true),
		SidebarHeaderAction:      role(ChatHeader).Foreground(pickColor(AccentPrimary, true)).Bold(true),
		SidebarHeaderActionHover: role(MessageHover).Foreground(pickColor(AccentPrimary, true)).Bold(true),
		Composer:                 composer,
		ComposerHover:            composer.Background(pickColor(SurfacePanel, false)),
		ComposerPlaceholder:      composerPlaceholder,
		ComposerCursor:           role(ComposerCursor),
		ComposerBorder: lipgloss.NewStyle().
			Foreground(pickColor(BorderBase, true)).
			Background(pickColor(ChatBase, false)),
		LocalChat:            lipgloss.NewStyle().Foreground(pickColor(AccentPrimary, true)),
		MessageRemote:        role(ChatMessageUser),
		MessageLocal:         role(ChatMessageSelf),
		MessageHover:         role(MessageHover),
		MessageLocalHover:    role(MessageHover),
		MessagePressed:       role(MessagePressed),
		MessageCopiedSurface: role(MessageCopied),
		MessageAuthorRemote:  lipgloss.NewStyle().Foreground(pickColor(AccentSecondary, true)).Bold(true),
		MessageAuthorLocal:   lipgloss.NewStyle().Foreground(pickColor(AccentPrimary, true)).Bold(true),
		MessageAccentRemote:  lipgloss.NewStyle().Foreground(pickColor(AccentSecondary, true)),
		MessageAccentLocal:   lipgloss.NewStyle().Foreground(pickColor(AccentPrimary, true)),
		MessageCopied:        role(CopiedFeedback).Bold(true),
		Divider:              lipgloss.NewStyle().Foreground(pickColor(BorderBase, true)),
		DividerHover:         lipgloss.NewStyle().Foreground(pickColor(BorderActive, true)),
		DividerDragging:      lipgloss.NewStyle().Foreground(pickColor(AccentPrimary, true)),
		Modal: role(DialogBase).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pickColor(BorderSubtle, true)).
			Padding(0, 1),
		ModalInterior: role(DialogBase),
		ModalFooter:   role(SurfaceElement),
		ModalBackdrop: role(ModalBackdrop),
		Toast: role(DialogBase).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pickColor(BorderSubtle, true)).
			Padding(0, 1),
		Label: role(DialogText).Foreground(pickColor(AccentPrimary, true)).Bold(true),
		Dim:   role(DialogMuted),
		Separator: lipgloss.NewStyle().
			Foreground(pickColor(BorderBase, true)),
		ApprovalButton:         role(ButtonDefault),
		ApprovalButtonSelected: role(ButtonFocused).Bold(true),
		ApprovalButtonHover: role(ButtonDefault).
			Background(pickColor(SurfaceHover, false)).Bold(true),
		ApprovalButtonPressed: role(ButtonDefault).
			Background(pickColor(BorderBase, true)).Bold(true),
		MenuLabel:    role(DialogText),
		MenuShortcut: role(DialogMuted),
	}
}

func (a *App) interactionStyle(
	target layerTarget,
	base lipgloss.Style,
	hover lipgloss.Style,
	pressed lipgloss.Style,
) lipgloss.Style {
	if a.pressedTarget == target {
		return pressed
	}
	if a.hoverTarget == target {
		return hover
	}
	return base
}
