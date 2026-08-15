// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"image/color"
	"math"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
)

type ColorScheme string

const (
	SchemeLight ColorScheme = "light"
	SchemeDark  ColorScheme = "dark"
)

type ThemeRole string

const (
	ChromeBase      ThemeRole = "ChromeBase"
	ChromeMuted     ThemeRole = "ChromeMuted"
	ChromeActive    ThemeRole = "ChromeActive"
	ChromeDanger    ThemeRole = "ChromeDanger"
	ChromeNotice    ThemeRole = "ChromeNotice"
	DialogBase      ThemeRole = "DialogBase"
	DialogBorder    ThemeRole = "DialogBorder"
	DialogText      ThemeRole = "DialogText"
	DialogMuted     ThemeRole = "DialogMuted"
	ButtonDefault   ThemeRole = "ButtonDefault"
	ButtonFocused   ThemeRole = "ButtonFocused"
	ButtonDanger    ThemeRole = "ButtonDanger"
	ChatBase        ThemeRole = "ChatBase"
	ChatHeader      ThemeRole = "ChatHeader"
	ChatMessageUser ThemeRole = "ChatMessageUser"
	ChatMessageSelf ThemeRole = "ChatMessageSelf"
	ChatPlaceholder ThemeRole = "ChatPlaceholder"
	ComposerBase    ThemeRole = "ComposerBase"
	ComposerCursor  ThemeRole = "ComposerCursor"
	SelectionMode   ThemeRole = "SelectionMode"

	SurfaceBackground ThemeRole = "SurfaceBackground"
	SurfacePanel      ThemeRole = "SurfacePanel"
	SurfaceElement    ThemeRole = "SurfaceElement"
	SurfaceHover      ThemeRole = "SurfaceHover"
	BorderSubtle      ThemeRole = "BorderSubtle"
	BorderBase        ThemeRole = "BorderBase"
	BorderActive      ThemeRole = "BorderActive"
	AccentPrimary     ThemeRole = "AccentPrimary"
	AccentSecondary   ThemeRole = "AccentSecondary"
	StateSuccess      ThemeRole = "StateSuccess"
	MessageHover      ThemeRole = "MessageHover"
	MessagePressed    ThemeRole = "MessagePressed"
	MessageCopied     ThemeRole = "MessageCopied"
	CopiedFeedback    ThemeRole = "CopiedFeedback"
	ModalBackdrop     ThemeRole = "ModalBackdrop"
)

type themeColorPair struct {
	foreground string
	background string
}

type Theme struct {
	scheme ColorScheme
	roles  map[ThemeRole]themeColorPair
}

func newTheme(scheme ColorScheme) Theme {
	if scheme != SchemeLight && scheme != SchemeDark {
		scheme = SchemeDark
	}
	return Theme{scheme: scheme, roles: themeRolesForScheme(scheme)}
}

func (t Theme) Role(role ThemeRole) lipgloss.Style {
	colors := t.roles[role]
	if colors.foreground == "" || colors.background == "" {
		colors = t.roles[ChromeBase]
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(colors.foreground)).
		Background(lipgloss.Color(colors.background))
}

func (t Theme) RoleColor(role ThemeRole, foreground bool) color.Color {
	colors := t.roles[role]
	if colors.foreground == "" || colors.background == "" {
		colors = t.roles[ChromeBase]
	}
	value := colors.background
	if foreground {
		value = colors.foreground
	}
	return lipgloss.Color(value)
}

func (t Theme) ContrastRatio(role ThemeRole) float64 {
	colors := t.roles[role]
	return contrastRatio(colors.foreground, colors.background)
}

func allThemeRoles() []ThemeRole {
	return []ThemeRole{
		ChromeBase,
		ChromeMuted,
		ChromeActive,
		ChromeDanger,
		ChromeNotice,
		DialogBase,
		DialogBorder,
		DialogText,
		DialogMuted,
		ButtonDefault,
		ButtonFocused,
		ButtonDanger,
		ChatBase,
		ChatHeader,
		ChatMessageUser,
		ChatMessageSelf,
		ChatPlaceholder,
		ComposerBase,
		ComposerCursor,
		SelectionMode,
		SurfaceBackground,
		SurfacePanel,
		SurfaceElement,
		SurfaceHover,
		BorderSubtle,
		BorderBase,
		BorderActive,
		AccentPrimary,
		AccentSecondary,
		StateSuccess,
		MessageHover,
		MessagePressed,
		MessageCopied,
		CopiedFeedback,
		ModalBackdrop,
	}
}

func themeRolesForScheme(scheme ColorScheme) map[ThemeRole]themeColorPair {
	if scheme == SchemeLight {
		return map[ThemeRole]themeColorPair{
			SurfaceBackground: {foreground: "#201E1B", background: "#FDFCFB"},
			SurfacePanel:      {foreground: "#201E1B", background: "#F8F7F5"},
			SurfaceElement:    {foreground: "#201E1B", background: "#F1EFEC"},
			SurfaceHover:      {foreground: "#201E1B", background: "#E8E4DF"},
			BorderSubtle:      {foreground: "#D6D0C9", background: "#FDFCFB"},
			BorderBase:        {foreground: "#BEB6AD", background: "#FDFCFB"},
			BorderActive:      {foreground: "#9E958B", background: "#FDFCFB"},
			AccentPrimary:     {foreground: "#A9501E", background: "#F8F7F5"},
			AccentSecondary:   {foreground: "#2F69B3", background: "#F8F7F5"},
			StateSuccess:      {foreground: "#397A4A", background: "#F8F7F5"},
			ChromeBase:        {foreground: "#201E1B", background: "#F8F7F5"},
			ChromeMuted:       {foreground: "#6F6A64", background: "#F8F7F5"},
			ChromeActive:      {foreground: "#FDFCFB", background: "#A9501E"},
			ChromeDanger:      {foreground: "#B7353A", background: "#F8F7F5"},
			ChromeNotice:      {foreground: "#FDFCFB", background: "#A9501E"},
			DialogBase:        {foreground: "#201E1B", background: "#F8F7F5"},
			DialogBorder:      {foreground: "#9E958B", background: "#F8F7F5"},
			DialogText:        {foreground: "#201E1B", background: "#F8F7F5"},
			DialogMuted:       {foreground: "#6F6A64", background: "#F8F7F5"},
			ButtonDefault:     {foreground: "#201E1B", background: "#F1EFEC"},
			ButtonFocused:     {foreground: "#FDFCFB", background: "#A9501E"},
			ButtonDanger:      {foreground: "#FDFCFB", background: "#B7353A"},
			ChatBase:          {foreground: "#201E1B", background: "#F8F7F5"},
			ChatHeader:        {foreground: "#201E1B", background: "#F1EFEC"},
			ChatMessageUser:   {foreground: "#201E1B", background: "#F8F7F5"},
			ChatMessageSelf:   {foreground: "#201E1B", background: "#F8F7F5"},
			ChatPlaceholder:   {foreground: "#6F6A64", background: "#F1EFEC"},
			ComposerBase:      {foreground: "#201E1B", background: "#F1EFEC"},
			ComposerCursor:    {foreground: "#A9501E", background: "#F1EFEC"},
			SelectionMode:     {foreground: "#201E1B", background: "#F1EFEC"},
			MessageHover:      {foreground: "#201E1B", background: "#E8E4DF"},
			MessagePressed:    {foreground: "#201E1B", background: "#DED9D3"},
			MessageCopied:     {foreground: "#201E1B", background: "#E4F0E5"},
			CopiedFeedback:    {foreground: "#FDFCFB", background: "#397A4A"},
			ModalBackdrop:     {foreground: "#8A837B", background: "#DED9D3"},
		}
	}
	return map[ThemeRole]themeColorPair{
		SurfaceBackground: {foreground: "#EEEEEE", background: "#0A0A0A"},
		SurfacePanel:      {foreground: "#EEEEEE", background: "#141414"},
		SurfaceElement:    {foreground: "#EEEEEE", background: "#1E1E1E"},
		SurfaceHover:      {foreground: "#EEEEEE", background: "#282828"},
		BorderSubtle:      {foreground: "#3C3C3C", background: "#0A0A0A"},
		BorderBase:        {foreground: "#484848", background: "#0A0A0A"},
		BorderActive:      {foreground: "#606060", background: "#0A0A0A"},
		AccentPrimary:     {foreground: "#FAB283", background: "#141414"},
		AccentSecondary:   {foreground: "#5C9CF5", background: "#141414"},
		StateSuccess:      {foreground: "#7FD88F", background: "#141414"},
		ChromeBase:        {foreground: "#EEEEEE", background: "#141414"},
		ChromeMuted:       {foreground: "#808080", background: "#141414"},
		ChromeActive:      {foreground: "#0A0A0A", background: "#FAB283"},
		ChromeDanger:      {foreground: "#E06C75", background: "#141414"},
		ChromeNotice:      {foreground: "#0A0A0A", background: "#F5A742"},
		DialogBase:        {foreground: "#EEEEEE", background: "#141414"},
		DialogBorder:      {foreground: "#484848", background: "#141414"},
		DialogText:        {foreground: "#EEEEEE", background: "#141414"},
		DialogMuted:       {foreground: "#808080", background: "#141414"},
		ButtonDefault:     {foreground: "#EEEEEE", background: "#1E1E1E"},
		ButtonFocused:     {foreground: "#0A0A0A", background: "#FAB283"},
		ButtonDanger:      {foreground: "#0A0A0A", background: "#E06C75"},
		ChatBase:          {foreground: "#EEEEEE", background: "#141414"},
		ChatHeader:        {foreground: "#EEEEEE", background: "#1E1E1E"},
		ChatMessageUser:   {foreground: "#EEEEEE", background: "#141414"},
		ChatMessageSelf:   {foreground: "#EEEEEE", background: "#141414"},
		ChatPlaceholder:   {foreground: "#808080", background: "#1E1E1E"},
		ComposerBase:      {foreground: "#EEEEEE", background: "#1E1E1E"},
		ComposerCursor:    {foreground: "#FAB283", background: "#1E1E1E"},
		SelectionMode:     {foreground: "#EEEEEE", background: "#1E1E1E"},
		MessageHover:      {foreground: "#EEEEEE", background: "#1E1E1E"},
		MessagePressed:    {foreground: "#EEEEEE", background: "#0A0A0A"},
		MessageCopied:     {foreground: "#EEEEEE", background: "#203425"},
		CopiedFeedback:    {foreground: "#0A0A0A", background: "#7FD88F"},
		ModalBackdrop:     {foreground: "#606060", background: "#0A0A0A"},
	}
}

func contrastRatio(foreground string, background string) float64 {
	fg := relativeLuminance(mustParseHexColor(foreground))
	bg := relativeLuminance(mustParseHexColor(background))
	light := math.Max(fg, bg)
	dark := math.Min(fg, bg)
	return (light + 0.05) / (dark + 0.05)
}

func relativeLuminance(rgb [3]float64) float64 {
	return 0.2126*linearRGB(rgb[0]) + 0.7152*linearRGB(rgb[1]) + 0.0722*linearRGB(rgb[2])
}

func linearRGB(v float64) float64 {
	v = v / 255
	if v <= 0.03928 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func mustParseHexColor(value string) [3]float64 {
	value = strings.TrimPrefix(strings.TrimSpace(value), "#")
	if len(value) != 6 {
		panic(fmt.Sprintf("invalid color %q", value))
	}
	var rgb [3]float64
	for i := 0; i < 3; i++ {
		component, err := strconv.ParseUint(value[i*2:i*2+2], 16, 8)
		if err != nil {
			panic(fmt.Sprintf("invalid color %q: %v", value, err))
		}
		rgb[i] = float64(component)
	}
	return rgb
}
