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

func newTerminalTheme(background color.Color, foreground color.Color) Theme {
	scheme := terminalColorScheme(background)
	fallback := newTheme(scheme)
	backgroundHex := terminalColorHex(background, fallback.roles[SurfaceBackground].background)
	foregroundHex := terminalColorHex(foreground, fallback.roles[SurfaceBackground].foreground)

	panelMix, elementMix, hoverMix := 0.06, 0.11, 0.16
	borderSubtleMix, borderBaseMix, borderActiveMix := 0.23, 0.32, 0.43
	mutedMix, pressedMix, copiedMix := 0.64, 0.22, 0.16
	if scheme == SchemeLight {
		panelMix, elementMix, hoverMix = 0.035, 0.07, 0.12
		borderSubtleMix, borderBaseMix, borderActiveMix = 0.18, 0.25, 0.35
		mutedMix, pressedMix, copiedMix = 0.58, 0.17, 0.11
	}

	panel := mixHexColors(backgroundHex, foregroundHex, panelMix)
	element := mixHexColors(backgroundHex, foregroundHex, elementMix)
	hover := mixHexColors(backgroundHex, foregroundHex, hoverMix)
	pressed := mixHexColors(backgroundHex, foregroundHex, pressedMix)
	copied := mixHexColors(backgroundHex, fallback.roles[StateSuccess].foreground, copiedMix)
	muted := mixHexColors(backgroundHex, foregroundHex, mutedMix)
	borderSubtle := mixHexColors(backgroundHex, foregroundHex, borderSubtleMix)
	borderBase := mixHexColors(backgroundHex, foregroundHex, borderBaseMix)
	borderActive := mixHexColors(backgroundHex, foregroundHex, borderActiveMix)

	roles := fallback.roles
	roles[SurfaceBackground] = themeColorPair{foreground: foregroundHex, background: backgroundHex}
	roles[SurfacePanel] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[SurfaceElement] = themeColorPair{foreground: foregroundHex, background: element}
	roles[SurfaceHover] = themeColorPair{foreground: foregroundHex, background: hover}
	roles[BorderSubtle] = themeColorPair{foreground: borderSubtle, background: backgroundHex}
	roles[BorderBase] = themeColorPair{foreground: borderBase, background: backgroundHex}
	roles[BorderActive] = themeColorPair{foreground: borderActive, background: backgroundHex}
	roles[AccentPrimary] = themeColorPair{foreground: fallback.roles[AccentPrimary].foreground, background: panel}
	roles[AccentSecondary] = themeColorPair{foreground: fallback.roles[AccentSecondary].foreground, background: panel}
	roles[StateSuccess] = themeColorPair{foreground: fallback.roles[StateSuccess].foreground, background: panel}
	roles[ChromeBase] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[ChromeMuted] = themeColorPair{foreground: muted, background: panel}
	roles[ChromeDanger] = themeColorPair{foreground: fallback.roles[ChromeDanger].foreground, background: panel}
	roles[DialogBase] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[DialogBorder] = themeColorPair{foreground: borderBase, background: panel}
	roles[DialogText] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[DialogMuted] = themeColorPair{foreground: muted, background: panel}
	roles[ButtonDefault] = themeColorPair{foreground: foregroundHex, background: element}
	roles[ChatBase] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[ChatHeader] = themeColorPair{foreground: foregroundHex, background: element}
	roles[ChatMessageUser] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[ChatMessageSelf] = themeColorPair{foreground: foregroundHex, background: panel}
	roles[ChatPlaceholder] = themeColorPair{foreground: muted, background: element}
	roles[ComposerBase] = themeColorPair{foreground: foregroundHex, background: element}
	roles[ComposerCursor] = themeColorPair{foreground: fallback.roles[ComposerCursor].foreground, background: element}
	roles[SelectionMode] = themeColorPair{foreground: foregroundHex, background: element}
	roles[MessageHover] = themeColorPair{foreground: foregroundHex, background: hover}
	roles[MessagePressed] = themeColorPair{foreground: foregroundHex, background: pressed}
	roles[MessageCopied] = themeColorPair{foreground: foregroundHex, background: copied}
	roles[ModalBackdrop] = themeColorPair{foreground: muted, background: pressed}

	return Theme{scheme: scheme, roles: roles}
}

func terminalColorScheme(background color.Color) ColorScheme {
	if background == nil {
		return SchemeDark
	}
	r, g, b, _ := background.RGBA()
	rgb := [3]float64{float64(r >> 8), float64(g >> 8), float64(b >> 8)}
	if relativeLuminance(rgb) > 0.42 {
		return SchemeLight
	}
	return SchemeDark
}

func terminalColorHex(value color.Color, fallback string) string {
	if value == nil {
		return fallback
	}
	r, g, b, _ := value.RGBA()
	return fmt.Sprintf("#%02X%02X%02X", uint8(r>>8), uint8(g>>8), uint8(b>>8))
}

func mixHexColors(from string, to string, amount float64) string {
	amount = math.Max(0, math.Min(amount, 1))
	start := mustParseHexColor(from)
	end := mustParseHexColor(to)
	component := func(index int) uint8 {
		return uint8(math.Round(start[index] + (end[index]-start[index])*amount))
	}
	return fmt.Sprintf("#%02X%02X%02X", component(0), component(1), component(2))
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
