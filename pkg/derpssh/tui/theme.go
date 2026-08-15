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
	BorderSubtle      ThemeRole = "BorderSubtle"
	BorderBase        ThemeRole = "BorderBase"
	BorderActive      ThemeRole = "BorderActive"
	AccentPrimary     ThemeRole = "AccentPrimary"
	AccentSecondary   ThemeRole = "AccentSecondary"
	StateSuccess      ThemeRole = "StateSuccess"
	MessageHover      ThemeRole = "MessageHover"
	MessagePressed    ThemeRole = "MessagePressed"
	CopiedFeedback    ThemeRole = "CopiedFeedback"
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
		BorderSubtle,
		BorderBase,
		BorderActive,
		AccentPrimary,
		AccentSecondary,
		StateSuccess,
		MessageHover,
		MessagePressed,
		CopiedFeedback,
	}
}

func themeRolesForScheme(scheme ColorScheme) map[ThemeRole]themeColorPair {
	if scheme == SchemeLight {
		return map[ThemeRole]themeColorPair{
			SurfaceBackground: {foreground: "#1A1A1A", background: "#FFFFFF"},
			SurfacePanel:      {foreground: "#1A1A1A", background: "#FAFAFA"},
			SurfaceElement:    {foreground: "#1A1A1A", background: "#F5F5F5"},
			BorderSubtle:      {foreground: "#D4D4D4", background: "#FFFFFF"},
			BorderBase:        {foreground: "#B8B8B8", background: "#FFFFFF"},
			BorderActive:      {foreground: "#A0A0A0", background: "#FFFFFF"},
			AccentPrimary:     {foreground: "#3B7DD8", background: "#FAFAFA"},
			AccentSecondary:   {foreground: "#7B5BB6", background: "#FAFAFA"},
			StateSuccess:      {foreground: "#3D9A57", background: "#FAFAFA"},
			ChromeBase:        {foreground: "#1A1A1A", background: "#FAFAFA"},
			ChromeMuted:       {foreground: "#686868", background: "#FAFAFA"},
			ChromeActive:      {foreground: "#0A0A0A", background: "#3B7DD8"},
			ChromeDanger:      {foreground: "#D1383D", background: "#FAFAFA"},
			ChromeNotice:      {foreground: "#1A1A1A", background: "#D68C27"},
			DialogBase:        {foreground: "#1A1A1A", background: "#FAFAFA"},
			DialogBorder:      {foreground: "#B8B8B8", background: "#FAFAFA"},
			DialogText:        {foreground: "#1A1A1A", background: "#FAFAFA"},
			DialogMuted:       {foreground: "#686868", background: "#FAFAFA"},
			ButtonDefault:     {foreground: "#1A1A1A", background: "#F5F5F5"},
			ButtonFocused:     {foreground: "#0A0A0A", background: "#3B7DD8"},
			ButtonDanger:      {foreground: "#FFFFFF", background: "#D1383D"},
			ChatBase:          {foreground: "#1A1A1A", background: "#FAFAFA"},
			ChatHeader:        {foreground: "#1A1A1A", background: "#F5F5F5"},
			ChatMessageUser:   {foreground: "#1A1A1A", background: "#FAFAFA"},
			ChatMessageSelf:   {foreground: "#1A1A1A", background: "#F5F5F5"},
			ChatPlaceholder:   {foreground: "#686868", background: "#F5F5F5"},
			ComposerBase:      {foreground: "#1A1A1A", background: "#F5F5F5"},
			ComposerCursor:    {foreground: "#0A0A0A", background: "#3B7DD8"},
			SelectionMode:     {foreground: "#1A1A1A", background: "#F5F5F5"},
			MessageHover:      {foreground: "#1A1A1A", background: "#F5F5F5"},
			MessagePressed:    {foreground: "#1A1A1A", background: "#FFFFFF"},
			CopiedFeedback:    {foreground: "#1A1A1A", background: "#3D9A57"},
		}
	}
	return map[ThemeRole]themeColorPair{
		SurfaceBackground: {foreground: "#EEEEEE", background: "#0A0A0A"},
		SurfacePanel:      {foreground: "#EEEEEE", background: "#141414"},
		SurfaceElement:    {foreground: "#EEEEEE", background: "#1E1E1E"},
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
		ChatMessageSelf:   {foreground: "#EEEEEE", background: "#1E1E1E"},
		ChatPlaceholder:   {foreground: "#808080", background: "#1E1E1E"},
		ComposerBase:      {foreground: "#EEEEEE", background: "#1E1E1E"},
		ComposerCursor:    {foreground: "#0A0A0A", background: "#FAB283"},
		SelectionMode:     {foreground: "#EEEEEE", background: "#1E1E1E"},
		MessageHover:      {foreground: "#EEEEEE", background: "#1E1E1E"},
		MessagePressed:    {foreground: "#EEEEEE", background: "#0A0A0A"},
		CopiedFeedback:    {foreground: "#0A0A0A", background: "#7FD88F"},
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
