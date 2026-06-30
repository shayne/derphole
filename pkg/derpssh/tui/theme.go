// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
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
	}
}

func adaptiveRoleStyle(role ThemeRole) lipgloss.Style {
	return lipgloss.NewStyle().
		Foreground(adaptiveRoleColor(role, true)).
		Background(adaptiveRoleColor(role, false))
}

func adaptiveRoleColor(role ThemeRole, foreground bool) lipgloss.AdaptiveColor {
	light := newTheme(SchemeLight).roles[role]
	dark := newTheme(SchemeDark).roles[role]
	if light.foreground == "" || dark.foreground == "" {
		light = newTheme(SchemeLight).roles[ChromeBase]
		dark = newTheme(SchemeDark).roles[ChromeBase]
	}
	if foreground {
		return lipgloss.AdaptiveColor{Light: light.foreground, Dark: dark.foreground}
	}
	return lipgloss.AdaptiveColor{Light: light.background, Dark: dark.background}
}

func themeRolesForScheme(scheme ColorScheme) map[ThemeRole]themeColorPair {
	if scheme == SchemeLight {
		return map[ThemeRole]themeColorPair{
			ChromeBase:      {"#4C4F69", "#DCE0E8"},
			ChromeMuted:     {"#5C5F77", "#DCE0E8"},
			ChromeActive:    {"#11111B", "#209FB5"},
			ChromeDanger:    {"#EFF1F5", "#D20F39"},
			ChromeNotice:    {"#D20F39", "#E6E9EF"},
			DialogBase:      {"#4C4F69", "#E6E9EF"},
			DialogBorder:    {"#7C7F93", "#E6E9EF"},
			DialogText:      {"#4C4F69", "#E6E9EF"},
			DialogMuted:     {"#5C5F77", "#E6E9EF"},
			ButtonDefault:   {"#4C4F69", "#DCE0E8"},
			ButtonFocused:   {"#11111B", "#209FB5"},
			ButtonDanger:    {"#EFF1F5", "#D20F39"},
			ChatBase:        {"#4C4F69", "#E6E9EF"},
			ChatHeader:      {"#4C4F69", "#DCE0E8"},
			ChatMessageUser: {"#40A02B", "#E6E9EF"},
			ChatMessageSelf: {"#4C4F69", "#E6E9EF"},
			ChatPlaceholder: {"#4C4F69", "#CCD0DA"},
			ComposerBase:    {"#4C4F69", "#CCD0DA"},
			ComposerCursor:  {"#EFF1F5", "#4C4F69"},
			SelectionMode:   {"#4C4F69", "#CCD0DA"},
		}
	}
	return map[ThemeRole]themeColorPair{
		ChromeBase:      {"#CDD6F4", "#313244"},
		ChromeMuted:     {"#BAC2DE", "#313244"},
		ChromeActive:    {"#11111B", "#74C7EC"},
		ChromeDanger:    {"#11111B", "#F38BA8"},
		ChromeNotice:    {"#F9E2AF", "#45475A"},
		DialogBase:      {"#CDD6F4", "#1E1E2E"},
		DialogBorder:    {"#74C7EC", "#1E1E2E"},
		DialogText:      {"#CDD6F4", "#1E1E2E"},
		DialogMuted:     {"#BAC2DE", "#1E1E2E"},
		ButtonDefault:   {"#CDD6F4", "#313244"},
		ButtonFocused:   {"#11111B", "#74C7EC"},
		ButtonDanger:    {"#11111B", "#F38BA8"},
		ChatBase:        {"#CDD6F4", "#181825"},
		ChatHeader:      {"#CDD6F4", "#313244"},
		ChatMessageUser: {"#A6E3A1", "#181825"},
		ChatMessageSelf: {"#CDD6F4", "#181825"},
		ChatPlaceholder: {"#BAC2DE", "#313244"},
		ComposerBase:    {"#CDD6F4", "#313244"},
		ComposerCursor:  {"#11111B", "#CDD6F4"},
		SelectionMode:   {"#CDD6F4", "#45475A"},
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
