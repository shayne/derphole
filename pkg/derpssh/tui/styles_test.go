// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestStructuralStylesUseAdaptiveBackgrounds(t *testing.T) {
	tests := []struct {
		name  string
		style lipgloss.Style
	}{
		{name: "top bar", style: topBarStyle},
		{name: "status bar", style: statusBarStyle},
		{name: "sidebar", style: sidebarStyle},
		{name: "modal", style: modalStyle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.style.GetBackground().(lipgloss.AdaptiveColor); !ok {
				t.Fatalf("%s background = %T, want lipgloss.AdaptiveColor", tt.name, tt.style.GetBackground())
			}
		})
	}
}

func TestSeparatorStyleUsesAdaptiveForegroundOnly(t *testing.T) {
	if _, ok := separatorStyle.GetForeground().(lipgloss.AdaptiveColor); !ok {
		t.Fatalf("separator foreground = %T, want lipgloss.AdaptiveColor", separatorStyle.GetForeground())
	}
	if got := separatorStyle.GetBackground(); got != nil {
		if _, ok := got.(lipgloss.NoColor); !ok {
			t.Fatalf("separator background = %T, want foreground-only divider", got)
		}
	}
}

func TestLightThemeChromeUsesRestrainedCatppuccinSurfaces(t *testing.T) {
	tests := []struct {
		name       string
		style      lipgloss.Style
		foreground string
		background string
	}{
		{
			name:       "muted top bar text",
			style:      topBarMutedStyle,
			foreground: "#5C5F77",
			background: "#DCE0E8",
		},
		{
			name:       "warning top bar chip",
			style:      topBarWarnStyle,
			foreground: "#D20F39",
			background: "#E6E9EF",
		},
		{
			name:       "modal interior",
			style:      modalInteriorStyle,
			foreground: "#4C4F69",
			background: "#E6E9EF",
		},
		{
			name:       "modal label",
			style:      labelStyle,
			foreground: "#209FB5",
			background: "#E6E9EF",
		},
		{
			name:       "default modal button",
			style:      approvalButtonStyle,
			foreground: "#4C4F69",
			background: "#DCE0E8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lightColor(t, tt.style.GetForeground()); got != tt.foreground {
				t.Fatalf("foreground = %q, want %q", got, tt.foreground)
			}
			if got := lightColor(t, tt.style.GetBackground()); got != tt.background {
				t.Fatalf("background = %q, want %q", got, tt.background)
			}
		})
	}
}

func TestModalBorderMatchesNeutralPanel(t *testing.T) {
	if got := lightColor(t, modalBorderStyle.GetBackground()); got != lightColor(t, modalInteriorStyle.GetBackground()) {
		t.Fatalf("modal border background = %q, want modal interior background", got)
	}
	if got := darkColor(t, modalBorderStyle.GetBackground()); got != darkColor(t, modalInteriorStyle.GetBackground()) {
		t.Fatalf("modal border dark background = %q, want modal interior background", got)
	}
}

func lightColor(t *testing.T, color any) string {
	t.Helper()
	adaptiveColor, ok := color.(lipgloss.AdaptiveColor)
	if !ok {
		t.Fatalf("color = %T, want lipgloss.AdaptiveColor", color)
	}
	return adaptiveColor.Light
}

func darkColor(t *testing.T, color any) string {
	t.Helper()
	adaptiveColor, ok := color.(lipgloss.AdaptiveColor)
	if !ok {
		t.Fatalf("color = %T, want lipgloss.AdaptiveColor", color)
	}
	return adaptiveColor.Dark
}
