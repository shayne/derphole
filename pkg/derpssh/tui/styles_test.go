// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"image/color"
	"testing"

	"charm.land/lipgloss/v2"
)

func TestStructuralStylesUseConcreteSchemeBackgrounds(t *testing.T) {
	for _, scheme := range []ColorScheme{SchemeLight, SchemeDark} {
		styles := NewStyleSet(scheme)
		tests := []struct {
			name  string
			style lipgloss.Style
		}{
			{name: "top bar", style: styles.TopBar},
			{name: "status bar", style: styles.StatusBar},
			{name: "sidebar", style: styles.Sidebar},
			{name: "modal", style: styles.Modal},
		}
		for _, tt := range tests {
			t.Run(string(scheme)+"/"+tt.name, func(t *testing.T) {
				if got := tt.style.GetBackground(); got == nil {
					t.Fatalf("%s background = nil, want concrete color", tt.name)
				}
			})
		}
	}
}

func TestSeparatorStyleUsesConcreteForegroundOnly(t *testing.T) {
	styles := NewStyleSet(SchemeDark)
	if got := colorString(styles.Separator.GetForeground()); got != "#74C7EC" {
		t.Fatalf("separator foreground = %q, want #74C7EC", got)
	}
	if got := styles.Separator.GetBackground(); got != nil {
		if _, ok := got.(lipgloss.NoColor); !ok {
			t.Fatalf("separator background = %T, want foreground-only divider", got)
		}
	}
}

func TestLightThemeChromeUsesRestrainedCatppuccinSurfaces(t *testing.T) {
	styles := NewStyleSet(SchemeLight)
	tests := []struct {
		name       string
		style      lipgloss.Style
		foreground string
		background string
	}{
		{name: "muted top bar text", style: styles.TopBarMuted, foreground: "#5C5F77", background: "#DCE0E8"},
		{name: "warning top bar chip", style: styles.TopBarWarn, foreground: "#D20F39", background: "#E6E9EF"},
		{name: "modal interior", style: styles.ModalInterior, foreground: "#4C4F69", background: "#E6E9EF"},
		{name: "modal label", style: styles.Label, foreground: "#209FB5", background: "#E6E9EF"},
		{name: "default modal button", style: styles.ApprovalButton, foreground: "#4C4F69", background: "#DCE0E8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := colorString(tt.style.GetForeground()); got != tt.foreground {
				t.Fatalf("foreground = %q, want %q", got, tt.foreground)
			}
			if got := colorString(tt.style.GetBackground()); got != tt.background {
				t.Fatalf("background = %q, want %q", got, tt.background)
			}
		})
	}
}

func colorString(value any) string {
	if c, ok := value.(color.Color); ok {
		r, g, b, _ := c.RGBA()
		return fmt.Sprintf("#%02X%02X%02X", uint8(r>>8), uint8(g>>8), uint8(b>>8))
	}
	return fmt.Sprint(value)
}
