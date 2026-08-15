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
	if got := colorString(styles.Separator.GetForeground()); got != "#484848" {
		t.Fatalf("separator foreground = %q, want #484848", got)
	}
	if got := styles.Separator.GetBackground(); got != nil {
		if _, ok := got.(lipgloss.NoColor); !ok {
			t.Fatalf("separator background = %T, want foreground-only divider", got)
		}
	}
}

func TestDarkThemeUsesOpenCodeSurfaces(t *testing.T) {
	styles := NewStyleSet(SchemeDark)
	tests := []struct {
		name       string
		style      lipgloss.Style
		foreground string
		background string
	}{
		{name: "top bar", style: styles.TopBar, foreground: "#EEEEEE", background: "#141414"},
		{name: "muted top bar", style: styles.TopBarMuted, foreground: "#808080", background: "#141414"},
		{name: "hover", style: styles.TopBarHover, foreground: "#EEEEEE", background: "#282828"},
		{name: "active", style: styles.TopBarActive, foreground: "#FAB283", background: "#1E1E1E"},
		{name: "sidebar", style: styles.Sidebar, foreground: "#EEEEEE", background: "#141414"},
		{name: "local message", style: styles.MessageLocal, foreground: "#EEEEEE", background: "#141414"},
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

func TestLightThemeUsesOpenCodeSurfaces(t *testing.T) {
	styles := NewStyleSet(SchemeLight)
	tests := []struct {
		name       string
		style      lipgloss.Style
		foreground string
		background string
	}{
		{name: "top bar", style: styles.TopBar, foreground: "#201E1B", background: "#F8F7F5"},
		{name: "muted top bar", style: styles.TopBarMuted, foreground: "#6F6A64", background: "#F8F7F5"},
		{name: "hover", style: styles.TopBarHover, foreground: "#201E1B", background: "#E8E4DF"},
		{name: "active", style: styles.TopBarActive, foreground: "#A9501E", background: "#E8E4DF"},
		{name: "sidebar", style: styles.Sidebar, foreground: "#201E1B", background: "#F8F7F5"},
		{name: "local message", style: styles.MessageLocal, foreground: "#201E1B", background: "#F8F7F5"},
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

func TestRestingHeaderMetadataUsesPanelAndSuccessColors(t *testing.T) {
	tests := []struct {
		scheme  ColorScheme
		panel   string
		success string
	}{
		{scheme: SchemeDark, panel: "#141414", success: "#7FD88F"},
		{scheme: SchemeLight, panel: "#F8F7F5", success: "#397A4A"},
	}
	for _, tt := range tests {
		t.Run(string(tt.scheme), func(t *testing.T) {
			app := NewApp(Options{Side: "host", DisplayName: "Shayne", Terminal: &fakePane{view: "ok"}})
			app.styles = NewStyleSet(tt.scheme)
			app.transport = "connected-direct"
			app.hostCols = 120
			app.hostRows = 40
			app.localRole = RoleWrite
			app.peers = []Peer{{ID: "guest-1", Name: "Alex", Role: RoleRead}}

			segments := append(app.identityTopBarSegments(), app.stateTopBarSegments()...)
			wantSuccess := map[string]bool{
				"● direct":    true,
				"● Alex/read": true,
			}
			seen := map[string]bool{}
			for _, segment := range segments {
				switch segment.text {
				case "host Shayne", "● direct", "120x40", "write", "● Alex/read":
					seen[segment.text] = true
					if got := colorString(segment.style.GetBackground()); got != tt.panel {
						t.Errorf("%q background = %q, want panel %q", segment.text, got, tt.panel)
					}
					if wantSuccess[segment.text] {
						if got := colorString(segment.style.GetForeground()); got != tt.success {
							t.Errorf("%q foreground = %q, want success %q", segment.text, got, tt.success)
						}
					}
				}
			}
			for _, label := range []string{"host Shayne", "● direct", "120x40", "write", "● Alex/read"} {
				if !seen[label] {
					t.Errorf("resting metadata missing %q in %+v", label, segments)
				}
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
