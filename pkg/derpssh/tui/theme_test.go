// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "testing"

func TestThemeRolesHaveReadableContrast(t *testing.T) {
	for _, scheme := range []ColorScheme{SchemeLight, SchemeDark} {
		theme := newTheme(scheme)
		for _, role := range []ThemeRole{
			ChromeActive,
			ChromeMuted,
			ChromeNotice,
			ChatBase,
			ChatHeader,
			ChatMessageUser,
			ChatMessageSelf,
			ComposerBase,
			MessageHover,
			MessagePressed,
		} {
			if got := theme.ContrastRatio(role); got < 4.5 {
				t.Fatalf("%s %s contrast = %.2f, want >= 4.5", scheme, role, got)
			}
		}
	}
}

func TestDarkChatPlaceholderKeepsOpenCodeMutedText(t *testing.T) {
	// The approved OpenCode color has 4.22:1 contrast on the composer element;
	// it is intentionally the only exception to TestThemeRolesHaveReadableContrast.
	style := newTheme(SchemeDark).Role(ChatPlaceholder)
	if got := colorString(style.GetForeground()); got != "#808080" {
		t.Fatalf("foreground = %q, want #808080", got)
	}
	if got := colorString(style.GetBackground()); got != "#1E1E1E" {
		t.Fatalf("background = %q, want #1E1E1E", got)
	}
}

func TestLightThemeUsesWarmNeutralSurfacesAndOrangeBlueChatAccents(t *testing.T) {
	theme := newTheme(SchemeLight)
	if got := colorString(theme.Role(SurfaceBackground).GetBackground()); got != "#FDFCFB" {
		t.Fatalf("light background = %q, want warm #FDFCFB", got)
	}
	if got := colorString(theme.Role(SurfacePanel).GetBackground()); got != "#F8F7F5" {
		t.Fatalf("light panel = %q, want #F8F7F5", got)
	}
	if got := colorString(theme.Role(AccentPrimary).GetForeground()); got != "#A9501E" {
		t.Fatalf("light local accent = %q, want orange #A9501E", got)
	}
	if got := colorString(theme.Role(AccentSecondary).GetForeground()); got != "#2F69B3" {
		t.Fatalf("light remote accent = %q, want blue #2F69B3", got)
	}
}

func TestDarkComposerCursorUsesVisibleWarmColor(t *testing.T) {
	style := newTheme(SchemeDark).Role(ComposerCursor)
	if got := colorString(style.GetForeground()); got != "#FAB283" {
		t.Fatalf("dark composer cursor = %q, want warm #FAB283", got)
	}
}

func TestThemeDefinesEveryRoleForLightAndDark(t *testing.T) {
	expectedOpenCodeRoles := []ThemeRole{
		"SurfaceBackground",
		"SurfacePanel",
		"SurfaceElement",
		"BorderSubtle",
		"BorderBase",
		"BorderActive",
		"AccentPrimary",
		"AccentSecondary",
		"StateSuccess",
		"MessageHover",
		"MessagePressed",
		"CopiedFeedback",
	}
	for _, role := range expectedOpenCodeRoles {
		if !themeRoleIncluded(allThemeRoles(), role) {
			t.Fatalf("allThemeRoles missing %s", role)
		}
	}

	for _, scheme := range []ColorScheme{SchemeLight, SchemeDark} {
		theme := newTheme(scheme)
		for _, role := range allThemeRoles() {
			if _, ok := theme.roles[role]; !ok {
				t.Fatalf("%s %s missing role colors", scheme, role)
			}
			style := theme.Role(role)
			if style.GetForeground() == nil {
				t.Fatalf("%s %s missing foreground", scheme, role)
			}
			if style.GetBackground() == nil {
				t.Fatalf("%s %s missing background", scheme, role)
			}
		}
	}
}

func themeRoleIncluded(roles []ThemeRole, want ThemeRole) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}
