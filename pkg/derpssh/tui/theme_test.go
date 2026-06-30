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
			DialogBase,
			DialogText,
			DialogMuted,
			ButtonFocused,
			ChatHeader,
			ChatPlaceholder,
			ComposerBase,
		} {
			if got := theme.ContrastRatio(role); got < 4.5 {
				t.Fatalf("%s %s contrast = %.2f, want >= 4.5", scheme, role, got)
			}
		}
	}
}

func TestThemeDefinesEveryRoleForLightAndDark(t *testing.T) {
	for _, scheme := range []ColorScheme{SchemeLight, SchemeDark} {
		theme := newTheme(scheme)
		for _, role := range allThemeRoles() {
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
