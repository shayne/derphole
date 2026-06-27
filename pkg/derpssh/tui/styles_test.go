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
		{name: "separator", style: separatorStyle},
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
