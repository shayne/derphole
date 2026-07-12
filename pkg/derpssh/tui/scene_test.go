// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestComposeSceneUsesFixedCanvasAndTopmostTarget(t *testing.T) {
	base := sceneLayer("base", Rect{X: 0, Y: 0, W: 5, H: 2}, 0, ".....\n.....")
	top := sceneLayer("top", Rect{X: 1, Y: 0, W: 2, H: 1}, 10, "界")
	scene := composeScene(5, 2, base, top)

	if scene.Width != 5 || scene.Height != 2 {
		t.Fatalf("scene size = %dx%d, want 5x2", scene.Width, scene.Height)
	}
	if got := scene.TargetAt(1, 0); got != "top" {
		t.Fatalf("TargetAt(1,0) = %q, want top", got)
	}
	if got := scene.TargetAt(4, 1); got != "base" {
		t.Fatalf("TargetAt(4,1) = %q, want base", got)
	}
	for i, line := range strings.Split(scene.Content, "\n") {
		if got := ansi.StringWidth(line); got > 5 {
			t.Fatalf("line %d width = %d, want <= 5: %q", i, got, line)
		}
	}
}

func TestSceneLayerClipsAndPadsContentToRect(t *testing.T) {
	layer := sceneLayer("panel", Rect{W: 4, H: 2}, 0, "界abc\nx\nextra")
	lines := strings.Split(layer.GetContent(), "\n")

	if len(lines) != 2 {
		t.Fatalf("layer lines = %d, want 2: %q", len(lines), layer.GetContent())
	}
	for i, line := range lines {
		if got := ansi.StringWidth(line); got != 4 {
			t.Fatalf("line %d width = %d, want 4: %q", i, got, line)
		}
	}
}
