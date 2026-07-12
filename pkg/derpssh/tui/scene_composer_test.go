// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestComposerUsesTextareaViewAndRealCursor(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.setSidebarOpen(true)
	app.focusChat()
	app.composer.SetValue("abc")
	app.composer.SetCursorColumn(1)

	view := app.View()
	if view.Cursor == nil {
		t.Fatal("View().Cursor = nil, want textarea cursor")
	}
	if view.Cursor.Position.X < app.layout.Composer.X ||
		view.Cursor.Position.X >= app.layout.Composer.X+app.layout.Composer.W {
		t.Fatalf("cursor X = %d outside composer %+v", view.Cursor.Position.X, app.layout.Composer)
	}
	if !strings.Contains(view.Content, "abc") {
		t.Fatalf("view missing textarea content: %q", view.Content)
	}

	app.focusTerminal()
	if cursor := app.View().Cursor; cursor != nil {
		t.Fatalf("terminal-focused View().Cursor = %+v, want nil", cursor)
	}
}

func TestComposerDoesNotExposeCursorWithoutVisibleLayer(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 2})
	app.setSidebarOpen(true)
	app.focusChat()

	if cursor := app.View().Cursor; cursor != nil {
		t.Fatalf("View().Cursor = %+v without visible composer layer, want nil", cursor)
	}
}

func TestComposerCursorSuppressedWhenProductionSurfaceObscuresComposer(t *testing.T) {
	newFocusedApp := func(t *testing.T, opts Options) *App {
		t.Helper()
		app := NewApp(opts)
		app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		app.setSidebarOpen(true)
		app.focusChat()
		if cursor := app.View().Cursor; cursor == nil {
			t.Fatal("focused composer cursor = nil before opening surface")
		}
		return app
	}

	t.Run("invite", func(t *testing.T) {
		app := newFocusedApp(t, Options{
			Side:          "host",
			InviteCommand: "derpssh connect invite",
			Terminal:      &fakePane{view: "shell$"},
		})
		_ = app.openInvite()

		if cursor := app.View().Cursor; cursor != nil {
			t.Fatalf("invite View().Cursor = %+v, want nil", cursor)
		}
	})

	t.Run("modal", func(t *testing.T) {
		app := newFocusedApp(t, Options{Terminal: &fakePane{view: "shell$"}})
		_ = helpAction(app)

		if cursor := app.View().Cursor; cursor != nil {
			t.Fatalf("modal View().Cursor = %+v, want nil", cursor)
		}
	})
}

func TestComposerShortSidebarSynchronizesTextareaViewport(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 3})
	app.setSidebarOpen(true)
	app.focusChat()
	_ = app.View()

	app.composer.SetValue(strings.Repeat("a", app.layout.Composer.W*2) + "Z")
	if got := app.composer.Height(); got != 3 {
		t.Fatalf("natural textarea height = %d, want 3 before layout crop", got)
	}

	view := app.View()
	if app.layout.Sidebar.H != 2 || app.layout.Composer.H != 1 {
		t.Fatalf("short layout = sidebar %+v composer %+v, want heights 2 and 1", app.layout.Sidebar, app.layout.Composer)
	}
	if view.Cursor == nil {
		t.Fatal("short composer cursor = nil")
	}
	if view.Cursor.Y < app.layout.Composer.Y || view.Cursor.Y >= app.layout.Composer.Y+app.layout.Composer.H {
		t.Fatalf("cursor Y = %d outside cropped composer %+v", view.Cursor.Y, app.layout.Composer)
	}
	nativeCursor := app.composer.Cursor()
	if nativeCursor == nil {
		t.Fatal("native textarea cursor = nil")
	}
	if got, want := view.Cursor.X, app.layout.Composer.X+nativeCursor.X; got != want {
		t.Fatalf("root cursor X = %d, want native textarea offset %d", got, want)
	}
	if got, want := view.Cursor.Y, app.layout.Composer.Y+nativeCursor.Y; got != want {
		t.Fatalf("root cursor Y = %d, want native textarea offset %d", got, want)
	}

	lines := strings.Split(ansiPattern.ReplaceAllString(view.Content, ""), "\n")
	row := lines[app.layout.Composer.Y]
	composerRow := string([]rune(row)[app.layout.Composer.X:])
	if !strings.Contains(composerRow, "Z") {
		t.Fatalf("visible composer row does not contain cursor-adjacent tail marker: %q", row)
	}
	if nativeCursor.X < 1 || composerRow[nativeCursor.X-1] != 'Z' {
		t.Fatalf("native cursor X = %d is not aligned after tail marker in %q", nativeCursor.X, composerRow)
	}

	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	view = app.View()
	if got := app.layout.Composer.H; got != 3 {
		t.Fatalf("composer height after enlarging viewport = %d, want natural height 3", got)
	}
	if view.Cursor == nil || view.Cursor.Y < app.layout.Composer.Y || view.Cursor.Y >= app.layout.Composer.Y+app.layout.Composer.H {
		t.Fatalf("cursor after enlarging viewport = %+v outside composer %+v", view.Cursor, app.layout.Composer)
	}
}
