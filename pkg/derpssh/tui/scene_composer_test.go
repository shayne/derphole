// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"
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
	contentRect := composerContentRect(app.layout.Composer)
	if view.Cursor.Position.X < contentRect.X ||
		view.Cursor.Position.X >= contentRect.X+contentRect.W {
		t.Fatalf("cursor X = %d outside composer content %+v", view.Cursor.Position.X, contentRect)
	}
	if !strings.Contains(view.Content, "abc") {
		t.Fatalf("view missing textarea content: %q", view.Content)
	}

	app.focusTerminal()
	if cursor := app.View().Cursor; cursor != nil {
		t.Fatalf("terminal-focused View().Cursor = %+v, want nil", cursor)
	}
}

func TestTerminalUsesChildCursorShapeBlinkColorAndPosition(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 80, 23)
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if _, err := pane.Write([]byte("abc\x1b[6 q\x1b]12;#ABCDEF\x07")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := app.View()
	if view.Cursor == nil {
		t.Fatal("terminal-focused View().Cursor = nil, want child cursor")
	}
	if got, want := view.Cursor.Position, (tea.Position{X: 3, Y: app.layout.Terminal.Y}); got != want {
		t.Fatalf("cursor position = %+v, want %+v", got, want)
	}
	if view.Cursor.Shape != tea.CursorBar || view.Cursor.Blink {
		t.Fatalf("cursor shape/blink = %v/%v, want steady bar", view.Cursor.Shape, view.Cursor.Blink)
	}
	wantColor := color.RGBA{R: 0xAB, G: 0xCD, B: 0xEF, A: 0xFF}
	if got := colorString(view.Cursor.Color); got != colorString(wantColor) {
		t.Fatalf("cursor color = %q, want %q", got, colorString(wantColor))
	}
	if strings.Contains(view.Content, "\x1b[7m") {
		t.Fatalf("native cursor still rendered as reverse-video content: %q", view.Content)
	}
}

func TestTerminalChildCursorIsSuppressedBehindModal(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 80, 23)
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	_ = helpAction(app)

	if cursor := app.View().Cursor; cursor != nil {
		t.Fatalf("modal View().Cursor = %+v, want nil", cursor)
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
	contentRect := composerContentRect(app.layout.Composer)
	if got, want := view.Cursor.X, contentRect.X+nativeCursor.X; got != want {
		t.Fatalf("root cursor X = %d, want native textarea offset %d", got, want)
	}
	if got, want := view.Cursor.Y, app.layout.Composer.Y+nativeCursor.Y; got != want {
		t.Fatalf("root cursor Y = %d, want native textarea offset %d", got, want)
	}

	lines := strings.Split(ansiPattern.ReplaceAllString(view.Content, ""), "\n")
	row := lines[app.layout.Composer.Y]
	composerRow := string([]rune(row)[contentRect.X:])
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

func TestComposerContentRectReservesAccentColumnsWhenWideEnough(t *testing.T) {
	tests := []struct {
		name string
		rect Rect
		want Rect
	}{
		{name: "wide", rect: Rect{X: 70, Y: 20, W: 24, H: 3}, want: Rect{X: 72, Y: 20, W: 22, H: 3}},
		{name: "two columns", rect: Rect{X: 7, Y: 2, W: 2, H: 1}, want: Rect{X: 7, Y: 2, W: 2, H: 1}},
		{name: "one column", rect: Rect{X: 7, Y: 2, W: 1, H: 1}, want: Rect{X: 7, Y: 2, W: 1, H: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := composerContentRect(tc.rect); got != tc.want {
				t.Fatalf("composerContentRect(%+v) = %+v, want %+v", tc.rect, got, tc.want)
			}
		})
	}
}
