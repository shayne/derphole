# Charm v2 TUI Replatform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replatform Derpssh onto the current Bubble Tea, Bubbles, and Lip Gloss v2 APIs while preserving terminal-sharing behavior and replacing custom composition, hit-testing, cursor, and terminal-I/O paths with the applicable v2 abstractions.

**Architecture:** Keep Derpssh's application state, layout policy, VT emulator, PTY encoder, and session transport. Move outer rendering into a fixed Lip Gloss canvas composed from semantic layers, make `tea.View` declarative, route mouse events through rendered layer IDs, render chat with Bubbles textarea and its real cursor, and let Bubble Tea own capability queries, color downsampling, terminal modes, and clipboard output.

**Tech Stack:** Go 1.26.1, `charm.land/bubbletea/v2` v2.0.8, `charm.land/bubbles/v2` v2.1.1, `charm.land/lipgloss/v2` v2.0.5, `github.com/charmbracelet/x/ansi` v0.11.7, GitButler CLI, `mise`.

## Global Constraints

- Upgrade Bubble Tea, Bubbles, and Lip Gloss together; no final mixed v1/v2 imports.
- Do not import `charm.land/lipgloss/v2/compat` or recreate v1 key, rune, renderer, or adaptive-color shims.
- Preserve the existing visual language, shortcuts, layout, permission model, wire protocol, and VT emulator.
- Request alternate keys, all keys as escape codes, and associated text; do not request key-release events.
- Preserve embedded-shell default foreground and background semantics; do not set terminal-wide `tea.View` colors.
- Keep `TerminalLifecycle` as the idempotent abnormal-exit restore path.
- Do not hand-edit or commit generated `dist/` contents.
- Do not publish a release.
- Use `mise` for Go and repository commands.
- Use GitButler for every version-control write. Before each task commit, run `but diff` and pass only that task's runtime-assigned file or hunk IDs to `but commit codex/charm-v2-tui-replatform-design --changes`; never include another active session's changes.
- Before implementation, invoke `superpowers:test-driven-development`. Before completion claims, invoke `superpowers:verification-before-completion`.

---

## File responsibility map

- `go.mod`, `go.sum`: exact Charm v2 dependency graph.
- `pkg/derpssh/tui/app.go`: application state, update loop, declarative root view, and focus/state transitions; rendering helpers move out.
- `pkg/derpssh/tui/styles.go`: per-app `StyleSet` construction.
- `pkg/derpssh/tui/theme.go`: semantic Catppuccin roles and concrete v2 colors.
- `pkg/derpssh/tui/scene.go`: fixed canvas, compositor, scene result, target lookup, and layer helpers.
- `pkg/derpssh/tui/scene_header.go`: top-bar layers and semantic action/peer IDs.
- `pkg/derpssh/tui/scene_content.go`: base, terminal, sidebar, divider, and composer layers.
- `pkg/derpssh/tui/scene_modal.go`: modal backdrop, panel, content, and button layers.
- `pkg/derpssh/tui/dialog_stack.go`: logical modal order and descriptions only.
- `pkg/derpssh/tui/mouse.go`: v2 pointer messages, capture, target dispatch, and SGR mouse encoding.
- `pkg/derpssh/tui/keys.go`: v2 key matching and PTY encoding.
- `pkg/derpssh/tui/input_router.go`: explicit modal, prefix, chat, paste, and terminal precedence.
- `pkg/derpssh/tui/terminal.go`: tracked embedded-terminal input modes, including bracketed paste.
- `pkg/derpssh/tui/test_events_test.go`: shared v2 key, mouse, color, and view-content test helpers.
- `pkg/derpssh/session/console.go`: Bubble Tea program wiring and removal of out-of-band clipboard output.
- `pkg/derpssh/tui/canvas.go`, `pkg/derpssh/tui/composer.go`: deleted after their v2 replacements are proven.

---

### Task 1: Establish the compiling Charm v2 baseline

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `pkg/derpssh/session/console.go`
- Modify: `pkg/derpssh/session/console_test.go`
- Modify: `pkg/derpssh/session/terminal_lifecycle_test.go`
- Modify: `pkg/derpssh/tui/actions.go`
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/tui/canvas.go`
- Modify: `pkg/derpssh/tui/canvas_test.go`
- Modify: `pkg/derpssh/tui/dialog_stack_test.go`
- Modify: `pkg/derpssh/tui/header_test.go`
- Modify: `pkg/derpssh/tui/input_router_test.go`
- Modify: `pkg/derpssh/tui/keys_test.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/tui/styles_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/styles.go`
- Modify: `pkg/derpssh/tui/theme.go`
- Modify: `pkg/derpssh/tui/input_router.go`
- Modify: `pkg/derpssh/tui/keys.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/model.go`
- Modify: `pkg/derpssh/tui/dialog_stack.go`
- Modify: `pkg/derpssh/tui/composer.go`
- Modify: `pkg/derpssh/tui/chat.go`
- Modify: `pkg/derpssh/tui/header.go`
- Create: `pkg/derpssh/tui/test_events_test.go`
- Test: `pkg/derpssh/tui/app_test.go`
- Test: `pkg/derpssh/tui/styles_test.go`
- Test: `pkg/derpssh/tui/keys_test.go`
- Test: `pkg/derpssh/tui/mouse_test.go`
- Test: `pkg/derpssh/session/console_test.go`

**Interfaces:**
- Produces: `func (*App) View() tea.View`, `type StyleSet`, `func NewStyleSet(ColorScheme) StyleSet`, `func newPointerMsg(layerTarget, tea.MouseMsg) pointerMsg`, and v2-only module imports.
- Preserves: existing renderer output and interaction behavior temporarily through the old `FrameCanvas` path.

- [ ] **Step 1: Add the v2 modules alongside v1, then add tests for the new root contracts**

Make the v2 test imports resolvable without removing the still-compiling v1
graph:

```sh
mise exec -- go get charm.land/bubbletea/v2@v2.0.8 charm.land/bubbles/v2@v2.1.1 charm.land/lipgloss/v2@v2.0.5 github.com/charmbracelet/x/ansi@v0.11.7
```

Add these helpers and assertions before changing production imports:

```go
// pkg/derpssh/tui/test_events_test.go
package tui

import (
	"image/color"

	tea "charm.land/bubbletea/v2"
)

func keyCode(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code}
}

func textKey(text string) tea.KeyPressMsg {
	runes := []rune(text)
	var code rune
	if len(runes) == 1 {
		code = runes[0]
	} else {
		code = tea.KeyExtended
	}
	return tea.KeyPressMsg{Code: code, Text: text}
}

func modifiedKey(code rune, text string, mod tea.KeyMod) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code, Text: text, Mod: mod}
}

func clickAt(x, y int, button tea.MouseButton) tea.MouseClickMsg {
	return tea.MouseClickMsg{X: x, Y: y, Button: button}
}

func releaseAt(x, y int, button tea.MouseButton) tea.MouseReleaseMsg {
	return tea.MouseReleaseMsg{X: x, Y: y, Button: button}
}

func backgroundMsg(c color.Color) tea.BackgroundColorMsg {
	return tea.BackgroundColorMsg{Color: c}
}

func appContent(app *App) string {
	if app == nil {
		return ""
	}
	return app.View().Content
}
```

Add to `app_test.go`:

```go
var _ tea.Model = (*App)(nil)

func TestViewDeclaresTerminalModes(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	view := app.View()
	if !view.AltScreen {
		t.Fatal("View().AltScreen = false, want true")
	}
	if view.MouseMode != tea.MouseModeCellMotion {
		t.Fatalf("View().MouseMode = %v, want cell motion", view.MouseMode)
	}
	if !view.KeyboardEnhancements.ReportAlternateKeys ||
		!view.KeyboardEnhancements.ReportAllKeysAsEscapeCodes ||
		!view.KeyboardEnhancements.ReportAssociatedText ||
		view.KeyboardEnhancements.ReportEventTypes {
		t.Fatalf("unexpected keyboard enhancements: %+v", view.KeyboardEnhancements)
	}
}

func TestBackgroundColorMessageRebuildsConcreteStyles(t *testing.T) {
	app := NewApp(Options{})
	if app.styles.Scheme != SchemeDark {
		t.Fatalf("initial scheme = %q, want dark", app.styles.Scheme)
	}
	app.Update(backgroundMsg(lipgloss.Color("#ffffff")))
	if app.styles.Scheme != SchemeLight {
		t.Fatalf("scheme after white background = %q, want light", app.styles.Scheme)
	}
}
```

- [ ] **Step 2: Run the focused tests and verify the v1 model fails the v2 contract**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'TestViewDeclaresTerminalModes' -count=1
```

Expected: FAIL to compile because `*App` still has `View() string` and does not implement `charm.land/bubbletea/v2.Model`.

- [ ] **Step 3: Switch the module graph and all import paths atomically**

Replace imports exactly:

```text
github.com/charmbracelet/bubbletea  -> charm.land/bubbletea/v2
github.com/charmbracelet/bubbles/  -> charm.land/bubbles/v2/
github.com/charmbracelet/lipgloss  -> charm.land/lipgloss/v2
```

The v2 modules are already present from Step 1. After replacing production
imports, remove the old direct requirements:

```sh
mise exec -- go mod edit -droprequire=github.com/charmbracelet/bubbletea
mise exec -- go mod edit -droprequire=github.com/charmbracelet/bubbles
mise exec -- go mod edit -droprequire=github.com/charmbracelet/lipgloss
```

Do not run `go mod tidy` until all source imports compile.

- [ ] **Step 4: Replace adaptive global styles with a per-app style set**

Implement this shape in `styles.go` and use it from `App` and every render helper:

```go
type StyleSet struct {
	Scheme                         ColorScheme
	TopBar, TopBarBrand            lipgloss.Style
	TopBarQuit, TopBarChip         lipgloss.Style
	TopBarMuted, TopBarWarn        lipgloss.Style
	TopBarAction, TopBarSeparator  lipgloss.Style
	StatusBar                      lipgloss.Style
	Sidebar, SidebarHeader         lipgloss.Style
	Composer, ComposerPlaceholder  lipgloss.Style
	ComposerCursor, ComposerBorder lipgloss.Style
	LocalChat                      lipgloss.Style
	Modal, ModalBorder             lipgloss.Style
	ModalInterior                  lipgloss.Style
	Label, Dim, Separator          lipgloss.Style
	ApprovalButton                 lipgloss.Style
	ApprovalButtonSelected         lipgloss.Style
	MenuLabel, MenuShortcut        lipgloss.Style
}

func NewStyleSet(scheme ColorScheme) StyleSet {
	theme := newTheme(scheme)
	role := func(r ThemeRole) lipgloss.Style { return theme.Role(r) }
	pickColor := func(r ThemeRole, foreground bool) color.Color {
		return theme.RoleColor(r, foreground)
	}
	return StyleSet{
		Scheme:        theme.scheme,
		TopBar:        role(ChromeBase),
		TopBarBrand:   role(ChromeActive).Bold(true),
		TopBarQuit:    role(ChromeDanger).Bold(true),
		TopBarChip:    role(ComposerBase),
		TopBarMuted:   role(ChromeMuted),
		TopBarWarn:    role(ChromeNotice).Bold(true),
		TopBarAction:  role(ButtonFocused).Bold(true),
		TopBarSeparator: lipgloss.NewStyle().
			Foreground(pickColor(DialogBorder, true)).
			Background(pickColor(ChromeBase, false)),
		StatusBar:     role(ChromeBase),
		Sidebar:       role(ChatBase),
		SidebarHeader: role(ChatHeader).Bold(true),
		Composer:      role(ComposerBase),
		ComposerPlaceholder: role(ChatPlaceholder),
		ComposerCursor:      role(ComposerCursor),
		ComposerBorder: lipgloss.NewStyle().
			Foreground(pickColor(DialogBorder, true)).
			Background(pickColor(ChatBase, false)),
		LocalChat: lipgloss.NewStyle().
			Foreground(pickColor(ChatMessageUser, true)),
		Modal: role(DialogBase).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(pickColor(DialogBorder, true)).
			Padding(0, 1),
		ModalBorder:   role(DialogBorder),
		ModalInterior: role(DialogBase),
		Label: role(DialogText).Bold(true).
			Foreground(pickColor(ChromeActive, false)),
		Dim: role(DialogMuted),
		Separator: lipgloss.NewStyle().
			Foreground(pickColor(DialogBorder, true)),
		ApprovalButton:         role(ButtonDefault),
		ApprovalButtonSelected: role(ButtonFocused).Bold(true),
		MenuLabel:              role(DialogText),
		MenuShortcut:           role(DialogMuted),
	}
}
```

Add `Theme.RoleColor(role ThemeRole, foreground bool) color.Color` in
`theme.go`:

```go
func (t Theme) RoleColor(role ThemeRole, foreground bool) color.Color {
	colors := t.roles[role]
	if colors.foreground == "" || colors.background == "" {
		colors = t.roles[ChromeBase]
	}
	value := colors.background
	if foreground {
		value = colors.foreground
	}
	return lipgloss.Color(value)
}
```

Remove `adaptiveRoleStyle`, `adaptiveRoleColor`, and all package-level style
variables. Add `styles StyleSet` and `scheme ColorScheme` to `App`, initialized
with `SchemeDark`.

- [ ] **Step 5: Convert the Bubble Tea model and events to v2**

Use this root-view skeleton while the old renderer still supplies content:

```go
func (a *App) Init() tea.Cmd {
	return tea.RequestBackgroundColor
}

func (a *App) View() tea.View {
	view := tea.NewView(a.renderContent())
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	if a.copyMode || a.inviteOpen {
		view.MouseMode = tea.MouseModeNone
	}
	view.KeyboardEnhancements = tea.KeyboardEnhancements{
		ReportAlternateKeys:        true,
		ReportAllKeysAsEscapeCodes: true,
		ReportAssociatedText:       true,
	}
	return view
}
```

Rename the old `View() string` body to `renderContent() string`. Handle
`tea.BackgroundColorMsg` in `applyMessage`, rebuild `a.styles`, and apply the
matching Bubbles textarea styles.

Apply these v2 mappings throughout production and tests:

```text
tea.KeyMsg struct       -> tea.KeyPressMsg
msg.Type                -> msg.Code
msg.Runes               -> msg.Text
msg.Alt                 -> msg.Mod.Contains(tea.ModAlt)
tea.KeyRunes            -> len(msg.Text) > 0
tea.MouseMsg fields     -> msg.Mouse() plus concrete message type
tea.MouseButtonLeft     -> tea.MouseLeft
tea.MouseButtonRight    -> tea.MouseRight
tea.MouseButtonMiddle   -> tea.MouseMiddle
tea.MouseButtonWheelUp  -> tea.MouseWheelUp
tea.MouseButtonWheelDown-> tea.MouseWheelDown
```

Introduce a temporary v2-native `pointerMsg` with empty target support so the
coordinate handlers compile until Task 5:

```go
type layerTarget string

type pointerMsg struct {
	Target layerTarget
	Event  tea.MouseMsg
	Mouse  tea.Mouse
}

func newPointerMsg(target layerTarget, msg tea.MouseMsg) pointerMsg {
	return pointerMsg{Target: target, Event: msg, Mouse: msg.Mouse()}
}
```

Update `Model.View()` and `tuiConsole.View()` string adapters to return
`app.View().Content`. Remove `WithAltScreen` and `WithMouseCellMotion` from
program construction; `WithInput` and `WithOutput` remain.

- [ ] **Step 6: Update the test suite to v2 event construction**

Use `textKey`, `keyCode`, `modifiedKey`, `clickAt`, `releaseAt`, and
`appContent` instead of v1 struct literals. For motion and wheel cases, use:

```go
tea.MouseMotionMsg{X: x, Y: y, Button: tea.MouseLeft}
tea.MouseWheelMsg{X: x, Y: y, Button: tea.MouseWheelUp}
```

Remove `lipgloss.SetColorProfile`, `lipgloss.SetHasDarkBackground`, and the
`termenv` test import. Assert concrete light and dark `StyleSet` values rather
than `AdaptiveColor` fields.

- [ ] **Step 7: Tidy and verify the complete v2 baseline**

Run:

```sh
mise exec -- go mod tidy
mise exec -- go test ./pkg/derpssh/... -count=1
mise exec -- go test ./cmd/derpssh/... -count=1
rg -n 'github.com/charmbracelet/(bubbletea|bubbles|lipgloss)' --glob '*.go' .
```

Expected: both test commands PASS; the final `rg` prints no Go imports.

- [ ] **Step 8: Commit only the v2 baseline files with GitButler**

Run `but diff`, select only the files listed in this task, and commit their
runtime IDs to `codex/charm-v2-tui-replatform-design` with message:

```text
tui: migrate Charm dependencies to v2
```

---

### Task 2: Add fixed-canvas scene primitives

**Files:**
- Create: `pkg/derpssh/tui/scene.go`
- Create: `pkg/derpssh/tui/scene_test.go`
- Modify: `pkg/derpssh/tui/app.go`

**Interfaces:**
- Produces: `type Scene`, `func composeScene(width, height int, layers ...*lipgloss.Layer) Scene`, `func (Scene) TargetAt(x, y int) layerTarget`, and `func sceneLayer(layerTarget, Rect, int, string) *lipgloss.Layer`.
- Consumes: `layerTarget` and `StyleSet` from Task 1.

- [ ] **Step 1: Write failing scene composition tests**

```go
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
```

- [ ] **Step 2: Run the scene test and verify it fails**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run TestComposeSceneUsesFixedCanvasAndTopmostTarget -count=1
```

Expected: FAIL because `Scene`, `composeScene`, and `sceneLayer` do not exist.

- [ ] **Step 3: Implement the minimal scene API**

```go
type Scene struct {
	Width      int
	Height     int
	Content    string
	Canvas     *lipgloss.Canvas
	Compositor *lipgloss.Compositor
	Cursor     *tea.Cursor
}

func composeScene(width, height int, layers ...*lipgloss.Layer) Scene {
	width = maxInt(width, 1)
	height = maxInt(height, 1)
	canvas := lipgloss.NewCanvas(width, height)
	compositor := lipgloss.NewCompositor(layers...)
	canvas.Compose(compositor)
	return Scene{
		Width: width, Height: height,
		Content: canvas.Render(),
		Canvas: canvas, Compositor: compositor,
	}
}

func (s Scene) TargetAt(x, y int) layerTarget {
	if s.Compositor == nil {
		return ""
	}
	hit := s.Compositor.Hit(x, y)
	if hit.Empty() {
		return ""
	}
	return layerTarget(hit.ID())
}

func sceneLayer(id layerTarget, rect Rect, z int, content string) *lipgloss.Layer {
	return lipgloss.NewLayer(content).
		ID(string(id)).X(rect.X).Y(rect.Y).Z(z)
}
```

Add helpers that clip/pad content to `Rect.W` by `Rect.H` before constructing a
layer. Use `ansi.Truncate` and `ansi.StringWidth`; do not truncate by bytes or
runes.

- [ ] **Step 4: Run scene and wide-glyph tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'TestComposeScene|TestViewFitsWideGlyph' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit the scene primitives with GitButler**

Run `but diff`, select only `scene.go`, `scene_test.go`, and the associated
`app.go` hunk, then commit with message:

```text
tui: add Lip Gloss scene primitives
```

---

### Task 3: Move base, header, terminal, and sidebar onto semantic layers

**Files:**
- Create: `pkg/derpssh/tui/scene_header.go`
- Create: `pkg/derpssh/tui/scene_content.go`
- Create: `pkg/derpssh/tui/scene_header_test.go`
- Create: `pkg/derpssh/tui/scene_content_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/header.go`
- Modify: `pkg/derpssh/tui/header_test.go`

**Interfaces:**
- Consumes: `Scene`, `sceneLayer`, `StyleSet`, `Layout`, `ActionID`, and current terminal/sidebar rendering helpers.
- Produces: `func (*App) buildBaseLayers(Layout) []*lipgloss.Layer`, `func (*App) buildHeaderLayers(Layout) []*lipgloss.Layer`, and stable targets `terminal`, `sidebar`, `composer`, `divider:chat`, `action:*`, and `peer:*`.

- [ ] **Step 1: Write failing semantic-layer tests**

```go
func TestSceneTargetsHeaderTerminalSidebarAndDivider(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	scene := app.buildScene()

	if got := scene.TargetAt(1, 1); got != targetTerminal {
		t.Fatalf("terminal target = %q", got)
	}
	if got := scene.TargetAt(app.layout.Divider.X, app.layout.Divider.Y+1); got != targetDivider {
		t.Fatalf("divider target = %q", got)
	}
	if got := scene.TargetAt(app.layout.Sidebar.X+1, app.layout.Sidebar.Y+1); got != targetSidebar {
		t.Fatalf("sidebar target = %q", got)
	}
	if got := scene.TargetAt(app.width-2, 0); !strings.HasPrefix(string(got), "action:") {
		t.Fatalf("top bar target = %q, want action", got)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run TestSceneTargetsHeaderTerminalSidebarAndDivider -count=1
```

Expected: FAIL because `buildScene` and semantic component targets do not exist.

- [ ] **Step 3: Build base and content layers**

Define stable targets:

```go
const (
	targetBase     layerTarget = "base"
	targetTerminal layerTarget = "terminal"
	targetSidebar  layerTarget = "sidebar"
	targetComposer layerTarget = "composer"
	targetDivider  layerTarget = "divider:chat"
)
```

`buildBaseLayers` must add a full-screen styled base, a clipped terminal layer,
and—when open—separate sidebar, composer, and divider layers. Use `Layout`
rectangles as the only positioning source. The terminal layer content comes
from `a.terminal.View(rect.W, rect.H)`.

- [ ] **Step 4: Build header segment layers with semantic IDs**

Replace `topBarHit` creation with layer IDs:

```go
func actionTarget(id ActionID) layerTarget {
	return layerTarget("action:" + string(id))
}

func peerTarget(id string) layerTarget {
	return layerTarget("peer:" + id)
}
```

Each visible segment becomes its own X-positioned layer on row zero. A separate
full-width top-bar base layer fills the gaps. Preserve existing left/right
packing and width truncation, but return layers rather than rectangles.

- [ ] **Step 5: Make the root view render the scene**

```go
func (a *App) buildScene() Scene {
	a.applyLayout()
	layers := a.buildBaseLayers(a.layout)
	layers = append(layers, a.buildHeaderLayers(a.layout)...)
	return composeScene(a.width, a.height, layers...)
}

func (a *App) View() tea.View {
	scene := a.buildScene()
	view := tea.NewView(scene.Content)
	return a.configureView(view, scene)
}

func (a *App) configureView(view tea.View, scene Scene) tea.View {
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	if a.copyMode || a.inviteOpen {
		view.MouseMode = tea.MouseModeNone
	}
	view.Cursor = scene.Cursor
	view.KeyboardEnhancements = tea.KeyboardEnhancements{
		ReportAlternateKeys:        true,
		ReportAllKeysAsEscapeCodes: true,
		ReportAssociatedText:       true,
	}
	return view
}
```

- [ ] **Step 6: Run component and existing render tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'TestSceneTargets|TestHeader|TestView|TestChatComposerGrows' -count=1
```

Expected: PASS, including narrow-window and wide-glyph coverage.

- [ ] **Step 7: Commit the component layers with GitButler**

Run `but diff`, select only this task's scene/header/app files and tests, then
commit with message:

```text
tui: compose primary surfaces with layers
```

---

### Task 4: Rebuild modals as layered scenes

**Files:**
- Create: `pkg/derpssh/tui/scene_modal.go`
- Create: `pkg/derpssh/tui/scene_modal_test.go`
- Modify: `pkg/derpssh/tui/dialog_stack.go`
- Modify: `pkg/derpssh/tui/dialog_stack_test.go`
- Modify: `pkg/derpssh/tui/app.go`

**Interfaces:**
- Consumes: `ModalID`, existing modal state and line builders, `Scene`, `StyleSet`.
- Produces: `func (*App) buildModalLayers(ModalFrame) []*lipgloss.Layer`, modal targets such as `modal:blocker` and `modal:approval`, and choice/action IDs.

- [ ] **Step 1: Write failing modal Z-order and hit tests**

```go
func TestModalLayersCoverUnderlyingTargetsAndExposeButtons(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	scene := app.buildScene()

	read, write, deny := app.approvalButtonRects()
	for _, tc := range []struct {
		rect Rect
		want layerTarget
	}{
		{read, "approval:read"},
		{write, "approval:write"},
		{deny, "approval:deny"},
	} {
		if got := scene.TargetAt(tc.rect.X, tc.rect.Y); got != tc.want {
			t.Fatalf("TargetAt(%v) = %q, want %q", tc.rect, got, tc.want)
		}
	}
	if got := scene.TargetAt(0, 1); got != targetModalBlocker {
		t.Fatalf("outside modal target = %q, want blocker", got)
	}
}
```

- [ ] **Step 2: Run the modal test and verify it fails**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run TestModalLayersCoverUnderlyingTargetsAndExposeButtons -count=1
```

Expected: FAIL because the scene does not yet include modal layers.

- [ ] **Step 3: Make the modal stack logical only**

Change `ModalDialog` to:

```go
type ModalDialog interface {
	ID() ModalID
	Lines() []string
}
```

Delete `Draw(*FrameCanvas, ModalFrame)` and `ModalStack.Draw`. Keep ordering,
`Front`, `IDs`, line generation, and `modalBounds`.

- [ ] **Step 4: Build backdrop, panel, content, and control layers**

Define:

```go
const targetModalBlocker layerTarget = "modal:blocker"

func modalTarget(id ModalID) layerTarget {
	return layerTarget("modal:" + string(id))
}
```

Add a full-screen blocker beneath the centered panel but above base content.
Build the panel from the current modal lines and `StyleSet.Modal`. Add a distinct
layer for each approval, peer-action, quit, shell-exit, and help action using
the existing button geometry and semantic IDs.

- [ ] **Step 5: Append modal layers last in `buildScene`**

```go
layers = append(layers, a.buildModalLayers(ModalFrame{
	Width: a.width, Height: a.height,
})...)
```

- [ ] **Step 6: Run all modal, narrow-screen, and style tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'TestModal|TestApproval|TestQuit|TestShellExit|TestResizeWarning' -count=1
```

Expected: PASS with no background holes and correct topmost targets.

- [ ] **Step 7: Commit modal layers with GitButler**

Run `but diff`, select only this task's modal/dialog/app files and tests, then
commit with message:

```text
tui: render modal stack as semantic layers
```

---

### Task 5: Route v2 pointer events through rendered targets

**Files:**
- Modify: `pkg/derpssh/tui/scene.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/tui/header.go`
- Test: `pkg/derpssh/tui/scene_header_test.go`
- Test: `pkg/derpssh/tui/scene_modal_test.go`

**Interfaces:**
- Consumes: `Scene.TargetAt`, semantic layer IDs, existing `ActionRegistry`.
- Produces: `func (Scene) PointerCmd(capture layerTarget, tea.MouseMsg) tea.Cmd`, `pointerMsg`, and `App.pointerCapture`.

- [ ] **Step 1: Write failing `OnMouse` target and pointer-capture tests**

```go
func dispatchViewMouse(t *testing.T, app *App, msg tea.MouseMsg) {
	t.Helper()
	cmd := app.View().OnMouse(msg)
	if cmd == nil {
		t.Fatal("View().OnMouse returned nil command")
	}
	app.Update(cmd())
}

func TestViewOnMouseUsesRenderedLayerAndCapturesDividerDrag(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	divider := app.layout.Divider

	dispatchViewMouse(t, app, clickAt(divider.X, divider.Y+1, tea.MouseLeft))
	if app.pointerCapture != targetDivider {
		t.Fatalf("capture = %q, want divider", app.pointerCapture)
	}
	dispatchViewMouse(t, app, tea.MouseMotionMsg{X: divider.X - 8, Y: divider.Y + 2, Button: tea.MouseLeft})
	dispatchViewMouse(t, app, releaseAt(divider.X-8, divider.Y+2, tea.MouseLeft))
	if app.pointerCapture != "" {
		t.Fatalf("capture after release = %q, want empty", app.pointerCapture)
	}
}

func TestEncodeSGRMousePreservesCtrlModifier(t *testing.T) {
	msg := tea.MouseClickMsg{X: 3, Y: 4, Button: tea.MouseLeft, Mod: tea.ModCtrl}
	got, ok := EncodeSGRMouse(msg, Rect{X: 0, Y: 1, W: 20, H: 10})
	if !ok || string(got) != "\x1b[<16;4;4M" {
		t.Fatalf("EncodeSGRMouse() = %q, %v, want ctrl-left sequence", got, ok)
	}
}
```

- [ ] **Step 2: Run the pointer test and verify it fails**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run TestViewOnMouseUsesRenderedLayerAndCapturesDividerDrag -count=1
```

Expected: FAIL because `OnMouse` and `pointerCapture` are not wired.

- [ ] **Step 3: Capture the immutable scene in `tea.View.OnMouse`**

```go
func (s Scene) PointerCmd(capture layerTarget, msg tea.MouseMsg) tea.Cmd {
	target := capture
	if target == "" {
		mouse := msg.Mouse()
		target = s.TargetAt(mouse.X, mouse.Y)
	}
	return func() tea.Msg { return newPointerMsg(target, msg) }
}

func (a *App) configureView(view tea.View, scene Scene) tea.View {
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	if a.copyMode || a.inviteOpen {
		view.MouseMode = tea.MouseModeNone
	}
	view.Cursor = scene.Cursor
	view.KeyboardEnhancements = tea.KeyboardEnhancements{
		ReportAlternateKeys:        true,
		ReportAllKeysAsEscapeCodes: true,
		ReportAssociatedText:       true,
	}
	capture := a.pointerCapture
	view.OnMouse = func(msg tea.MouseMsg) tea.Cmd {
		return scene.PointerCmd(capture, msg)
	}
	return view
}
```

Handle only `pointerMsg` for UI mouse behavior. Raw `tea.MouseMsg` values that
Bubble Tea also delivers to `Update` must not trigger a second action.

- [ ] **Step 4: Dispatch semantic targets and implement capture**

Parse `action:*` through `ActionRegistry`, `peer:*` through the peer dialog,
modal choice targets through the existing selection/confirmation methods, and
content targets through chat/terminal handlers. A divider click sets
`pointerCapture = targetDivider`; release clears it. Opening a modal or leaving
mouse mode also clears it.

- [ ] **Step 5: Convert SGR mouse encoding to concrete v2 message kinds**

```go
func EncodeSGRMouse(msg tea.MouseMsg, terminal Rect) ([]byte, bool) {
	mouse := msg.Mouse()
	if !terminal.contains(mouse.X, mouse.Y) {
		return nil, false
	}
	code, ok := mouseButtonCodes[mouse.Button]
	if !ok {
		return nil, false
	}
	suffix := "M"
	switch msg.(type) {
	case tea.MouseMotionMsg:
		code += 32
	case tea.MouseReleaseMsg:
		code, suffix = 0, "m"
	}
	if mouse.Mod.Contains(tea.ModShift) {
		code += 4
	}
	if mouse.Mod.Contains(tea.ModAlt) {
		code += 8
	}
	if mouse.Mod.Contains(tea.ModCtrl) {
		code += 16
	}
	x := mouse.X - terminal.X + 1
	y := mouse.Y - terminal.Y + 1
	return []byte(fmt.Sprintf("\x1b[<%d;%d;%d%s", code, x, y, suffix)), true
}
```

- [ ] **Step 6: Remove manual hit rectangles and run mouse coverage**

Delete `topBarHits`, `topBarHitAt`, `helpActionAt`, and coordinate-based modal
hit dispatch once semantic targets cover them. Keep geometry helpers only where
scene construction itself uses them.

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'Test.*Mouse|TestSceneTargets|TestModalLayers' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit pointer routing with GitButler**

Run `but diff`, select only this task's scene/app/mouse/header files and tests,
then commit with message:

```text
tui: route pointer input through scene targets
```

---

### Task 6: Render chat with Bubbles textarea and a real cursor

**Files:**
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/scene_content.go`
- Modify: `pkg/derpssh/tui/styles.go`
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/tui/input_router_test.go`
- Create: `pkg/derpssh/tui/scene_composer_test.go`

**Interfaces:**
- Consumes: Bubbles v2 `textarea.Model`, `StyleSet`, and composer `Layout`.
- Produces: `func (*App) configureComposerStyles()`, `func (*App) composerLayer(Layout) *lipgloss.Layer`, and a root `tea.View.Cursor` with absolute coordinates.

- [ ] **Step 1: Write failing real-cursor tests**

```go
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
}
```

- [ ] **Step 2: Run the cursor test and verify it fails**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run TestComposerUsesTextareaViewAndRealCursor -count=1
```

Expected: FAIL because the composer still draws a virtual cursor into content.

- [ ] **Step 3: Configure Bubbles v2 textarea as the sole composer**

In `NewApp`:

```go
composer := textarea.New()
composer.Prompt = ""
composer.Placeholder = "Message"
composer.ShowLineNumbers = false
composer.CharLimit = 4096
composer.DynamicHeight = true
composer.MinHeight = 1
composer.MaxHeight = 3
composer.MaxContentHeight = 4096
composer.SetVirtualCursor(false)
```

Build focused and blurred `textarea.Styles` from `StyleSet`, including base,
text, placeholder, prompt, and cursor color. Reapply them after a background
scheme change:

```go
func (a *App) configureComposerStyles() {
	state := textarea.StyleState{
		Base:        a.styles.Composer,
		Text:        a.styles.Composer,
		Placeholder: a.styles.ComposerPlaceholder,
		Prompt:      a.styles.Composer,
	}
	a.composer.SetStyles(textarea.Styles{
		Focused: state,
		Blurred: state,
		Cursor: textarea.CursorStyle{
			Color: a.styles.ComposerCursor.GetForeground(),
			Shape: tea.CursorBlock,
			Blink: true,
		},
	})
}
```

- [ ] **Step 4: Render `textarea.View()` in the composer layer**

Set width from `Layout.Composer.W`; let `DynamicHeight` produce one-to-three
rows and feed `composer.Height()` back into layout before final scene creation.
Remove `composerVisibleLines`, `renderComposerLine`, and
`renderComposerPlaceholderLine` from the app path. Build the layer with:

```go
func (a *App) composerLayer(layout Layout) *lipgloss.Layer {
	rect := layout.Composer
	a.composer.SetWidth(maxInt(rect.W, 1))
	content := fitBlock(a.composer.View(), rect.W, rect.H)
	return sceneLayer(targetComposer, rect, zChrome, content)
}
```

- [ ] **Step 5: Offset the real cursor into the root view**

```go
func (a *App) composerCursor() *tea.Cursor {
	if a.focus != FocusChat {
		return nil
	}
	cursor := a.composer.Cursor()
	if cursor == nil {
		return nil
	}
	cursor.Position.X += a.layout.Composer.X
	cursor.Position.Y += a.layout.Composer.Y
	return cursor
}
```

Assign the result to `Scene.Cursor` and then `tea.View.Cursor`. Terminal focus
keeps the real cursor nil and preserves the emulated terminal cursor layer:

```go
scene := composeScene(a.width, a.height, layers...)
scene.Cursor = a.composerCursor()
return scene
```

- [ ] **Step 6: Run composer behavior and cursor tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'Test.*Composer|TestTerminalCursorSuppressed|TestInputRouterChat' -count=1
```

Expected: PASS for placeholder, wrapping, growth, insertion, deletion,
navigation, focus, and cursor coordinates.

- [ ] **Step 7: Commit the composer migration with GitButler**

Run `but diff`, select only this task's app/content/style and composer tests,
then commit with message:

```text
tui: render chat with Bubbles real cursor
```

---

### Task 7: Upgrade PTY key encoding and paste routing

**Files:**
- Modify: `pkg/derpssh/tui/keys.go`
- Modify: `pkg/derpssh/tui/keys_test.go`
- Modify: `pkg/derpssh/tui/input_router.go`
- Modify: `pkg/derpssh/tui/input_router_test.go`
- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_test.go`
- Create: `pkg/derpssh/tui/paste_test.go`

**Interfaces:**
- Produces: `func EncodeTerminalKeyWithMode(tea.KeyPressMsg, TerminalInputMode) ([]byte, bool)`, `func EncodeTerminalPaste(tea.PasteMsg, TerminalInputMode) []byte`, and `TerminalInputMode.BracketedPaste`.
- Consumes: v2 key enhancements declared in Task 1 and existing terminal input commands.

- [ ] **Step 1: Add failing modifier, international, and paste tests**

```go
func TestEncodeTerminalKeyV2Modifiers(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want string
	}{
		{"unicode", textKey("界"), "界"},
		{"alt text", modifiedKey('x', "x", tea.ModAlt), "\x1bx"},
		{"ctrl c", modifiedKey('c', "", tea.ModCtrl), "\x03"},
		{"ctrl shift right", modifiedKey(tea.KeyRight, "", tea.ModCtrl|tea.ModShift), "\x1b[1;6C"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EncodeTerminalKeyWithMode(tt.msg, TerminalInputMode{})
			if !ok || string(got) != tt.want {
				t.Fatalf("EncodeTerminalKeyWithMode() = %q, %v, want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestEncodeTerminalPasteTracksEmbeddedMode(t *testing.T) {
	msg := tea.PasteMsg{Content: "one\ntwo"}
	if got := string(EncodeTerminalPaste(msg, TerminalInputMode{})); got != "one\ntwo" {
		t.Fatalf("plain paste = %q", got)
	}
	mode := TerminalInputMode{BracketedPaste: true}
	if got := string(EncodeTerminalPaste(msg, mode)); got != "\x1b[200~one\ntwo\x1b[201~" {
		t.Fatalf("bracketed paste = %q", got)
	}
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'TestEncodeTerminalKeyV2Modifiers|TestEncodeTerminalPasteTracksEmbeddedMode' -count=1
```

Expected: FAIL for missing modifier sequences and bracketed-paste state.

- [ ] **Step 3: Implement the v2 PTY key encoder**

Use `msg.Text` for printable associated text. Prefix Alt text with ESC. Map
Ctrl+ASCII to control bytes. Map unmodified special keys to the existing
sequences; when Shift, Alt, Ctrl, or Meta modifies navigation/function keys,
emit standard xterm `1;N` modifier forms. Preserve application-cursor arrow
sequences only when no modifier is present.

Implement modifier numbering explicitly:

```go
func xtermModifier(mod tea.KeyMod) (int, bool) {
	value := 1
	if mod.Contains(tea.ModShift) { value += 1 }
	if mod.Contains(tea.ModAlt) { value += 2 }
	if mod.Contains(tea.ModCtrl) { value += 4 }
	if mod.Contains(tea.ModMeta) { value += 8 }
	if mod.Contains(tea.ModHyper) || mod.Contains(tea.ModSuper) {
		return 0, false
	}
	return value, value != 1
}
```

- [ ] **Step 4: Track embedded bracketed-paste mode**

Extend `TrackInputMode` so private mode `?2004h` sets
`BracketedPaste = true` and `?2004l` clears it. Preserve handling of mode `?1`
for application cursor.

```go
func EncodeTerminalPaste(msg tea.PasteMsg, mode TerminalInputMode) []byte {
	data := []byte(msg.Content)
	if !mode.BracketedPaste {
		return data
	}
	wrapped := make([]byte, 0, len(data)+12)
	wrapped = append(wrapped, "\x1b[200~"...)
	wrapped = append(wrapped, data...)
	return append(wrapped, "\x1b[201~"...)
}
```

- [ ] **Step 5: Route paste with explicit input precedence**

Handle `tea.PasteMsg` separately in `App.Update`/`InputRouter`:

```go
func (r InputRouter) RoutePaste(msg tea.PasteMsg) tea.Cmd {
	a := r.app
	if a == nil || a.modalActive() || a.prefix {
		return nil
	}
	if a.focus == FocusChat {
		var cmd tea.Cmd
		a.composer, cmd = a.composer.Update(msg)
		return cmd
	}
	a.emit(TerminalInputCommand{Data: EncodeTerminalPaste(msg, a.terminal.InputMode())})
	return nil
}
```

- [ ] **Step 6: Run key, paste, textarea, and terminal mode tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -run 'TestEncodeTerminalKey|TestEncodeTerminalPaste|TestInputRouter|TestTrackInputMode' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit input encoding with GitButler**

Run `but diff`, select only this task's key/input/terminal files and tests, then
commit with message:

```text
tui: support enhanced keys and paste events
```

---

### Task 8: Move clipboard and terminal lifecycle fully onto v2 contracts

**Files:**
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/messages.go`
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/session/console.go`
- Modify: `pkg/derpssh/session/console_test.go`
- Modify: `pkg/derpssh/session/terminal_lifecycle.go`
- Modify: `pkg/derpssh/session/terminal_lifecycle_test.go`

**Interfaces:**
- Produces: native `tea.SetClipboard` commands and declarative view transitions with no imperative mouse/alternate-screen commands.
- Removes: `CopyInviteCommand`, `osc52`, and its base64 import.

- [ ] **Step 1: Write failing clipboard and view-transition tests**

```go
func TestInviteCopyUsesBubbleTeaClipboardCommand(t *testing.T) {
	app := NewApp(Options{
		Side: "host", InviteCommand: "derpssh connect invite",
		Terminal: &fakePane{view: "shell$"},
	})
	app.inviteOpen = true
	cmd := app.handleInviteKey(textKey("c"))
	if cmd == nil || cmd() == nil {
		t.Fatal("copy command = nil, want Bubble Tea clipboard message")
	}
}

func TestViewDeclarativelyDisablesMouseForSelectionAndInvite(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "invite"})
	app.copyMode = true
	if got := app.View().MouseMode; got != tea.MouseModeNone {
		t.Fatalf("selection mouse mode = %v", got)
	}
	app.copyMode = false
	app.inviteOpen = true
	if got := app.View().MouseMode; got != tea.MouseModeNone {
		t.Fatalf("invite mouse mode = %v", got)
	}
}
```

- [ ] **Step 2: Run the focused tests and verify the old custom path fails**

Run:

```sh
mise exec -- go test ./pkg/derpssh/... -run 'TestInviteCopyUsesBubbleTeaClipboardCommand|TestViewDeclarativelyDisablesMouseForSelectionAndInvite' -count=1
```

Expected: FAIL because copy still emits an app command or mouse changes still
return imperative commands.

- [ ] **Step 3: Return native clipboard commands from invite actions**

```go
case msg.Text == "c":
	return tea.SetClipboard(strings.TrimSpace(a.inviteCommand))
```

Remove `CopyInviteCommand` from `messages.go`, its session dispatch case,
`handleCopyInviteCommand`, `osc52`, and `encoding/base64`.

- [ ] **Step 4: Remove all imperative terminal-mode commands**

`openInvite` and `setCopyMode` mutate state and return nil. Remove returns of
`tea.EnableMouseCellMotion` and `tea.DisableMouse`. Remove stale approval
`tea.ClearScreen` calls unless the PTY integration test demonstrates that the
new renderer needs one.

- [ ] **Step 5: Strengthen terminal lifecycle tests around v2 cleanup**

Keep the explicit restore sequence and idempotence assertions. Add a fake
program/view transition test proving normal quit calls `Program.Quit` once,
waits once, and leaves the defensive restore responsible only for final cleanup.

- [ ] **Step 6: Run lifecycle and console tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/session ./pkg/derpssh/tui -run 'Test.*(Clipboard|Invite|MouseMode|TerminalLifecycle|Restore|Quit)' -count=1
```

Expected: PASS with no direct clipboard writes.

- [ ] **Step 7: Commit lifecycle integration with GitButler**

Run `but diff`, select only this task's TUI/session files and tests, then commit
with message:

```text
tui: delegate terminal I/O lifecycle to Bubble Tea
```

---

### Task 9: Delete superseded custom rendering and dead composer code

**Files:**
- Delete: `pkg/derpssh/tui/canvas.go`
- Delete: `pkg/derpssh/tui/canvas_test.go`
- Delete: `pkg/derpssh/tui/composer.go`
- Delete: `pkg/derpssh/tui/composer_test.go`
- Modify: `pkg/derpssh/tui/chat.go`
- Modify: `pkg/derpssh/tui/chat_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/header.go`
- Modify: `pkg/derpssh/tui/dialog_stack.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: affected TUI tests

**Interfaces:**
- Consumes: all scene, pointer, and Bubbles composer replacements.
- Produces: no references to `FrameCanvas`, `Point`, custom `Cell`, `topBarHit`, custom `Composer`, or coordinate-only UI hit dispatch.

- [ ] **Step 1: Add an architecture guard test**

Create `pkg/derpssh/tui/architecture_test.go`:

```go
func TestCharmV2ArchitectureHasNoLegacyFiles(t *testing.T) {
	for _, path := range []string{"canvas.go", "composer.go"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy file %s still exists or returned unexpected error: %v", path, err)
		}
	}
}
```

- [ ] **Step 2: Run the guard and verify it fails**

Run from `pkg/derpssh/tui`:

```sh
mise exec -- go test . -run TestCharmV2ArchitectureHasNoLegacyFiles -count=1
```

Expected: FAIL because both legacy files still exist.

- [ ] **Step 3: Remove custom canvas and composer implementations**

Delete `canvas.go`, `canvas_test.go`, `composer.go`, and `composer_test.go`.
Remove the unused `Composer` field from legacy `ChatPane`; keep its message and
identity behavior if still used. Delete `Header` only if all header behavior is
now in `scene_header.go`; otherwise reduce it to a pure segment-description
helper with no mutable hit state.

- [ ] **Step 4: Remove obsolete helpers from `app.go` and `mouse.go`**

Delete frame overlay methods, manual composer renderers, manual top-bar hit
storage, modal button hit functions that are no longer used by scene building,
and coordinate-only dispatch. Keep reusable width, wrapping, identity, button
label, and layout helpers.

- [ ] **Step 5: Verify the architecture and all TUI tests**

Run:

```sh
mise exec -- go test ./pkg/derpssh/tui -count=1
rg -n 'FrameCanvas|NewFrameCanvas|topBarHits|CopyInviteCommand|func osc52|AdaptiveColor|lipgloss/compat|EnableMouseCellMotion|DisableMouse' pkg/derpssh
```

Expected: tests PASS and `rg` prints no production references.

- [ ] **Step 6: Commit legacy cleanup with GitButler**

Run `but diff`, select only this task's deletions and cleanup files, then commit
with message:

```text
tui: remove superseded Charm v1 rendering paths
```

---

### Task 10: Verify the full replatform and dependency graph

**Files:**
- No planned source changes
- Do not modify: `dist/**`

**Interfaces:**
- Consumes: the complete replatform.
- Produces: verified module, unit, race, build, smoke, and packaging evidence.

- [ ] **Step 1: Verify exact dependency versions and absence of v1 modules**

Run:

```sh
mise exec -- go list -m all | rg '(^charm.land/(bubbletea|bubbles|lipgloss)/v2|github.com/charmbracelet/x/ansi|github.com/charmbracelet/(bubbletea|bubbles|lipgloss) )'
```

Expected output includes exactly:

```text
charm.land/bubbletea/v2 v2.0.8
charm.land/bubbles/v2 v2.1.1
charm.land/lipgloss/v2 v2.0.5
github.com/charmbracelet/x/ansi v0.11.7
```

Expected: no unversioned-v2 `github.com/charmbracelet/bubbletea`, `bubbles`, or
`lipgloss` module lines.

- [ ] **Step 2: Run focused Derpssh tests uncached**

Run:

```sh
mise exec -- go test ./pkg/derpssh/... ./cmd/derpssh/... -count=1
```

Expected: PASS.

- [ ] **Step 3: Run the repository check and race suite**

Run:

```sh
mise run check
mise run race
```

Expected: both PASS.

- [ ] **Step 4: Build and run the local Derpssh smoke test**

Run:

```sh
mise run build
mise run smoke-derpssh-local
```

Expected: build PASS and local host/guest smoke PASS with terminal echo,
promotion, chat/status output, and clean teardown.

- [ ] **Step 5: Validate npm packaging without publishing**

Run:

```sh
VERSION=v0.0.0-charm-v2 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:npm-dry-run
```

Expected: all npm dry-run checks PASS. This read-only `git rev-parse` is allowed;
do not tag or publish.

- [ ] **Step 6: Run remote smoke when a configured host is available**

Run:

```sh
if [[ -n "${REMOTE_HOST:-}" ]]; then
  mise run smoke-remote-derpssh
else
  echo 'REMOTE_HOST is not configured; remote Derpssh smoke not run'
fi
```

Expected: PASS. If no configured host is available, record that this optional
gate was not run; do not invent or commit a hostname.

- [ ] **Step 7: Inspect the final scoped diff and commit verification fixes**

Run `but diff`. If verification required code fixes, select only those runtime
IDs and commit with message:

```text
tui: finish Charm v2 verification
```

If `but diff` shows no changes from this session, do not create an empty commit.

---

## Final review checklist

- Every implementation task in Tasks 1–9 used a failing test before implementation.
- No task committed another session's `pkg/session` work.
- All old Charm Go imports are absent.
- Lip Gloss canvas/compositor/layers own all visible composition.
- `tea.View` owns alternate screen, mouse mode, cursor, keyboard enhancements,
  and `OnMouse`.
- Bubbles textarea is the sole composer renderer and cursor source.
- Key, paste, and mouse input preserve PTY semantics.
- Clipboard output is native Bubble Tea OSC52.
- The defensive terminal restore path remains idempotent.
- No generated `dist/` files are committed.
- No release is created.
