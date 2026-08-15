# derpssh OpenCode-Inspired UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modernize the derpssh top bar and chat with OpenCode's visual language, semantic hover and pressed states, and click-to-copy chat messages.

**Architecture:** Keep Bubble Tea v2 and Lip Gloss v2's declarative scene compositor. Expand the theme into OpenCode-style surface and accent roles, keep hit testing on semantic Lip Gloss layers, and introduce a focused chat-row layout that maps every visible message back to its source index. Mouse motion, press/release, divider capture, terminal gestures, and copied-feedback timers remain explicit `App` state with modal and terminal routing taking priority.

**Tech Stack:** Go 1.25.1, Bubble Tea v2, Bubbles v2 textarea, Lip Gloss v2 compositor/layers, `github.com/charmbracelet/x/ansi`, GitButler CLI.

## Global Constraints

- Dark palette: background `#0A0A0A`, panel `#141414`, element `#1E1E1E`, subtle border `#3C3C3C`, border `#484848`, active border `#606060`, text `#EEEEEE`, muted text `#808080`, primary `#FAB283`, secondary `#5C9CF5`, success `#7FD88F`, warning `#F5A742`, danger `#E06C75`.
- Light theme follows OpenCode's corresponding surface and semantic colors, using contrast-safe muted text `#686868`; every text-bearing role must retain at least 4.5:1 contrast.
- Glyphs are standard-font Unicode only: `◆`, `●`, `◈`, `⋮`, `×`, `┃`, `✓`, with `▲` and `▼` reserved for visible scroll affordances.
- Chat click copies only `ChatMessage.Body`; it never copies the author, changes focus, opens a menu, or changes scroll position.
- No protocol, timestamp, reply, reaction, context-menu, rich-text, syntax-highlight, Ghostty-private escape, Nerd Font, generated `dist/`, publish, or release changes.
- Preserve terminal selection, SGR mouse forwarding, divider capture, modal priority, keyboard shortcuts, dynamic composer height, and automatic narrow-width chat collapse.
- Use `charm.land/lipgloss/v2 v2.0.6` and `github.com/charmbracelet/x/ansi v0.11.8`; keep current `charm.land/bubbletea/v2 v2.0.8` and `charm.land/bubbles/v2 v2.1.1`.
- Use GitButler for commits. Before each checkpoint, run `but diff`; commit without `--changes` only when it lists exclusively the task's files. Otherwise use the printed file/hunk IDs to commit only this branch's work.

---

## File map

- `go.mod`, `go.sum`: pin the current stable Lip Gloss and ANSI releases.
- `pkg/derpssh/tui/theme.go`: define OpenCode-derived primitive and component color roles for light and dark modes.
- `pkg/derpssh/tui/styles.go`: construct normal, hover, pressed, active, danger, divider, message, composer, and copied-feedback styles.
- `pkg/derpssh/tui/theme_test.go`, `pkg/derpssh/tui/styles_test.go`: lock palette values, role completeness, concrete surfaces, and contrast.
- `pkg/derpssh/tui/app.go`: store hover/press/copy state, create top-bar segment content, and consume copied-feedback ticks.
- `pkg/derpssh/tui/scene_header.go`: render glyph-based top-bar groups and resolve interaction-state styles before packing.
- `pkg/derpssh/tui/scene_header_test.go`, `pkg/derpssh/tui/header_test.go`, `pkg/derpssh/tui/app_test.go`: verify top-bar content, packing, targets, and rendered states.
- `pkg/derpssh/tui/chat_view.go`: own chat row construction, viewport clipping, message block rectangles, and message target parsing.
- `pkg/derpssh/tui/chat_view_test.go`: verify grouping, wrapping, clipping, source indexes, and stable target mapping.
- `pkg/derpssh/tui/scene_content.go`: compose panel, header, messages, close control, composer, and heavy divider as semantic layers.
- `pkg/derpssh/tui/scene_content_test.go`, `pkg/derpssh/tui/scene_composer_test.go`: verify chat scene ownership and composer placement.
- `pkg/derpssh/tui/mouse.go`: update hover, arm/release chrome targets, copy messages, improve chat wheel movement, and preserve capture precedence.
- `pkg/derpssh/tui/mouse_test.go`: verify motion, press/release cancellation, copied clipboard data, feedback timing, scroll clamping, and regressions.

---

### Task 1: OpenCode palette, styles, and dependency pins

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `pkg/derpssh/tui/theme.go`
- Modify: `pkg/derpssh/tui/styles.go`
- Modify: `pkg/derpssh/tui/theme_test.go`
- Modify: `pkg/derpssh/tui/styles_test.go`

**Interfaces:**
- Produces: `Theme.Role(ThemeRole) lipgloss.Style` and `Theme.RoleColor(ThemeRole, bool) color.Color` for the expanded role set.
- Produces: `StyleSet` fields `TopBarHover`, `TopBarPressed`, `TopBarActive`, `TopBarDangerHover`, `SidebarHeaderAction`, `SidebarHeaderActionHover`, `MessageRemote`, `MessageLocal`, `MessageHover`, `MessagePressed`, `MessageAuthorRemote`, `MessageAuthorLocal`, `MessageAccentRemote`, `MessageAccentLocal`, `MessageCopied`, `Divider`, `DividerHover`, and `DividerDragging`.
- Consumes: existing `ColorScheme`, `Theme`, and Lip Gloss v2 styles.

- [ ] **Step 1: Replace Catppuccin-specific style assertions with failing OpenCode palette assertions**

Add exact dark palette coverage to `styles_test.go`:

```go
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
		{name: "hover", style: styles.TopBarHover, foreground: "#EEEEEE", background: "#1E1E1E"},
		{name: "active", style: styles.TopBarActive, foreground: "#FAB283", background: "#1E1E1E"},
		{name: "sidebar", style: styles.Sidebar, foreground: "#EEEEEE", background: "#141414"},
		{name: "local message", style: styles.MessageLocal, foreground: "#EEEEEE", background: "#1E1E1E"},
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
```

Update `TestSeparatorStyleUsesConcreteForegroundOnly` to expect `#484848`, and replace `TestLightThemeChromeUsesRestrainedCatppuccinSurfaces` with `TestLightThemeUsesOpenCodeSurfaces` covering `#FAFAFA` panel, `#F5F5F5` element, and the chosen contrast-safe muted foreground.

- [ ] **Step 2: Extend role completeness and contrast tests**

Add the new roles to `allThemeRoles()` and make `theme_test.go` fail until every new role exists. Keep the current 4.5 threshold and add every text-bearing message and hover role:

```go
for _, role := range []ThemeRole{
	ChromeActive, ChromeMuted, ChromeNotice,
	ChatBase, ChatHeader, ChatMessageUser, ChatMessageSelf,
	ChatPlaceholder, ComposerBase, MessageHover, MessagePressed,
} {
	if got := theme.ContrastRatio(role); got < 4.5 {
		t.Fatalf("%s %s contrast = %.2f, want >= 4.5", scheme, role, got)
	}
}
```

- [ ] **Step 3: Run the focused tests and confirm the intended failure**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(DarkThemeUsesOpenCodeSurfaces|LightThemeUsesOpenCodeSurfaces|ThemeRolesHaveReadableContrast|ThemeDefinesEveryRole)'
```

Expected: FAIL because the new style fields/roles do not exist and current colors are Catppuccin values.

- [ ] **Step 4: Upgrade only the stale UI modules**

Run:

```bash
go get charm.land/lipgloss/v2@v2.0.6 github.com/charmbracelet/x/ansi@v0.11.8
go mod tidy
```

Confirm with:

```bash
go list -m charm.land/bubbles/v2 charm.land/bubbletea/v2 charm.land/lipgloss/v2 github.com/charmbracelet/x/ansi
```

Expected versions: Bubbles `v2.1.1`, Bubble Tea `v2.0.8`, Lip Gloss `v2.0.6`, ANSI `v0.11.8`.

- [ ] **Step 5: Add OpenCode primitive/component roles and map both schemes**

In `theme.go`, add these role constants and include them in `allThemeRoles()`:

```go
const (
	SurfaceBackground ThemeRole = "SurfaceBackground"
	SurfacePanel      ThemeRole = "SurfacePanel"
	SurfaceElement    ThemeRole = "SurfaceElement"
	BorderSubtle      ThemeRole = "BorderSubtle"
	BorderBase        ThemeRole = "BorderBase"
	BorderActive      ThemeRole = "BorderActive"
	AccentPrimary     ThemeRole = "AccentPrimary"
	AccentSecondary   ThemeRole = "AccentSecondary"
	StateSuccess      ThemeRole = "StateSuccess"
	MessageHover      ThemeRole = "MessageHover"
	MessagePressed    ThemeRole = "MessagePressed"
	CopiedFeedback    ThemeRole = "CopiedFeedback"
)
```

Use the exact dark values from Global Constraints. For light roles use background `#FFFFFF`, panel `#FAFAFA`, element `#F5F5F5`, subtle border `#D4D4D4`, border `#B8B8B8`, active border `#A0A0A0`, text `#1A1A1A`, contrast-safe muted text `#686868`, primary `#3B7DD8`, secondary `#7B5BB6`, accent/warning `#D68C27`, success `#3D9A57`, and danger `#D1383D`.

- [ ] **Step 6: Build the expanded style set from roles**

Expand `StyleSet` with the fields listed in Interfaces. Construct states from role colors, keeping backgrounds concrete for structural surfaces:

```go
TopBar:            role(ChromeBase),
TopBarBrand:       role(ChromeBase).Foreground(pickColor(AccentPrimary, true)).Bold(true),
TopBarHover:       role(MessageHover),
TopBarPressed:     role(MessagePressed).Bold(true),
TopBarActive:      role(MessageHover).Foreground(pickColor(AccentPrimary, true)).Bold(true),
TopBarDangerHover: role(MessageHover).Foreground(pickColor(ChromeDanger, true)).Bold(true),
Sidebar:           role(ChatBase),
MessageRemote:     role(ChatMessageUser),
MessageLocal:      role(ChatMessageSelf),
MessageHover:      role(MessageHover),
MessagePressed:    role(MessagePressed),
MessageAccentRemote: lipgloss.NewStyle().Foreground(pickColor(AccentSecondary, true)),
MessageAccentLocal: lipgloss.NewStyle().Foreground(pickColor(AccentPrimary, true)),
MessageCopied:     role(CopiedFeedback).Bold(true),
Divider: lipgloss.NewStyle().Foreground(pickColor(BorderBase, true)),
DividerHover: lipgloss.NewStyle().Foreground(pickColor(BorderActive, true)),
DividerDragging: lipgloss.NewStyle().Foreground(pickColor(AccentPrimary, true)),
```

Preserve existing modal/button APIs by remapping them to the new palette rather than renaming them.

- [ ] **Step 7: Run focused tests and the fast build gate**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(DarkThemeUsesOpenCodeSurfaces|LightThemeUsesOpenCodeSurfaces|ThemeRolesHaveReadableContrast|ThemeDefinesEveryRole|StructuralStylesUseConcreteSchemeBackgrounds|SeparatorStyle)'
mise run check:fast
```

Expected: PASS.

- [ ] **Step 8: Create the palette/dependency checkpoint**

Run `but diff`. If only the six task files plus `go.mod` and `go.sum` are present, run:

```bash
but commit codex/derpssh-opencode-ui -m "tui: adopt OpenCode visual palette"
```

Expected: one new local checkpoint on `codex/derpssh-opencode-ui`; nothing is pushed.

---

### Task 2: Glyph-based top bar with hover and safe activation

**Files:**
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/scene_header.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/tui/header_test.go`
- Modify: `pkg/derpssh/tui/scene_header_test.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`

**Interfaces:**
- Consumes: Task 1 `StyleSet` interaction fields.
- Produces: `App.hoverTarget layerTarget` and `App.pressedTarget layerTarget`.
- Produces: `func (a *App) headerSegmentStyle(topBarSegment, layerTarget) lipgloss.Style`.
- Produces: `func isChromeTarget(layerTarget) bool` and press/release handling shared by header actions and peers.

- [ ] **Step 1: Write failing glyph and packing tests**

Update `TestViewRendersSingleQuietTopBar` and `TestTopBarHidesInviteBehindMenu` in `app_test.go`:

```go
for _, want := range []string{"◆ derpssh", "host", "◈ Chat", "⋮", "×"} {
	if !strings.Contains(firstLine, want) {
		t.Fatalf("top bar missing %q:\n%s", want, firstLine)
	}
}
if strings.Contains(firstLine, "›") || strings.Contains(firstLine, "☰") {
	t.Fatalf("top bar retained legacy separators or menu glyph:\n%s", firstLine)
}
```

Extend `scene_header_test.go` to assert the right-side Chat, menu, and quit targets all remain present and that `displayWidth(firstLine)` equals the terminal width at 56, 80, and 120 columns.

- [ ] **Step 2: Write failing hover and press/release tests**

Add to `mouse_test.go`:

```go
func TestMouseHoverTracksSemanticTopBarTarget(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	chat := topBarActionRect(t, app, ActionToggleChat)

	app.Update(tea.MouseMotionMsg{X: chat.X, Y: chat.Y})
	if app.hoverTarget != actionTarget(ActionToggleChat) {
		t.Fatalf("hover = %q, want chat target", app.hoverTarget)
	}
	app.Update(tea.MouseMotionMsg{X: app.layout.Terminal.X, Y: app.layout.Terminal.Y})
	if app.hoverTarget != "" {
		t.Fatalf("hover = %q after leaving chrome, want empty", app.hoverTarget)
	}
}

func TestMouseTopBarActionRequiresMatchingRelease(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	chat := topBarActionRect(t, app, ActionToggleChat)
	menu := topBarActionRect(t, app, ActionShowMenu)

	app.Update(leftClick(chat.X, chat.Y))
	if app.sidebarOpen {
		t.Fatal("chat opened on press")
	}
	app.Update(leftRelease(menu.X, menu.Y))
	if app.sidebarOpen {
		t.Fatal("chat opened after release on a different target")
	}
}
```

Update existing top-bar and peer click tests to dispatch both `leftClick` and `leftRelease`.

- [ ] **Step 3: Run the focused tests and confirm failure**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(ViewRendersSingleQuietTopBar|TopBarHidesInviteBehindMenu|Header|MouseHoverTracksSemanticTopBarTarget|MouseTopBarActionRequiresMatchingRelease|MouseClickTopBar|MouseClickPeerTopBar)'
```

Expected: FAIL because glyphs, hover state, and release activation are absent.

- [ ] **Step 4: Add app-level hover and pressed state**

Add to `App`:

```go
hoverTarget   layerTarget
pressedTarget layerTarget
```

Add helpers in `mouse.go`:

```go
func isChromeTarget(target layerTarget) bool {
	value := string(target)
	return strings.HasPrefix(value, "action:") || strings.HasPrefix(value, "peer:")
}

func (a *App) updateHover(pointer pointerMsg) {
	if pointer.action() != pointerMotion || a.pointerCapture != "" || a.modalActive() {
		return
	}
	if isChromeTarget(pointer.Target) || pointer.Target == targetDivider ||
		pointer.Target == targetComposer || strings.HasPrefix(string(pointer.Target), "chat-message:") {
		a.hoverTarget = pointer.Target
		return
	}
	a.hoverTarget = ""
}
```

Call `updateHover` before target dispatch. Clear `pressedTarget` on unmatched release, modal activation, invite mode, resize, and explicit pointer-state cleanup. Do not clear terminal gesture capture or forwarded SGR release state as a side effect of ordinary hover.

- [ ] **Step 5: Make header actions and peers activate on matching release**

Replace immediate-click behavior with:

```go
func (a *App) handleChromePress(pointer pointerMsg) bool {
	switch pointer.action() {
	case pointerClick:
		if pointer.Mouse.Button != tea.MouseLeft {
			return false
		}
		a.pressedTarget = pointer.Target
		return true
	case pointerRelease:
		matched := a.pressedTarget != "" && a.pressedTarget == pointer.Target
		a.pressedTarget = ""
		return matched
	default:
		return false
	}
}
```

On a matching release, action targets call `NewActionRegistry().Run`, and peer targets call `openPeerDialog`. A mismatched or non-left release does nothing.

- [ ] **Step 6: Paint the new top-bar content and states**

Change segment creation in `app.go` so the left side starts with:

```go
segments := []topBarSegment{{text: "◆ derpssh", style: a.styles.TopBarBrand}}
```

Keep `chatTopBarSegments()` as the owner of unread counts and pulse styling, but prefix each of its labels with `◈ `. Build the right side by appending menu and quit after those segments:

```go
segments := a.chatTopBarSegments()
segments = append(segments,
	topBarSegment{text: "⋮", style: a.styles.TopBarMuted, action: ActionShowMenu},
	topBarSegment{text: "×", style: a.styles.TopBarQuit, action: ActionQuit},
)
```

Prefix compact transport text and each peer-presence label with `● `. Remove the `›` layer from `packHeaderSegments`; spacing comes from each segment's existing one-cell padding.

Before rendering a segment in `packHeaderSegments`, compute its semantic target and call:

```go
func (a *App) headerSegmentStyle(segment topBarSegment, target layerTarget) lipgloss.Style {
	if a.pressedTarget == target {
		return a.styles.TopBarPressed
	}
	if a.hoverTarget == target {
		if segment.action == ActionQuit {
			return a.styles.TopBarDangerHover
		}
		return a.styles.TopBarHover
	}
	if segment.action == ActionToggleChat && a.sidebarOpen {
		return a.styles.TopBarActive
	}
	return segment.style
}
```

Preserve unread warning/pulse styling and prefix hints ahead of the normal hover fallback.

- [ ] **Step 7: Run focused tests, all TUI tests, and the fast gate**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(ViewRendersSingleQuietTopBar|TopBarHidesInviteBehindMenu|Header|MouseHoverTracksSemanticTopBarTarget|MouseTopBarActionRequiresMatchingRelease|MouseClickTopBar|MouseClickPeerTopBar)'
go test ./pkg/derpssh/tui
mise run check:fast
```

Expected: PASS.

- [ ] **Step 8: Create the top-bar checkpoint**

Run `but diff`; when only Task 2 files are present, run:

```bash
but commit codex/derpssh-opencode-ui -m "tui: modernize derpssh top bar"
```

Expected: local checkpoint only.

---

### Task 3: Layered chat panel and message hit targets

**Files:**
- Create: `pkg/derpssh/tui/chat_view.go`
- Create: `pkg/derpssh/tui/chat_view_test.go`
- Modify: `pkg/derpssh/tui/scene_content.go`
- Modify: `pkg/derpssh/tui/scene_content_test.go`
- Modify: `pkg/derpssh/tui/scene_composer_test.go`
- Modify: `pkg/derpssh/tui/app.go`

**Interfaces:**
- Consumes: Task 1 message/divider styles and Task 2 hover/press state.
- Produces: `func chatMessageTarget(int) layerTarget` and `func chatMessageIndex(layerTarget) (int, bool)`.
- Produces: `chatRenderRow { messageIndex int; content string }` and `chatRenderBlock { messageIndex int; rect Rect; content string }`.
- Produces: `func (a *App) chatRows(int) []chatRenderRow` and `func visibleChatBlocks([]chatRenderRow, Rect, int) []chatRenderBlock`.

- [ ] **Step 1: Write failing row/grouping tests in the new test file**

Create `chat_view_test.go` with:

```go
func TestChatRowsGroupAuthorAndBodyBySourceMessage(t *testing.T) {
	app := NewApp(Options{DisplayName: "shayne", Terminal: &fakePane{view: "ok"}})
	app.chatMessages = []ChatMessage{
		{Author: "alex", Body: "run this command: systemctl status derphole"},
		{Author: "shayne", Body: "checking", Local: true},
	}

	rows := app.chatRows(24)
	var remote, local int
	for _, row := range rows {
		switch row.messageIndex {
		case 0:
			remote++
		case 1:
			local++
		}
	}
	if remote < 3 || local < 2 {
		t.Fatalf("message rows = remote %d local %d, want grouped author/body rows", remote, local)
	}
}

func TestVisibleChatBlocksPreserveMessageIndexesWhenClipped(t *testing.T) {
	rows := []chatRenderRow{
		{messageIndex: 0, content: "alex"},
		{messageIndex: 0, content: "one"},
		{messageIndex: -1},
		{messageIndex: 1, content: "shayne"},
		{messageIndex: 1, content: "two"},
	}
	blocks := visibleChatBlocks(rows, Rect{X: 70, Y: 2, W: 24, H: 3}, 0)
	if len(blocks) != 1 || blocks[0].messageIndex != 1 {
		t.Fatalf("blocks = %+v, want clipped block for message 1", blocks)
	}
}
```

Add round-trip target tests for indexes `0`, `1`, and `42`, plus malformed and negative targets.

- [ ] **Step 2: Write failing scene ownership and glyph tests**

Update `scene_content_test.go` to expect `┃`, find `actionTarget(ActionToggleChat)` on the sidebar header close cell, and find `chatMessageTarget(0)` over a rendered message. Preserve terminal, divider, sidebar background, and composer assertions.

Add a test that hover state changes the ANSI-rendered message block but does not change its plain text:

```go
normal := app.buildScene().Content
app.hoverTarget = chatMessageTarget(0)
hovered := app.buildScene().Content
if normal == hovered {
	t.Fatal("message hover did not change rendered style")
}
if ansiPattern.ReplaceAllString(normal, "") != ansiPattern.ReplaceAllString(hovered, "") {
	t.Fatal("message hover changed visible text")
}
```

- [ ] **Step 3: Run the new tests and confirm failure**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(ChatRows|VisibleChatBlocks|ChatMessageTarget|SceneTargetsHeaderTerminalSidebarAndDivider|ChatMessageHover)'
```

Expected: FAIL because `chat_view.go`, message targets, and layered chat blocks do not exist.

- [ ] **Step 4: Implement target parsing and viewport rows**

Create `chat_view.go` with:

```go
const chatSpacerMessageIndex = -1

type chatRenderRow struct {
	messageIndex int
	content      string
}

type chatRenderBlock struct {
	messageIndex int
	rect         Rect
	content      string
}

func chatMessageTarget(index int) layerTarget {
	return layerTarget(fmt.Sprintf("chat-message:%d", index))
}

func chatMessageIndex(target layerTarget) (int, bool) {
	value, ok := strings.CutPrefix(string(target), "chat-message:")
	if !ok {
		return 0, false
	}
	index, err := strconv.Atoi(value)
	return index, err == nil && index >= 0
}
```

`chatRows(width)` must add an author row, wrapped body rows, then one spacer row per message. Use `displayHandleWithCounts`, preserve the original body for later copy, and select local/remote author styles without adding timestamps.

Build each message inside the available width after reserving two columns for
the accent and padding:

```go
func (a *App) chatRows(width int) []chatRenderRow {
	contentWidth := maxInt(width-2, 1)
	counts := a.identityCounts()
	rows := make([]chatRenderRow, 0, len(a.chatMessages)*3)
	for index, msg := range a.chatMessages {
		author := a.displayHandleWithCounts(msg.Author, 16, counts)
		if author == "" {
			author = "peer"
		}
		authorStyle := a.styles.MessageAuthorRemote
		if msg.Local {
			authorStyle = a.styles.MessageAuthorLocal
		}
		rows = append(rows, chatRenderRow{messageIndex: index, content: authorStyle.Render(author)})
		for _, line := range wrapPlainLines(msg.Body, contentWidth) {
			rows = append(rows, chatRenderRow{messageIndex: index, content: line})
		}
		rows = append(rows, chatRenderRow{messageIndex: chatSpacerMessageIndex})
	}
	return rows
}
```

`visibleChatBlocks` must use `chatWindowStart(len(rows), viewport.H, scroll)`, clip to the viewport, skip spacer rows as targets, and merge adjacent rows with the same nonnegative message index into one `chatRenderBlock`.

- [ ] **Step 5: Replace the monolithic sidebar layer with semantic layers**

In `scene_content.go`, paint the sidebar background first:

```go
layers := []*lipgloss.Layer{
	sceneLayer(targetSidebar, layout.Sidebar, sidebarLayerZ, sceneFill(a.styles.Sidebar, layout.Sidebar)),
}
```

Add a header layer containing `◈ Chat`, muted peer count, and a right-aligned `×` layer whose ID is `actionTarget(ActionToggleChat)`. Build a message viewport between header and composer, call `visibleChatBlocks`, and create one semantic layer per block. Choose normal/local, hover, pressed, and copied styles from `StyleSet` before calling `sceneLayer(chatMessageTarget(block.messageIndex), ...)`.

Prefix every painted message row with a colored `┃ ` accent without reducing
the source body's copy value:

```go
accent := a.styles.MessageAccentRemote
surface := a.styles.MessageRemote
if a.chatMessages[block.messageIndex].Local {
	accent = a.styles.MessageAccentLocal
	surface = a.styles.MessageLocal
}
if a.hoverTarget == chatMessageTarget(block.messageIndex) {
	surface = a.styles.MessageHover
}
if a.pressedTarget == chatMessageTarget(block.messageIndex) {
	surface = a.styles.MessagePressed
}
content := prefixChatBlock(block.content, accent.Render("┃")+" ")
content = surface.Width(block.rect.W).Height(block.rect.H).Render(content)
layers = append(layers, sceneLayer(chatMessageTarget(block.messageIndex), block.rect, sidebarLayerZ+1, content))
```

Implement `prefixChatBlock` by splitting on newlines and prepending the given
prefix to each row; it must not trim ANSI sequences or body whitespace.

Keep the native textarea as its own `targetComposer` layer. Paint the full
composer rectangle with `Composer`, place a `┃` accent in its first column, and
render the textarea in this derived inner rectangle:

```go
func composerContentRect(rect Rect) Rect {
	if rect.W <= 2 {
		return rect
	}
	return Rect{X: rect.X + 2, Y: rect.Y, W: rect.W - 2, H: rect.H}
}
```

`prepareComposerViewport`, `composerLayer`, and `composerCursor` must use the
same inner rectangle so the cursor and textarea never drift. Change
`buildDividerLayer` to render `┃` using `Divider`, `DividerHover`, or
`DividerDragging` according to app state.

Delete the now-replaced `sidebarLines`, `writeSidebarHeader`, `writeSidebarMessages`, and `writeSidebarComposer` rendering path from `app.go`, while retaining general wrapping and scroll helpers still used by tests or chat layout.

- [ ] **Step 6: Preserve composer cursor and short-layout behavior**

Adjust message viewport height to reserve exactly `sidebarComposerRows(height)` rows. Update cursor translation to use `composerContentRect(a.layout.Composer)`. For a two-row sidebar, header/background ownership may remain without a composer layer; for three or more rows, composer rect and cursor must remain inside the inner content rectangle.

- [ ] **Step 7: Run focused, full TUI, and fast verification**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(ChatRows|VisibleChatBlocks|ChatMessageTarget|SceneTargetsHeaderTerminalSidebarAndDivider|ChatMessageHover|Composer)'
go test ./pkg/derpssh/tui
mise run check:fast
```

Expected: PASS.

- [ ] **Step 8: Create the layered-chat checkpoint**

Run `but diff`; when only Task 3 files are present, run:

```bash
but commit codex/derpssh-opencode-ui -m "tui: paint layered chat messages"
```

Expected: local checkpoint only.

---

### Task 4: Click-to-copy, copied feedback, and chat mouse polish

**Files:**
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/chat_view.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/tui/app_test.go`

**Interfaces:**
- Consumes: Task 2 `pressedTarget`, Task 3 message targets/blocks, and `ChatMessage.Body`.
- Produces: `clearCopiedChatMsg { seq uint64 }` and `func clearCopiedChatTick(uint64) tea.Cmd`.
- Produces: `func (a *App) copyChatMessage(int) tea.Cmd` and `func (a *App) handleCopiedChatTick(clearCopiedChatMsg)`.
- Produces: copied state `copiedChatIndex int`, `copiedChatActive bool`, and `copiedChatSeq uint64`.

- [ ] **Step 1: Write failing message copy tests**

Add to `mouse_test.go`:

```go
func TestMouseChatMessageCopiesOnlyBodyOnMatchingRelease(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	app.chatMessages = []ChatMessage{{Author: "alex", Body: "sudo systemctl restart derphole"}}
	rect := targetRect(t, app.buildScene(), chatMessageTarget(0))

	app.Update(leftClick(rect.X+1, rect.Y))
	if app.focus != FocusChat {
		// setSidebarOpen focuses chat; the message press itself must not change it.
		t.Fatalf("unexpected focus %v", app.focus)
	}
	_, cmd := app.Update(leftRelease(rect.X+1, rect.Y))
	assertImmediateClipboard(t, cmd, "sudo systemctl restart derphole")
	if !app.copiedChatActive || app.copiedChatIndex != 0 {
		t.Fatalf("copied state = %v/%d, want active message 0", app.copiedChatActive, app.copiedChatIndex)
	}
}
```

Add tests for release on another message, empty body, multiline body, stale message index, and click preserving `chatScroll`. Use a helper that finds a rectangle by walking `Scene.TargetAt` rather than manual coordinate dispatch.

Add the helper in `mouse_test.go`:

```go
func targetRect(t *testing.T, scene Scene, target layerTarget) Rect {
	t.Helper()
	for y := 0; y < scene.Height; y++ {
		start := -1
		for x := 0; x <= scene.Width; x++ {
			matches := x < scene.Width && scene.TargetAt(x, y) == target
			if matches && start < 0 {
				start = x
			}
			if !matches && start >= 0 {
				return Rect{X: start, Y: y, W: x - start, H: 1}
			}
		}
	}
	t.Fatalf("scene target %q not found", target)
	return Rect{}
}
```

- [ ] **Step 2: Write failing feedback and wheel tests**

Add:

```go
func TestCopiedChatFeedbackIgnoresStaleTick(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.chatMessages = []ChatMessage{{Body: "one"}, {Body: "two"}}
	_ = app.copyChatMessage(0)
	stale := app.copiedChatSeq
	_ = app.copyChatMessage(1)
	app.Update(clearCopiedChatMsg{seq: stale})
	if !app.copiedChatActive || app.copiedChatIndex != 1 {
		t.Fatalf("stale tick cleared newer copied feedback")
	}
}

func TestMouseChatWheelMovesThreeRenderedRows(t *testing.T) {
	app := chatAppWithScrollableMessages(t)
	app.Update(tea.MouseWheelMsg{X: app.layout.Sidebar.X + 2, Y: app.layout.Sidebar.Y + 3, Button: tea.MouseWheelUp})
	if app.chatScroll != 3 {
		t.Fatalf("chatScroll = %d, want 3", app.chatScroll)
	}
}
```

Also assert `✓ Copied` appears only on the copied message and disappears after the matching tick.

- [ ] **Step 3: Run copy/mouse tests and confirm failure**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(MouseChatMessage|CopiedChatFeedback|MouseChatWheel)'
```

Expected: FAIL because message copy state, target handling, feedback ticks, and three-row chat scrolling are absent.

- [ ] **Step 4: Add copied feedback state and timer handling**

In `app.go`:

```go
const copiedChatFeedbackDuration = 1200 * time.Millisecond

type clearCopiedChatMsg struct {
	seq uint64
}
```

Add fields:

```go
copiedChatIndex  int
copiedChatActive bool
copiedChatSeq    uint64
```

Initialize `copiedChatIndex: -1` in `NewApp`. Handle `clearCopiedChatMsg` in `applyMessage`:

```go
func (a *App) handleCopiedChatTick(msg clearCopiedChatMsg) {
	if msg.seq != a.copiedChatSeq {
		return
	}
	a.copiedChatActive = false
	a.copiedChatIndex = -1
}

func clearCopiedChatTick(seq uint64) tea.Cmd {
	return tea.Tick(copiedChatFeedbackDuration, func(time.Time) tea.Msg {
		return clearCopiedChatMsg{seq: seq}
	})
}
```

- [ ] **Step 5: Copy message bodies on a matching left release**

In `mouse.go`:

```go
func (a *App) copyChatMessage(index int) tea.Cmd {
	if index < 0 || index >= len(a.chatMessages) {
		return nil
	}
	body := a.chatMessages[index].Body
	if strings.TrimSpace(body) == "" {
		return nil
	}
	a.copiedChatSeq++
	a.copiedChatIndex = index
	a.copiedChatActive = true
	return tea.Batch(tea.SetClipboard(body), clearCopiedChatTick(a.copiedChatSeq))
}
```

Route `chat-message:` targets before the generic sidebar case. Reuse Task 2's press/release matcher: press paints `MessagePressed`; matching release calls `copyChatMessage`; mismatched release clears state without copying. Do not call `focusChat`, clear terminal selection, or mutate `chatScroll` from the message path.

- [ ] **Step 6: Render feedback and improve chat wheel movement**

In `chat_view.go`, append a right-aligned `✓ Copied` label to the author row only when `copiedChatActive && copiedChatIndex == index`. Style the label with `MessageCopied`; retain the same plain display width while hover states change ANSI colors.

Define:

```go
const chatWheelRows = 3
```

Change `handleChatScrollMouse` so wheel-up adds three rows and clamps to the maximum derived from `len(a.chatRows(contentWidth)) - viewportHeight`; wheel-down subtracts three and clamps at zero.

- [ ] **Step 7: Add stale-state cleanup without disturbing capture**

Clear `hoverTarget` and `pressedTarget` when the chat closes, a modal/invite takes over, or a resize invalidates layer geometry. Clear copied feedback only when its timer fires or its source index becomes invalid; opening/closing chat should not erase a successful copy immediately.

Keep terminal `pointerCapture`, `terminalGesture`, `terminalSGRReleasePending`, and modal-specific `mousePress` behavior unchanged. Existing divider-drag and terminal-selection tests are the regression contract.

- [ ] **Step 8: Run focused, race-sensitive TUI, and fast checks**

Run:

```bash
go test ./pkg/derpssh/tui -run 'Test(MouseChatMessage|CopiedChatFeedback|MouseChatWheel|MouseDragDivider|MouseLocalTerminal|MouseTerminalWheel|SelectionMode|PointerCapture)'
go test ./pkg/derpssh/tui
mise run check:fast
```

Expected: PASS.

- [ ] **Step 9: Create the mouse/copy checkpoint**

Run `but diff`; when only Task 4 files are present, run:

```bash
but commit codex/derpssh-opencode-ui -m "tui: add chat hover and click-to-copy"
```

Expected: local checkpoint only.

---

### Task 5: Final regression verification and history cleanup

**Files:**
- Modify only if verification exposes a defect: files already listed in Tasks 1-4.
- Do not modify: `dist/`, protocol packages, release docs, or packaging templates.

**Interfaces:**
- Consumes: the complete Task 1-4 implementation.
- Produces: one clean, verified local feature commit stack; no push or release.

- [ ] **Step 1: Verify module pins and workspace scope**

Run:

```bash
go list -m charm.land/bubbles/v2 charm.land/bubbletea/v2 charm.land/lipgloss/v2 github.com/charmbracelet/x/ansi
but diff
but status
```

Expected: exact versions from Global Constraints; no unrelated files assigned to this branch; no uncommitted implementation changes after the last checkpoint.

- [ ] **Step 2: Run the complete focused and repository gates**

Run:

```bash
go test ./pkg/derpssh/tui
mise run smoke-derpssh-local
mise run check:fast
```

Expected: PASS. Fix any failure in the task that introduced it, rerun the focused failing command, and amend/absorb the fix into that unpublished checkpoint rather than adding a tiny fixup commit.

- [ ] **Step 3: Perform an interactive modern-terminal smoke check**

Using a PTY/TUI controller, exercise a local derpssh host/guest pair and verify:

```text
◆ derpssh  …  ● direct                         ◈ Chat  ⋮  ×
```

Confirm the following observable behavior in both dark and light terminal backgrounds:

1. glyphs occupy one cell and stay aligned while resizing;
2. top-bar actions and peer targets repaint on hover and press;
3. release away from a pressed action cancels it;
4. `┃` divider repaints on hover and remains draggable;
5. message blocks group author/body and repaint on hover;
6. clicking a command copies only its body and shows `✓ Copied` briefly;
7. wheel scrolls chat three rows without affecting terminal scrollback;
8. composer click/focus and dynamic height still work;
9. terminal selection and a mouse-aware embedded application still receive their intended mouse paths.

- [ ] **Step 4: Run the exhaustive gate once on the final stack**

At the safe boundary required by `AGENTS.md`, run:

```bash
but pull --check
mise run check
```

Expected: `but pull --check` reports current/clean base and `mise run check` passes. If tracked content changes afterward, rerun `mise run check`.

- [ ] **Step 5: Create a recovery point and tidy unpublished checkpoints**

Run:

```bash
but oplog snapshot -m "before derpssh UI history cleanup"
but status
```

If Tasks 1-4 produced multiple checkpoints, use their current IDs from `but status` with `but squash` so the branch becomes one coherent commit:

```text
tui: modernize derpssh chrome and chat
```

Do not guess commit IDs, do not rewrite another branch, and do not use raw Git history commands.

- [ ] **Step 6: Re-run final verification if history cleanup changed the tree**

Run:

```bash
go test ./pkg/derpssh/tui
mise run check
but status
```

Expected: tests and exhaustive gate pass; `codex/derpssh-opencode-ui` is one clean local feature commit based on current `origin/main`. Stop without pushing, landing, tagging, or releasing unless the user separately requests it.
