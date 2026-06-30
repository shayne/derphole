# derpssh TUI Foundation Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild derpssh TUI internals so terminal lifecycle, terminal rendering, input routing, overlays, chat, peer permissions, invite flow, and shutdown are reliable enough for rich shared-terminal use.

**Architecture:** Introduce hard boundaries: `TerminalLifecycle` owns terminal mode and restore, `TerminalSurface` owns PTY bytes and safe grid reads, `FrameCanvas` owns every drawn cell, `ActionRegistry` owns commands, `InputRouter` owns focus routing, `ChatPane` owns chat layout, and `RuntimeStateAdapter` owns peer/session state. Wire the existing UI through those boundaries first, then replace row-string rendering and scattered handlers with tested components.

**Tech Stack:** Go, Bubble Tea, Lip Gloss, vt10x behind a replaceable terminal-surface interface, GitButler, mise, derpssh live smoke using `derpssh@dev`.

---

## Source Spec

Implement the approved design in `docs/superpowers/specs/2026-06-29-derpssh-tui-foundation-rebuild-design.md`.

Reference repos to inspect during implementation:

- `~/code/crush/internal/ui/dialog`, `~/code/crush/internal/ui/common`, and `~/code/crush/internal/ui/styles` for modal stack, actions, full-cell fills, and semantic themes.
- `~/code/ghostty/src/terminal`, `~/code/ghostty/src/input`, and `~/code/ghostty/src/termio` for terminal-state boundaries, input encoding, mouse modes, paste, and reset order.
- `~/code/fresh/crates/fresh-editor/src/view/split.rs`, `~/code/fresh/crates/fresh-editor/src/view/theme`, and `~/code/fresh/crates/fresh-editor/tests/e2e` for thin dividers, drag resizing, focus, and clean TUI layout.
- `~/code/yeet/pkg/catch/tty_*.go` for TTY discipline and remote smoke habits only. Ignore unrelated yeet product bugs during this derpssh rebuild.

## File Structure

Create these files:

- `pkg/derpssh/session/terminal_lifecycle.go`: single owner for Bubble Tea startup, raw/alternate-screen boundary, restore sequence, final reason, and idempotent shutdown.
- `pkg/derpssh/session/terminal_lifecycle_test.go`: restore idempotence, quit ordering, no duplicate restore writes, and no leaked mouse/SGR sequences.
- `pkg/derpssh/session/runtime_state_adapter.go`: normalized host/guest/peer/permission/transport/size/shell state for the UI.
- `pkg/derpssh/session/runtime_state_adapter_test.go`: peer de-duplication, removal, close reasons, host-authoritative size, and reconnect behavior.
- `pkg/derpssh/session/invite_interstitial.go`: plain stdout invite screen and event bridge into the TUI when Enter or a guest connection arrives.
- `pkg/derpssh/session/invite_interstitial_test.go`: copyable invite output, quit before sharing, guest-connect transition, and connecting guest close reason.
- `pkg/derpssh/tui/canvas.go`: cell canvas, rectangular fills, clipping, layers, overlay composition, and render to string.
- `pkg/derpssh/tui/canvas_test.go`: full modal background fills, button-row fills, overlay clipping, and no chat/dialog cut-through.
- `pkg/derpssh/tui/theme.go`: Catppuccin Latte/Mocha palette values mapped to semantic TUI roles.
- `pkg/derpssh/tui/theme_test.go`: contrast and role sanity checks for light and dark schemes.
- `pkg/derpssh/tui/terminal_surface.go`: safe terminal-emulator boundary around vt10x with replaceable interface.
- `pkg/derpssh/tui/terminal_surface_test.go`: safe cell access, resize clamps, Vim fixture rendering, htop fixture rendering, cursor visibility, and styled blank behavior.
- `pkg/derpssh/tui/actions.go`: action registry with shortcuts, visibility, enabled state, mouse targets, and handlers.
- `pkg/derpssh/tui/actions_test.go`: guest/host action visibility, peer chip actions, menu actions, and shortcut dispatch.
- `pkg/derpssh/tui/input_router.go`: ordered routing for shutdown, modal, prefix, select mode, chat, and terminal focus.
- `pkg/derpssh/tui/input_router_test.go`: `Ctrl-R`, arrows, prefix mode, select exit, chat focus, terminal focus, and mouse dispatch.
- `pkg/derpssh/tui/header.go`: powerline-inspired top bar backed by action registry and runtime state.
- `pkg/derpssh/tui/header_test.go`: light/dark header contrast, compact peer chips, hidden guest invite action, and click targets.
- `pkg/derpssh/tui/chat.go`: chat panel layout, message wrapping, auto-scroll, unread notices, display names, and overlay mode.
- `pkg/derpssh/tui/chat_test.go`: IRC-style rendering, wrapping, unread state, display-name compaction, duplicate-message prevention, and auto-scroll.
- `pkg/derpssh/tui/composer.go`: composer viewport, placeholder, block cursor, and one-to-three-line growth.
- `pkg/derpssh/tui/composer_test.go`: placeholder cursor position, focus rendering, line growth, and scroll-after-three behavior.

Modify these files:

- `pkg/derpssh/session/console.go`: replace direct program lifecycle and restore writes with `TerminalLifecycle`; route callbacks through normalized state and close reasons.
- `pkg/derpssh/session/host.go`: emit normalized state events, close reasons, guest disconnect events, shell state, peer permission updates, and host-size updates.
- `pkg/derpssh/session/guest.go`: show waiting-for-approval state, consume host-size updates, handle close reasons, and restore terminal through lifecycle only.
- `pkg/derpssh/session/share_terminal_manager.go`: surface shell-exited and restart events to host and guests with deterministic close behavior.
- `pkg/derpssh/tui/app.go`: replace row-string assembly with canvas/compositor, remove duplicated routing, and delegate chrome rendering to header/chat/modal components.
- `pkg/derpssh/tui/layout.go`: keep a one-cell divider, host-authoritative terminal viewport, and guest chat overlay sizing.
- `pkg/derpssh/tui/keys.go`: keep terminal encoding, but move command handling into action registry and input router.
- `pkg/derpssh/tui/mouse.go`: move click handling through action registry, input router, header hit targets, chat hit targets, and thin divider resizing.
- `pkg/derpssh/tui/messages.go`: add close reason, shell state, peer id, transport state, and host-size messages.
- `pkg/derpssh/tui/styles.go`: replace direct color call sites with semantic theme roles from `theme.go`.
- Existing tests under `pkg/derpssh/session` and `pkg/derpssh/tui`: move assertions to the new APIs while keeping prior bug coverage.

## Implementation Tasks

### Task 0: Execution Setup and Baseline

**Files:**
- Read: `AGENTS.md`
- Read: `docs/superpowers/specs/2026-06-29-derpssh-tui-foundation-rebuild-design.md`
- Read: `/Users/shayne/code/derphole/.agents/skills/gitbutler/SKILL.md`

- [ ] **Step 1: Confirm GitButler branch state**

Run: `but status -fv`

Expected: output identifies the current applied branch and target branch. If another active branch owns derpssh TUI files, stop and report the overlap before editing.

- [ ] **Step 2: Check upstream race state**

Run: `but pull --check`

Expected: clean check. If it reports conflicts or updates that touch another active branch, stop and report the branch names and files.

- [ ] **Step 3: Run baseline tests**

Run: `mise run test`

Expected: either PASS or a recorded baseline failure unrelated to derpssh TUI. If derpssh tests fail at baseline, save the failing package and test names in the implementation notes before changing code.

- [ ] **Step 4: Run focused baseline tests**

Run: `go test ./pkg/derpssh/session ./pkg/derpssh/tui -count=1`

Expected: either PASS or the same recorded baseline failures from Step 3.

### Task 1: TerminalLifecycle Owns TUI Startup and Restore

**Files:**
- Create: `pkg/derpssh/session/terminal_lifecycle.go`
- Create: `pkg/derpssh/session/terminal_lifecycle_test.go`
- Modify: `pkg/derpssh/session/console.go`

- [ ] **Step 1: Add failing restore idempotence tests**

Add tests that assert a lifecycle writes restore bytes once even if `End` is called from Run completion, Stop, and context cancellation.

```go
func TestTerminalLifecycleRestoresExactlyOnce(t *testing.T) {
	var out bytes.Buffer
	p := &fakeTeaProgram{}
	l := newTerminalLifecycle(terminalLifecycleOptions{
		Output:  &out,
		Program: p,
		Restore: []byte("RESTORE"),
	})

	l.End(CloseReason{Code: "host_quit", Message: "host quit"})
	l.End(CloseReason{Code: "stop", Message: "stop called"})
	l.End(CloseReason{Code: "run_done", Message: "program returned"})

	if got := strings.Count(out.String(), "RESTORE"); got != 1 {
		t.Fatalf("restore writes = %d, want 1; output %q", got, out.String())
	}
}
```

- [ ] **Step 2: Add failing leaked-sequence test**

Add a test that exits after mouse/cursor state was enabled and asserts restore bytes are written before any final human-readable prompt text.

```go
func TestTerminalLifecycleWritesRestoreBeforeFinalReason(t *testing.T) {
	var out bytes.Buffer
	p := &fakeTeaProgram{}
	l := newTerminalLifecycle(terminalLifecycleOptions{
		Output:  &out,
		Program: p,
		Restore: []byte("\x1b[?1006l\x1b[?25h\x1b[0m"),
	})

	l.End(CloseReason{Code: "guest_quit", Message: "session ended: guest quit"})
	l.WriteFinalReason()

	got := out.String()
	restoreAt := strings.Index(got, "\x1b[?1006l")
	reasonAt := strings.Index(got, "session ended: guest quit")
	if restoreAt < 0 || reasonAt < 0 || restoreAt > reasonAt {
		t.Fatalf("restore must precede final reason, output %q", got)
	}
}
```

- [ ] **Step 3: Implement `TerminalLifecycle`**

Implement this shape and keep all terminal restore writes inside it.

```go
type CloseReason struct {
	Code    string
	Message string
}

type terminalLifecycleOptions struct {
	Output  io.Writer
	Program teaProgram
	Restore []byte
	IsTTY   bool
}

type TerminalLifecycle struct {
	output  io.Writer
	program teaProgram
	restore []byte
	isTTY   bool

	mu      sync.Mutex
	reason  CloseReason
	ended   bool
	restoreOnce sync.Once
}

func newTerminalLifecycle(opts terminalLifecycleOptions) *TerminalLifecycle {
	return &TerminalLifecycle{
		output:  opts.Output,
		program: opts.Program,
		restore: append([]byte(nil), opts.Restore...),
		isTTY:   opts.IsTTY,
	}
}

func (l *TerminalLifecycle) End(reason CloseReason) {
	l.mu.Lock()
	if !l.ended {
		l.reason = reason
		l.ended = true
	}
	l.mu.Unlock()

	l.restoreOnce.Do(func() {
		if l.output != nil && len(l.restore) > 0 {
			_, _ = l.output.Write(l.restore)
		}
		if l.program != nil {
			l.program.Quit()
		}
	})
}

func (l *TerminalLifecycle) WriteFinalReason() {
	l.mu.Lock()
	reason := l.reason
	l.mu.Unlock()
	if l.output != nil && reason.Message != "" {
		_, _ = fmt.Fprintf(l.output, "\r\nderpssh: %s\r\n", reason.Message)
	}
}
```

- [ ] **Step 4: Wire console shutdown through lifecycle**

Modify `tuiConsole.Start`, `tuiConsole.Stop`, and panic/recovery paths so they call `TerminalLifecycle.End` and never write `terminalRestoreSequence` directly after Bubble Tea returns.

- [ ] **Step 5: Remove duplicate restore writes**

Delete direct calls to `writeTerminalRestore` outside `TerminalLifecycle`. Keep `writeTerminalRestore` only as a compatibility helper if tests still use it.

- [ ] **Step 6: Verify lifecycle tests**

Run: `go test ./pkg/derpssh/session -run 'TestTerminalLifecycle|TestTUIConsole' -count=1`

Expected: PASS.

### Task 2: TerminalSurface Replaces Direct vt10x Grid Reads

**Files:**
- Create: `pkg/derpssh/tui/terminal_surface.go`
- Create: `pkg/derpssh/tui/terminal_surface_test.go`
- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_test.go`

- [ ] **Step 1: Add failing safe-cell tests**

Add tests for host/guest width mismatch and resize during a modal.

```go
func TestTerminalSurfaceClampsCellReads(t *testing.T) {
	s := newVTTerminalSurface(terminalSize{Cols: 30, Rows: 10})
	s.Resize(terminalSize{Cols: 30, Rows: 10})

	cell := s.Cell(130, 0)
	if cell.Rune != ' ' {
		t.Fatalf("out-of-range cell rune = %q, want space", cell.Rune)
	}
	if cell.Style != zeroTerminalCellStyle() {
		t.Fatalf("out-of-range cell style = %#v", cell.Style)
	}
}
```

- [ ] **Step 2: Add failing Vim artifact fixture**

Add a fixture that writes Vim-style underlined blank spans and asserts blank cells are not rendered as horizontal rule rows unless their background or reverse state is visible.

```go
func TestTerminalSurfaceDoesNotRenderUnderlineOnlyBlankCells(t *testing.T) {
	s := newVTTerminalSurface(terminalSize{Cols: 40, Rows: 5})
	s.Write([]byte("\x1b[4m                                        \x1b[0m"))

	view := renderTerminalSurfaceRows(s, terminalRenderOptions{
		Width:  40,
		Height: 5,
		Focused: false,
	})
	if strings.Contains(view, "________________________________________") {
		t.Fatalf("underline-only blank row rendered as visible rule: %q", view)
	}
}
```

- [ ] **Step 3: Implement terminal-surface interface**

Use this interface and keep vt10x behind it.

```go
type terminalSize struct {
	Cols int
	Rows int
}

type terminalCell struct {
	Rune  rune
	Style terminalCellStyle
}

type TerminalSurface interface {
	Write([]byte)
	Resize(terminalSize)
	Size() terminalSize
	Cell(x int, y int) terminalCell
	Cursor() terminalCursorView
	MouseMode() terminalMouseMode
	InputMode() terminalInputMode
	Scroll(delta int)
}
```

- [ ] **Step 4: Move current vt10x calls into `vtTerminalSurface`**

Replace direct `term.Cell(x, y)` calls with `surface.Cell(x, y)`. Clamp `x` and `y` against `surface.Size()` before reaching vt10x.

- [ ] **Step 5: Preserve styled blanks semantically**

Implement a single predicate named `terminalCellVisibleOnBlank` that returns true for reverse-video blanks and explicit-background blanks. It must return false for underline-only blanks. Document this as terminal grid semantic handling, not a Vim-only workaround.

- [ ] **Step 6: Verify terminal surface tests**

Run: `go test ./pkg/derpssh/tui -run 'TestTerminalSurface|TestTerminalPane' -count=1`

Expected: PASS.

### Task 3: Cell Canvas and Overlay Compositor

**Files:**
- Create: `pkg/derpssh/tui/canvas.go`
- Create: `pkg/derpssh/tui/canvas_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/styles.go`

- [ ] **Step 1: Add failing overlay fill tests**

Add tests that render the approval dialog and shell-exited dialog in light and dark modes, then assert every cell inside the modal rectangle has the dialog background role.

```go
func TestCanvasOverlayFillsDialogButtonRow(t *testing.T) {
	theme := newTheme(SchemeLight)
	c := NewFrameCanvas(80, 24, theme.Role(ChromeBase))
	dialog := Rect{X: 20, Y: 8, W: 40, H: 7}

	c.Fill(dialog, Cell{Rune: ' ', Style: theme.Role(DialogBase)})
	c.DrawText(22, 12, "Restart Shell", theme.Role(ButtonFocused))

	for x := dialog.X; x < dialog.X+dialog.W; x++ {
		got := c.Cell(x, 12).Style.Background
		want := theme.Role(DialogBase).Background
		if got != want && c.Cell(x, 12).Style.Background != theme.Role(ButtonFocused).Background {
			t.Fatalf("x=%d button row bg=%q, want dialog or button bg", x, got)
		}
	}
}
```

- [ ] **Step 2: Implement canvas cells and fills**

Implement a rectangular canvas that owns whitespace.

```go
type Cell struct {
	Rune  rune
	Style lipgloss.Style
}

type FrameCanvas struct {
	width  int
	height int
	cells  []Cell
}

func NewFrameCanvas(width int, height int, base lipgloss.Style) *FrameCanvas
func (c *FrameCanvas) Fill(rect Rect, cell Cell)
func (c *FrameCanvas) DrawText(x int, y int, text string, style lipgloss.Style)
func (c *FrameCanvas) Overlay(src *FrameCanvas, at Point)
func (c *FrameCanvas) Cell(x int, y int) Cell
func (c *FrameCanvas) Render() string
```

- [ ] **Step 3: Replace string overlay paths**

Replace `overlay(lines, body)` and row-slice mutation in `App.View` with `FrameCanvas` composition. Keep terminal rows as a layer, chrome as layers, and modals as last layer.

- [ ] **Step 4: Ensure dialog and menu rows fill all cells**

Rewrite modal/menu render functions so text is drawn into a filled rectangle rather than styling only the characters.

- [ ] **Step 5: Verify compositor tests**

Run: `go test ./pkg/derpssh/tui -run 'TestCanvas|TestApp.*Modal|TestApp.*Menu' -count=1`

Expected: PASS.

### Task 4: Semantic Catppuccin Theme Roles

**Files:**
- Create: `pkg/derpssh/tui/theme.go`
- Create: `pkg/derpssh/tui/theme_test.go`
- Modify: `pkg/derpssh/tui/styles.go`

- [ ] **Step 1: Add role coverage tests**

Add tests that assert every role exists for Latte and Mocha and that important foreground/background pairs have readable contrast.

```go
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
			if contrastRatio(theme.Role(role).Foreground, theme.Role(role).Background) < 4.5 {
				t.Fatalf("%s %s contrast too low", scheme, role)
			}
		}
	}
}
```

- [ ] **Step 2: Implement palette and roles**

Map Catppuccin colors through semantic roles. Use restrained Latte roles for dialogs and header states. Keep danger and approval roles readable without hot pink backgrounds.

- [ ] **Step 3: Remove direct palette use from chrome**

Update `styles.go`, header, chat, menu, and dialogs to request semantic roles only.

- [ ] **Step 4: Verify style tests**

Run: `go test ./pkg/derpssh/tui -run 'TestTheme|TestStyles' -count=1`

Expected: PASS.

### Task 5: Action Registry, Header Menu, and Peer Permission Dialog

**Files:**
- Create: `pkg/derpssh/tui/actions.go`
- Create: `pkg/derpssh/tui/actions_test.go`
- Create: `pkg/derpssh/tui/header.go`
- Create: `pkg/derpssh/tui/header_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/keys.go`
- Modify: `pkg/derpssh/tui/mouse.go`

- [ ] **Step 1: Add action visibility tests**

Add tests showing host sees invite and peer-management actions while guest does not see invite.

```go
func TestActionRegistryHidesHostOnlyInviteForGuest(t *testing.T) {
	reg := NewActionRegistry()
	ctx := ActionContext{Mode: ModeGuest, HasInvite: true}

	actions := reg.Visible(ctx)
	if hasAction(actions, ActionShowInvite) {
		t.Fatalf("guest must not see invite action")
	}
}
```

- [ ] **Step 2: Add peer-chip click test**

Add a test that clicks the host header peer chip and opens a dialog with Read, Write, and Kick actions for that peer id.

- [ ] **Step 3: Implement action registry**

Use one action model.

```go
type ActionID string

const (
	ActionQuit ActionID = "quit"
	ActionToggleChat ActionID = "toggle_chat"
	ActionFocusChat ActionID = "focus_chat"
	ActionFocusTerminal ActionID = "focus_terminal"
	ActionToggleSelect ActionID = "toggle_select"
	ActionShowMenu ActionID = "show_menu"
	ActionShowInvite ActionID = "show_invite"
	ActionGrantRead ActionID = "grant_read"
	ActionGrantWrite ActionID = "grant_write"
	ActionDenyGuest ActionID = "deny_guest"
	ActionKickPeer ActionID = "kick_peer"
	ActionRestartShell ActionID = "restart_shell"
)

type Action struct {
	ID ActionID
	Label string
	Shortcut KeyChord
	Visible func(ActionContext) bool
	Enabled func(ActionContext) bool
	Run func(*App, ActionContext) tea.Cmd
}
```

- [ ] **Step 4: Build compact top bar**

Render only the top bar. Remove bottom status. Header left segments: quit, brand, mode/user, transport, canonical size, peer chips, notable state. Header right segments: Chat, unread badge when needed, menu icon.

- [ ] **Step 5: Replace header Invite chip with menu entry**

Do not show Invite as a persistent top-right chip. Show it in the menu for host only with its shortcut.

- [ ] **Step 6: Verify action and header tests**

Run: `go test ./pkg/derpssh/tui -run 'TestAction|TestHeader|TestTopBar' -count=1`

Expected: PASS.

### Task 6: Input Router Captures Only derpssh Commands

**Files:**
- Create: `pkg/derpssh/tui/input_router.go`
- Create: `pkg/derpssh/tui/input_router_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/keys.go`
- Modify: `pkg/derpssh/tui/mouse.go`

- [ ] **Step 1: Add key pass-through tests**

Add tests for `Ctrl-R`, arrow keys, function keys, and printable text while terminal focus is active.

```go
func TestInputRouterPassesCtrlRToTerminal(t *testing.T) {
	var sent []byte
	app := newTestApp(t, ModeHost)
	app.callbacks.TerminalInput = func(b []byte) tea.Cmd {
		sent = append(sent, b...)
		return nil
	}

	_ = app.routeInput(tea.KeyMsg{Type: tea.KeyCtrlR})
	if string(sent) != "\x12" {
		t.Fatalf("sent %q, want Ctrl-R byte", string(sent))
	}
}
```

- [ ] **Step 2: Add prefix/select tests**

Add tests that `Ctrl-X` opens prefix mode, prefix mode shows correct actions, select mode exits on Esc, select mode exits on click outside, and guest prefix actions omit Invite.

- [ ] **Step 3: Implement explicit input priority**

Route input with this priority:

1. lifecycle shutdown state
2. modal or menu
3. prefix state
4. native selection mode
5. chat composer focus
6. terminal focus

- [ ] **Step 4: Keep terminal focused pass-through strict**

When focus is terminal, only `Ctrl-X` starts derpssh prefix mode. All other keys and mouse sequences go through `EncodeTerminalKeyWithMode` or `EncodeSGRMouse` when the shared terminal requests mouse tracking.

- [ ] **Step 5: Verify input routing tests**

Run: `go test ./pkg/derpssh/tui -run 'TestInputRouter|TestEncodeTerminalKey|TestMouse' -count=1`

Expected: PASS.

### Task 7: Chat Panel and Composer Rebuild

**Files:**
- Create: `pkg/derpssh/tui/chat.go`
- Create: `pkg/derpssh/tui/chat_test.go`
- Create: `pkg/derpssh/tui/composer.go`
- Create: `pkg/derpssh/tui/composer_test.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/layout.go`
- Modify: `pkg/derpssh/tui/mouse.go`

- [ ] **Step 1: Add composer line-growth tests**

Add tests for one, two, three, and five visual lines.

```go
func TestComposerGrowsToThreeLinesBeforeScrolling(t *testing.T) {
	c := NewComposer(ComposerOptions{Width: 32, MaxVisibleLines: 3})
	c.SetText("first line wraps here second line wraps here third line wraps here")

	lines := c.VisibleLines()
	if len(lines) != 3 {
		t.Fatalf("visible lines = %d, want 3: %#v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "first") {
		t.Fatalf("first line should remain visible before max height, got %#v", lines)
	}
}
```

- [ ] **Step 2: Add placeholder cursor test**

Add a test for an empty focused composer that shows the cursor at column zero while the placeholder remains readable.

```go
func TestFocusedEmptyComposerCursorStartsAtPlaceholderStart(t *testing.T) {
	c := NewComposer(ComposerOptions{Width: 20, Placeholder: "Message", MaxVisibleLines: 3})
	c.Focus()
	line := c.RenderLines(newTheme(SchemeDark))[0]

	if !strings.Contains(line, "Message") {
		t.Fatalf("placeholder missing from %q", line)
	}
	if cursorColumn(line) != 0 {
		t.Fatalf("cursor column = %d, want 0", cursorColumn(line))
	}
}
```

- [ ] **Step 3: Add chat click focus test**

Clicking the Chat header or opening chat by shortcut must focus the composer.

- [ ] **Step 4: Implement chat render model**

Use a chat model with stable message ids and no optimistic duplicate local echo.

```go
type ChatPane struct {
	open bool
	focused bool
	messages []ChatLine
	scrollOffset int
	wasAtBottom bool
	composer Composer
	unread int
}

type ChatLine struct {
	ID string
	Author DisplayName
	Text string
	Local bool
}
```

- [ ] **Step 5: Implement compact display names**

Use `user` when unique, `user@host` when another active peer has the same user, and shorten long host names to a stable prefix plus suffix.

- [ ] **Step 6: Render chat as panel or overlay without false guest size**

Host chat may reduce host terminal viewport and broadcast that size. Guest chat should render over the local frame when possible so it does not create a false resize warning.

- [ ] **Step 7: Verify chat and composer tests**

Run: `go test ./pkg/derpssh/tui -run 'TestChat|TestComposer|TestLayout' -count=1`

Expected: PASS.

### Task 8: Plain Invite Interstitial and TUI Transition

**Files:**
- Create: `pkg/derpssh/session/invite_interstitial.go`
- Create: `pkg/derpssh/session/invite_interstitial_test.go`
- Modify: `pkg/derpssh/session/console.go`
- Modify: `pkg/derpssh/session/host.go`
- Modify: `pkg/derpssh/tui/app.go`

- [ ] **Step 1: Add copyability test**

Add a test that the printed invite command is a single logical line ending with newline, not pre-wrapped with embedded newlines.

```go
func TestInviteInterstitialPrintsCommandAsOneLogicalLine(t *testing.T) {
	var out bytes.Buffer
	cmd := "npx -y derpssh@latest connect DSHlongtoken"
	i := NewInviteInterstitial(InviteOptions{Output: &out, Command: cmd})

	i.Print()
	got := out.String()
	if strings.Count(got, cmd) != 1 {
		t.Fatalf("invite command not printed exactly once: %q", got)
	}
	if strings.Contains(strings.TrimSuffix(got, "\n"), cmd+"\n") {
		t.Fatalf("invite command contains embedded newline: %q", got)
	}
}
```

- [ ] **Step 2: Add guest-before-enter transition test**

Simulate a guest connect while the host remains on the interstitial. Assert the host enters TUI mode and shows approval.

- [ ] **Step 3: Add quit-while-guest-connects test**

If host quits from the interstitial while a guest is connecting, guest receives close reason `host_quit_before_approval`.

- [ ] **Step 4: Implement interstitial controller**

Keep the initial screen outside Bubble Tea alternate screen. It reads Enter or q/Esc from stdin and also listens for a host session event named `guest_pending`.

- [ ] **Step 5: Keep in-app invite host-only**

Move in-app invite to the menu for host only. It should display the full command with a copy action when available, but the initial interstitial remains the primary manual-copy path.

- [ ] **Step 6: Verify invite tests**

Run: `go test ./pkg/derpssh/session ./pkg/derpssh/tui -run 'TestInvite|TestInitial' -count=1`

Expected: PASS.

### Task 9: Runtime State Adapter and Peer Lifecycle

**Files:**
- Create: `pkg/derpssh/session/runtime_state_adapter.go`
- Create: `pkg/derpssh/session/runtime_state_adapter_test.go`
- Modify: `pkg/derpssh/session/host.go`
- Modify: `pkg/derpssh/session/guest.go`
- Modify: `pkg/derpssh/tui/messages.go`
- Modify: `pkg/derpssh/tui/app.go`

- [ ] **Step 1: Add peer de-duplication tests**

Reconnect the same display name four times with only one active connection. Assert the header renders one peer chip.

```go
func TestRuntimeStateAdapterDeduplicatesReconnects(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeHost})
	a.UpsertPeer(PeerState{ID: "c1", Display: "shayne", Role: "write", Active: true})
	a.RemovePeer("c1", CloseReason{Code: "guest_quit", Message: "guest quit"})
	a.UpsertPeer(PeerState{ID: "c2", Display: "shayne", Role: "write", Active: true})

	peers := a.Snapshot().ActivePeers
	if len(peers) != 1 || peers[0].ID != "c2" {
		t.Fatalf("active peers = %#v, want c2 only", peers)
	}
}
```

- [ ] **Step 2: Add guest-waiting modal test**

Guest after connect and before approval must show a modal saying it is waiting for host approval.

- [ ] **Step 3: Add size synchronization test**

Host resize and host chat-open viewport changes must update canonical size and guest resize prompt state.

- [ ] **Step 4: Implement normalized state**

Use this shape:

```go
type RuntimeSnapshot struct {
	Mode RuntimeMode
	LocalName DisplayName
	Transport string
	CanonicalCols int
	CanonicalRows int
	Shell ShellState
	Approval ApprovalState
	ActivePeers []PeerState
	CloseReason CloseReason
}
```

- [ ] **Step 5: Emit state from host and guest runtimes**

Update host and guest control-message handling to emit peer add, peer remove, permission change, resize, transport change, shell state, and close reason events.

- [ ] **Step 6: Verify runtime adapter tests**

Run: `go test ./pkg/derpssh/session ./pkg/derpssh/tui -run 'TestRuntimeState|TestGuestWaiting|TestPeer' -count=1`

Expected: PASS.

### Task 10: Shell Exit, Restart, Quit, and Close Reasons

**Files:**
- Modify: `pkg/derpssh/session/share_terminal_manager.go`
- Modify: `pkg/derpssh/session/host.go`
- Modify: `pkg/derpssh/session/guest.go`
- Modify: `pkg/derpssh/session/console.go`
- Modify: `pkg/derpssh/tui/app.go`
- Test: `pkg/derpssh/session/share_terminal_manager_test.go`
- Test: `pkg/derpssh/session/share_connect_test.go`
- Test: `pkg/derpssh/tui/app_test.go`

- [ ] **Step 1: Add shell EOF host test**

Host Ctrl-D must set shell state to exited and show Restart Shell / Quit modal.

- [ ] **Step 2: Add guest close-reason test**

When host quits, guest exits to shell and prints `derpssh: session ended: host quit`.

- [ ] **Step 3: Add guest-quit host notice test**

When guest quits, host sees a dialog or notice, peer chip is removed, and header no longer shows the guest role.

- [ ] **Step 4: Implement close reason propagation**

Send close reasons through protocol `MessageClose` and normalize them in the runtime adapter.

- [ ] **Step 5: Restart shell without breaking guests**

Host Restart Shell starts a new PTY, broadcasts new size and terminal reset state, and keeps active approved guests connected.

- [ ] **Step 6: Verify close and restart tests**

Run: `go test ./pkg/derpssh/session ./pkg/derpssh/tui -run 'Test.*Close|Test.*Quit|Test.*Shell|Test.*Restart' -count=1`

Expected: PASS.

### Task 11: Rich TUI Input and Rendering Conformance

**Files:**
- Modify: `pkg/derpssh/tui/terminal_surface_test.go`
- Modify: `pkg/derpssh/tui/keys_test.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/session/input_router_test.go`

- [ ] **Step 1: Add htop key tests**

Assert up, down, function keys, and mouse events are encoded and forwarded when terminal focus is active.

- [ ] **Step 2: Add readline test**

Assert `Ctrl-R` forwards as byte `0x12` and does not enter prefix mode.

- [ ] **Step 3: Add Vim alternate-screen fixture**

Feed terminal bytes from a captured Vim screen into `TerminalSurface`. Assert there are no artificial horizontal rule rows and the cursor state remains valid.

- [ ] **Step 4: Add selection mode restoration test**

Entering native selection disables mouse forwarding. Leaving selection by Esc, click-out, or prefix shortcut restores terminal mouse mode if the application requested it.

- [ ] **Step 5: Verify conformance tests**

Run: `go test ./pkg/derpssh/tui ./pkg/derpssh/session -run 'Test.*Htop|Test.*Readline|Test.*Vim|Test.*Selection' -count=1`

Expected: PASS.

### Task 12: Local Verification and Live Smoke

**Files:**
- Modify: `scripts/smoke-local.sh` only if the existing smoke cannot cover derpssh TUI shutdown.
- Modify: `scripts/smoke-remote-share.sh` only if remote share smoke needs derpssh TUI coverage.

- [ ] **Step 1: Run full Go tests**

Run: `mise run test`

Expected: PASS.

- [ ] **Step 2: Run hooks**

Run: `mise run check:hooks`

Expected: PASS.

- [ ] **Step 3: Run local smoke**

Run: `mise run smoke-local`

Expected: PASS.

- [ ] **Step 4: Smoke derpssh dev package without publishing**

Run a local host and guest session using `derpssh@dev`. Cover share, connect, approval read, approval write, chat, peer role change, kick, guest quit, host quit, shell EOF, and Restart Shell.

Expected: host and guest terminals restore cleanly with no leaked SGR, mouse, or bracketed-paste sequences.

- [ ] **Step 5: Live smoke from `root@hetz`**

Run derpssh share/connect using `npx -y derpssh@dev` on `root@hetz`. Cover htop, Vim, shell `Ctrl-R`, chat, resize, guest quit, host quit, and shell EOF.

Expected: no terminal restore corruption, no render panics, and clean close reasons.

- [ ] **Step 6: Live smoke from `root@pve1`**

Run the same derpssh share/connect flow on `root@pve1`.

Expected: no terminal restore corruption, no render panics, and clean close reasons.

- [ ] **Step 7: Release dry run only if packaging changed**

Run: `VERSION=v0.0.0-dev COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:npm-dry-run`

Expected: PASS when packaging or npm entrypoint behavior changed. Skip this step when only Go TUI/session internals changed.

## Self-Review

- [ ] **Spec coverage:** Confirm each failure class in the spec maps to a task: lifecycle to Task 1 and Task 10, terminal rendering to Task 2 and Task 11, overlays to Task 3, input routing to Task 6, session state to Task 9, chat to Task 7, copyability to Task 8, and live confidence to Task 12.
- [ ] **Placeholder scan:** Run a literal-red-flag scan for unfinished-plan wording, constructing the query strings outside the document text, and remove every match before execution.
- [ ] **Type consistency:** Confirm `CloseReason`, `RuntimeSnapshot`, `TerminalSurface`, `FrameCanvas`, `Action`, `ChatPane`, and `Composer` names match across task snippets and target files.
- [ ] **GitButler discipline:** Use `but diff` before checkpoint commits. Use `but commit derpssh-tui-foundation -c -m "derpssh: rebuild tui foundation"` for the first checkpoint only when all changed files belong to this plan. Use `but commit derpssh-tui-foundation -m "derpssh: rebuild tui foundation"` for later checkpoints on the same branch.
- [ ] **No release during rebuild:** Use `derpssh@dev` for smoke tests. Do not tag or publish until the user asks for a semver release.
