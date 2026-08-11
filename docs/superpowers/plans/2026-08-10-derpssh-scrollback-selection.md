# derpssh Scrollback and Terminal Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the derpssh terminal pane a 10,000-line local scrollback buffer, mouse and page-key scrolling, drag and double-click text selection, and automatic clipboard copy with herdr-compatible interaction semantics.

**Architecture:** Replace the `vt10x` surface with a mutex-protected `x/vt` emulator, then keep viewport and selection state inside the terminal pane behind a private optional interaction interface. `App` routes mouse and keyboard gestures to that capability without changing the public `TerminalPane` interface, while the session console closes real panes through optional `io.Closer` support.

**Tech Stack:** Go 1.26.1, `github.com/charmbracelet/x/vt`, `github.com/charmbracelet/ultraviolet`, Bubble Tea v2, GitButler, Go's `testing` package.

## Global Constraints

- Preserve the public `TerminalPane` method set so existing fake and custom panes continue to compile.
- Keep the terminal emulator, viewport, and selection state behind one `vtTerminalSurface.mu`; clone x/vt cells before releasing the lock.
- Retain at most 10,000 primary-screen rows; alternate-screen output never enters host scrollback.
- Keep SGR mouse forwarding authoritative unless forced-selection mode is active.
- Use `tea.SetClipboard`; do not add platform clipboard commands or a protocol message.
- Do not edit generated `dist/` content or release metadata.
- Follow strict TDD: add one focused failing behavior, run it to observe the expected failure, implement only that behavior, and rerun it before proceeding.
- Preserve unrelated changes in `pkg/transfertrace/`; commit only files listed in each task.

---

## Task 1: Replace vt10x with x/vt and preserve emulator behavior

**Files:**

- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_surface.go`
- Modify: `pkg/derpssh/tui/terminal_surface_test.go`
- Modify: `pkg/derpssh/tui/terminal_test.go`

### 1.1 Pin the dependency

- [ ] Run:

  ```bash
  go get github.com/charmbracelet/x/vt@v0.0.0-20260803091719-3755ebad01b1
  go mod tidy
  ```

- [ ] Confirm `github.com/charmbracelet/x/vt` is direct, `github.com/hinshun/vt10x` is absent, and Go module selection retains the repository's already-newer Ultraviolet version.

### 1.2 Write mode-callback and split-sequence tests

- [ ] Replace the manual parser unit tests for `TrackMouseMode`, `TrackInputMode`, and `incompletePrivateModeTail` with surface-level tests that feed complete and split escape sequences:

  ```go
  func TestVTTerminalSurfaceTracksModesThroughEmulatorCallbacks(t *testing.T) {
      surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
      t.Cleanup(func() { _ = surface.Close() })

      surface.Write([]byte("\x1b[?10"))
      surface.Write([]byte("00;1006h\x1b[?1;2004;1007h"))

      if got := surface.MouseMode(); got != (MouseMode{Enabled: true, SGR: true}) {
          t.Fatalf("MouseMode() = %+v", got)
      }
      if got := surface.InputMode(); got != (TerminalInputMode{
          ApplicationCursor: true,
          BracketedPaste:    true,
          AlternateScroll:   true,
      }) {
          t.Fatalf("InputMode() = %+v", got)
      }
  }
  ```

- [ ] Add matching disable assertions for DEC modes 1, 1000/1002/1003, 1006, 1007, and 2004. Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestVTTerminalSurfaceTracksModesThroughEmulatorCallbacks'
  ```

  Expected: compile failure because `TerminalInputMode.AlternateScroll` and the new x/vt-backed surface do not exist.

### 1.3 Implement the x/vt adapter and callbacks

- [ ] Replace the `vt10x.Terminal` field and manual mode-tail parsing with:

  ```go
  const terminalScrollbackLimit = 10_000

  type vtTerminalSurface struct {
      mu            sync.Mutex
      term          *vt.Emulator
      privateModes  map[int]bool
      mouse         MouseMode
      inputMode     TerminalInputMode
      cursorVisible bool
      cursorActive  bool
      closed        bool
      drainDone     chan struct{}
  }
  ```

- [ ] Initialize `vt.NewEmulator(cols, rows)`, call `SetScrollbackSize(terminalScrollbackLimit)`, and register `vt.Callbacks`. In `EnableMode`/`DisableMode`, update `privateModes[mode.Mode()]`, then derive the existing derpssh-facing structs from the full set so disabling one tracking mode cannot erase another enabled tracking mode. The helper handles:

  ```go
  ansi.ModeCursorKeys
  ansi.ModeMouseX10
  ansi.ModeMouseNormal
  ansi.ModeMouseHighlight
  ansi.ModeMouseButtonEvent
  ansi.ModeMouseAnyEvent
  ansi.ModeMouseExtSgr
  ansi.DECMode(1007) // alternate scroll
  ansi.ModeBracketedPaste
  ```

- [ ] Add `AlternateScroll bool` to `TerminalInputMode`. Track `CursorVisibility` through the callback, but do not take `mu` recursively from a callback invoked synchronously by `term.Write`; the callback helper is called while `Write` already owns the surface lock.

- [ ] Delete `privateModePattern`, `TrackMouseMode`, `TrackInputMode`, and `incompletePrivateModeTail` after the callback tests cover their former behavior.

### 1.4 Write the response-drain regression test

- [ ] Add a test that writes a device status query from a goroutine and fails if it does not return promptly:

  ```go
  func TestVTTerminalSurfaceDrainsDeviceResponses(t *testing.T) {
      surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
      t.Cleanup(func() { _ = surface.Close() })
      done := make(chan struct{})
      go func() {
          surface.Write([]byte("\x1b[6n"))
          close(done)
      }()
      select {
      case <-done:
      case <-time.After(time.Second):
          t.Fatal("device query blocked terminal output")
      }
  }
  ```

- [ ] Run the test. Expected: it times out until the response reader exists.

### 1.5 Drain responses and make teardown idempotent

- [ ] Start one goroutine per real surface before it can receive output:

  ```go
  go func() {
      defer close(surface.drainDone)
      _, _ = io.Copy(io.Discard, surface.term)
  }()
  ```

- [ ] Implement `Close() error` under `mu`: guard with `closed`, call `term.Close()`, release the lock, then wait for `drainDone`. Add `TestVTTerminalSurfaceCloseIsIdempotent` and use `t.Cleanup` for every real surface test.

- [ ] Run:

  ```bash
  go test -race ./pkg/derpssh/tui -run 'TestVTTerminalSurface(TracksModes|DrainsDeviceResponses|CloseIsIdempotent)'
  ```

  Expected: pass with no race reports.

### 1.6 Port cursor, size, cell, and resize access

- [ ] Introduce emulator-independent value types:

  ```go
  type terminalPoint struct { X, Y int }

  type terminalCell struct {
      Content string
      Width   int
      Style   uv.Style
  }

  type terminalCursorView struct {
      cursor  terminalPoint
      visible bool
  }
  ```

- [ ] Convert `CellAt`, `CursorPosition`, `Width`, `Height`, `Resize`, and `IsAltScreen` results while holding `mu`. Treat a nil x/vt cell as `uv.EmptyCell`, and copy `uv.Cell` by value before unlocking.

- [ ] Update the existing clamp, cursor, resize, ANSI color, underline-only blank, and Vim alternate-screen fixtures to assert `Content`/`Width`/`uv.Style` instead of a rune and vt10x glyph attributes.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'Test(VTTerminalSurface|TerminalSurface|TerminalCell|VTTerminalPane)'
  ```

  Expected: pass.

### 1.7 Checkpoint

- [ ] Review only the six files in this task with `but diff`, then commit them to `codex/derpssh-scrollback-selection` with subject:

  ```text
  derpssh: migrate terminal surface to x/vt
  ```

---

## Task 2: Add the retained viewport and grapheme-aware rendering

**Files:**

- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_surface.go`
- Modify: `pkg/derpssh/tui/terminal_surface_test.go`
- Modify: `pkg/derpssh/tui/terminal_test.go`

### 2.1 Write retained-buffer and clamp tests

- [ ] Add tests that write numbered lines into a 5-row surface and assert both retained length and rendered viewport content:

  ```go
  func TestVTTerminalSurfaceScrollsRetainedRows(t *testing.T) {
      surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 5})
      t.Cleanup(func() { _ = surface.Close() })
      surface.Write([]byte("01\r\n02\r\n03\r\n04\r\n05\r\n06\r\n07"))

      if got := surface.ViewportState().ScrollbackLines; got != 2 {
          t.Fatalf("scrollback = %d, want 2", got)
      }
      surface.ScrollLines(2)
      if got := plainSurfaceRows(surface, 12, 5); !strings.HasPrefix(got, "01\n02\n03") {
          t.Fatalf("historical view = %q", got)
      }
      surface.ScrollLines(999)
      if got := surface.ViewportState().OffsetFromBottom; got != 2 {
          t.Fatalf("offset = %d, want 2", got)
      }
      surface.ScrollLines(-999)
      if got := surface.ViewportState().OffsetFromBottom; got != 0 {
          t.Fatalf("offset = %d, want 0", got)
      }
  }
  ```

- [ ] Run it. Expected: compile failure because viewport methods do not exist.

### 2.2 Implement combined-row mapping

- [ ] Add:

  ```go
  type terminalViewportState struct {
      OffsetFromBottom int
      ScrollbackLines  int
      Rows             int
      AlternateScreen bool
  }
  ```

- [ ] Store `offsetFromBottom` in the surface. Define the visible combined-buffer top row as:

  ```go
  top := term.ScrollbackLen() - offsetFromBottom
  combinedRow := top + viewportY
  ```

  Rows below `ScrollbackLen()` use `ScrollbackCellAt`; later rows use `CellAt` with the history length subtracted. Alternate screen always uses `CellAt` and offset zero.

- [ ] Remove the obsolete no-op `Scroll(delta int)` method. Implement `ScrollLines(delta int) bool`, `ResetViewport() bool`, and `ViewportState() terminalViewportState`, clamping the offset to `[0, ScrollbackLen()]` and returning whether visible state changed.

- [ ] Run the focused viewport test. Expected: pass.

### 2.3 Preserve the viewed content while output arrives

- [ ] Add `TestVTTerminalSurfacePreservesScrolledViewportOnWrite`: scroll away from bottom, record the visible rows, append enough output to grow scrollback, and require the same leading rows afterward.

- [ ] Run it. Expected: the viewport shifts toward newer content.

- [ ] In `Write`, record `before := term.ScrollbackLen()`, write bytes, then calculate positive `growth := term.ScrollbackLen() - before`. When `offsetFromBottom > 0`, add `growth` and clamp. At the fixed 10,000-row capacity, x/vt reports no further length growth; accepting the clamped view there matches the design's eviction boundary rather than inventing parser-side scroll accounting.

- [ ] Add assertions that output at live bottom stays at offset zero and alternate-screen entry/exit resets the offset. Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestVTTerminalSurface(PreservesScrolledViewportOnWrite|ResetsViewportForAlternateScreen|ScrollsRetainedRows)'
  ```

  Expected: pass.

### 2.4 Write grapheme and styled-blank rendering tests

- [ ] Add fixtures containing `界`, `e\u0301`, reverse video, background-only spaces, and underline-only spaces. Assert:

  - each grapheme appears exactly once;
  - a width-zero continuation cell emits no content;
  - background and reverse spaces remain visible;
  - underline-only trailing blanks remain suppressed.

- [ ] Run the tests. Expected: failures while rendering still expects a rune.

### 2.5 Implement Ultraviolet style rendering

- [ ] Make row rendering advance by display columns and skip `Width == 0` cells. Normalize an empty cell to `{Content: " ", Width: 1}`.

- [ ] Replace custom vt10x SGR assembly with `uv.Style.Diff`. Keep one active `uv.Style`, write only the required transition, and emit `ansi.ResetStyle` at the end when active. `terminalCellVisibleOnBlank` is true only for a background or effective reverse-video attribute; underline alone does not make a trailing blank renderable.

- [ ] Render the cursor only when `OffsetFromBottom == 0`; apply cursor inversion without losing the cell's style. Rerun the grapheme, style, cursor, and Vim fixtures.

### 2.6 Expose viewport interaction without changing TerminalPane

- [ ] Add a private capability next to `TerminalPane`:

  ```go
  type terminalViewportInteraction interface {
      ScrollLines(delta int) bool
      ResetViewport() bool
      ViewportState() terminalViewportState
  }
  ```

- [ ] Forward these methods from `vtTerminalPane` to its surface and implement `Close() error`. Add compile-time assertions for `TerminalPane`, `terminalViewportInteraction`, and `io.Closer`. Do not add these methods to `TerminalPane`.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui
  ```

  Expected: pass, including unchanged `fakePane` implementations.

### 2.7 Checkpoint

- [ ] Commit the Task 2 files with subject:

  ```text
  derpssh: add terminal scrollback viewport
  ```

---

## Task 3: Build the retained-row selection model

**Files:**

- Create: `pkg/derpssh/tui/terminal_selection.go`
- Create: `pkg/derpssh/tui/terminal_selection_test.go`
- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_test.go`
- Modify: `pkg/derpssh/tui/terminal_surface.go`
- Modify: `pkg/derpssh/tui/terminal_surface_test.go`

### 3.1 Write ordering and click-without-drag tests

- [ ] Define test helpers that seed `"alpha\r\nbeta"` into a small surface and call selection methods in viewport coordinates. Add `TestTerminalSelectionCopiesForwardAndReverseRanges`, requiring both gesture directions to return `"alpha\nbeta"`, and `TestTerminalSelectionClickWithoutMovementIsEmpty`, requiring a press/release at one cell to return `("", false)`.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestTerminalSelection(CopiesForwardAndReverseRanges|ClickWithoutMovementIsEmpty)'
  ```

  Expected: compile failure because selection types do not exist.

### 3.2 Implement retained positions and phases

- [ ] Add pure model types:

  ```go
  type terminalSelectionPhase uint8

  const (
      selectionNone terminalSelectionPhase = iota
      selectionAnchored
      selectionDragging
      selectionDone
  )

  type terminalBufferPosition struct {
      Row int // combined history + live-grid row
      Col int
  }

  type terminalSelection struct {
      anchor terminalBufferPosition
      cursor terminalBufferPosition
      phase  terminalSelectionPhase
  }
  ```

- [ ] Implement lexicographic ordering by row then column, inclusive containment, and transition from `selectionAnchored` to `selectionDragging` only after the endpoint changes. Convert viewport `(x, y)` into a combined row while holding the surface lock.

- [ ] Extend the pane capability only after the surface methods exist:

  ```go
  type terminalInteraction interface {
      terminalViewportInteraction
      BeginSelection(x, y int) bool
      UpdateSelection(x, y int) bool
      FinishSelection() (string, bool)
      SelectWord(x, y int) (string, bool)
      ClearSelection()
      SelectionActive() bool
  }
  ```

  Forward the selection methods from `vtTerminalPane` and add its compile-time `terminalInteraction` assertion.

- [ ] Rerun the two tests. Expected: pass.

### 3.3 Write extraction tests

- [ ] Add table tests for:

  - partial first and last lines;
  - full middle lines;
  - trailing blank trimming without trimming selected interior spaces;
  - reverse selection;
  - empty history cells;
  - a wide grapheme selected through either its lead or continuation column;
  - a combining grapheme copied once.

- [ ] Run the table. Expected: failures until extraction walks x/vt display cells.

### 3.4 Implement grapheme-safe extraction and highlighting

- [ ] Add a locked helper that fetches a cell by combined row and normalizes a continuation column leftward to its owning cell. Extract selected rows in display order, append `Content` once per positive-width cell, trim unselected row-end blanks, and join non-final selected display rows with `\n`.

- [ ] Add `Selected bool` to `terminalCell`. During rendering, reverse the effective style of selected cells while leaving content, width, foreground, background, and underline intact. Use XOR for `uv.AttrReverse` so a pre-reversed cell is visibly inverted rather than remaining unchanged.

- [ ] Rerun the extraction table and add a render assertion that only the selected span receives reverse-video styling.

### 3.5 Write word selection tests

- [ ] Add table cases for ASCII, Unicode letters/numbers, underscores, punctuation, whitespace, and wide graphemes:

  ```go
  tests := []struct{ line string; col int; want string }{
      {"alpha_beta!", 4, "alpha_beta"},
      {"café κόσμος", 6, "κόσμος"},
      {"one.two", 3, ""},
  }
  ```

- [ ] Define word cells as graphemes whose runes are all Unicode letters/numbers or underscore. Punctuation and whitespace return no word. Expand left/right by display cells, mark `selectionDone`, and return extracted text.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestTerminalSelection'
  ```

  Expected: pass.

### 3.6 Test scroll and invalidation invariants

- [ ] Add tests proving:

  - an anchor remains on the same combined row while `ScrollLines` changes the viewport;
  - wheel movement during drag updates the cursor against the new viewport;
  - resize clears selection and clamps viewport;
  - alternate-screen changes clear selection;
  - a write that can evict rows while the configured history is already full conservatively cancels selection.

- [ ] Add a test-only surface constructor that accepts a small scrollback limit. Implement the minimal clearing/clamping in `Resize`, `Write`, and the alt-screen callback. Because x/vt does not expose its push count once history is full, clear an active selection conservatively when a non-empty `Write` starts and ends at the configured capacity; this prevents copying text against shifted retained coordinates. Then run:

  ```bash
  go test -race ./pkg/derpssh/tui -run 'TestTerminalSelection|TestVTTerminalSurface'
  ```

  Expected: pass.

### 3.7 Checkpoint

- [ ] Commit the six Task 3 files with subject:

  ```text
  derpssh: add retained terminal selection
  ```

---

## Task 4: Route local mouse selection, scrolling, and clipboard copy

**Files:**

- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/actions.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/tui/keys_test.go`

### 4.1 Add an interactive fake pane

- [ ] Extend the TUI test helpers with a fake that embeds the existing `fakePane` and records calls to the private `terminalInteraction` methods. Provide deterministic selection strings such as `"selected text"` and configurable `MouseMode`, `InputMode`, and `terminalViewportState`.

- [ ] Keep the original `fakePane` unchanged so source compatibility remains covered.

### 4.2 Write local drag-routing tests

- [ ] Add mouse tests for left press, motion, and release over the semantic terminal target. Assert:

  - press focuses the terminal, begins selection, and sets `pointerCapture = targetTerminal`;
  - captured motion updates selection even when the scene target would be header/sidebar;
  - release calls `FinishSelection`, clears capture, and returns a command whose message is the Bubble Tea clipboard write for `"selected text"`;
  - a click with no movement returns no clipboard command.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestMouse(LocalTerminalDrag|TerminalClickWithoutDrag)'
  ```

  Expected: failures because `handleTerminalMouse` does not return a command or use the interaction capability.

### 4.3 Implement local drag and forced-selection routing

- [ ] Change `handleTerminalMouse(pointerMsg)` to return `tea.Cmd` and return it from `handleTargetMouse`.

- [ ] Convert scene coordinates to pane-relative coordinates through `currentTerminalRect()`. For an interactive pane:

  1. if `copyMode` is true, consume left-button and wheel events locally;
  2. otherwise, if `MouseMode{Enabled: true, SGR: true}`, reset the viewport and preserve `EncodeSGRMouse` forwarding;
  3. otherwise, begin/update/finish local selection and scroll locally.

- [ ] On a successful `FinishSelection`, clear the selection after creating `tea.SetClipboard(text)`. Keep a completed word selection separate for timed feedback in Step 4.5.

- [ ] Modify `HandleMouse` so copy mode no longer discards terminal gestures. A click on nonterminal chrome still calls `setCopyMode(false)`; modal handling remains first.

- [ ] Keep `view.MouseMode = tea.MouseModeCellMotion` in forced-selection mode. Only `inviteOpen` disables outer mouse reporting.

- [ ] Rename the action label from `Native Selection` to `Terminal Selection`, and retain `Ctrl-X Y`, `Esc`, and the existing top-bar status wording.

- [ ] Run the focused drag tests plus existing modal, divider, action, and SGR forwarding tests. Expected: pass.

### 4.4 Write wheel-routing tests

- [ ] Add cases asserting three rows per notch:

  - primary screen plus no SGR mouse calls `ScrollLines(+3/-3)`;
  - an active drag scrolls and updates its endpoint;
  - SGR mouse mode emits the existing mouse bytes and does not scroll locally;
  - forced-selection mode scrolls locally even when SGR mode is enabled;
  - alternate screen plus `AlternateScroll` emits three application-cursor up/down sequences;
  - alternate screen without alternate scroll does nothing locally.

- [ ] Implement a `terminalWheelRows = 3` constant and use `EncodeTerminalKeyWithMode` to build repeated cursor-key bytes for alternate-scroll mode. Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestMouse.*(Wheel|SGR|Forced|Alternate)'
  ```

  Expected: pass.

### 4.5 Write and implement double-click copy

- [ ] Add App fields:

  ```go
  lastTerminalClick terminalClick
  terminalGesture   terminalGestureKind
  selectionSeq      uint64
  ```

  where `terminalClick` stores pane-relative cell and `time.Time`. Use the existing injectable `a.now` and a `terminalDoubleClickInterval = 500 * time.Millisecond` constant.

- [ ] Test two unmodified left clicks on the same terminal cell within 500 ms. The second press calls `SelectWord`, sets `terminalGesture` to the word gesture, creates `tea.SetClipboard`, and leaves the word highlighted; its matching release only clears pointer capture. A different cell, modifier, timeout, drag, or forwarded SGR click resets the click candidate.

- [ ] Add a private `clearTerminalSelectionMsg{seq uint64}` and schedule it with `tea.Tick(500*time.Millisecond, ...)`. In `applyMessage`, clear only when the sequence still matches so stale ticks cannot erase a newer selection.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestMouseDoubleClick|TestTerminalSelectionClearTick'
  ```

  Expected: pass.

### 4.6 Write edge-autoscroll lifecycle tests

- [ ] Add `terminalSelectionAutoscrollMsg{seq uint64}` and App state recording the last pointer position and active sequence. Test that dragging one row beyond the top scrolls three rows and dragging farther ramps linearly, capped at fifteen rows. Verify ticks stop after pointer re-entry, release, modal open, resize, copy-mode exit, or sequence replacement.

- [ ] Use a 50 ms `tea.Tick` cadence. Calculate speed from out-of-bounds distance and clamp to `[3, 15]`. Each valid tick scrolls, updates the retained selection endpoint against the new viewport, and reschedules itself.

- [ ] Separate “stop the timer” from “clear the retained selection”: ordinary release only invalidates the autoscroll sequence, while `setCopyMode(false)`, modal-opening paths, and resize also call `terminalInteraction.ClearSelection()`. Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestTerminalSelectionAutoscroll'
  ```

  Expected: pass.

### 4.7 Run mouse and App regressions

- [ ] Run:

  ```bash
  go test -race ./pkg/derpssh/tui -run 'Test(Mouse|HandleMouse|App|CopyMode|TerminalSelection)'
  ```

- [ ] Confirm the existing semantic-target rule still prevents a modal/header/sidebar/divider release from becoming terminal input.

### 4.8 Checkpoint

- [ ] Commit the six Task 4 files with subject:

  ```text
  derpssh: route terminal scrolling and selection
  ```

---

## Task 5: Add page-key scrolling and live-bottom reset

**Files:**

- Modify: `pkg/derpssh/tui/input_router.go`
- Modify: `pkg/derpssh/tui/input_router_test.go`
- Modify: `pkg/derpssh/tui/keys_test.go`

### 5.1 Write page-key policy tests

- [ ] Add `TestInputRouterRoutesEligiblePageKeysToScrollback`, with Page Up expecting `+ViewportState().Rows` and Page Down expecting its negative; `TestInputRouterForwardsModifiedPageKeys`, covering Shift/Ctrl/Alt; and `TestInputRouterForwardsPageKeysForFullscreenModes`, covering mouse, application-cursor, and bracketed-paste modes. Plain Page Up/Down scrolls locally only when on the primary screen, mouse reporting is off, and neither application-cursor nor bracketed-paste mode suggests a full-screen app. Modified page keys always forward.

- [ ] Run the tests. Expected: plain page keys still emit terminal input.

### 5.2 Implement page-key interception

- [ ] Add a helper before `handleTerminalKey`:

  ```go
  func (a *App) handleTerminalViewportKey(msg tea.KeyPressMsg) bool
  ```

  Reject modifiers and forced-selection-independent full-screen states. Map `tea.KeyPgUp` to `ScrollLines(+rows)` and `tea.KeyPgDown` to `ScrollLines(-rows)`. Return true only when the local policy owns the key, including an already-clamped boundary, so an extra Page Up is not leaked to the PTY.

- [ ] Rerun page-key tests. Expected: pass.

### 5.3 Write live-bottom reset tests

- [ ] Add tests proving a forwarded terminal key and terminal paste call `ResetViewport()` before emitting their `TerminalInputCommand`. Chat paste, modal input, prefix keys, and locally consumed page keys must not reset it.

- [ ] Implement reset calls in `handleTerminalKey` and terminal-focused `RoutePaste`, also clearing temporary word-selection feedback through the interaction capability.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/tui -run 'TestInputRouter|TestTerminalKey'
  ```

  Expected: pass.

### 5.4 Checkpoint

- [ ] Commit the three Task 5 files with subject:

  ```text
  derpssh: add terminal viewport key routing
  ```

---

## Task 6: Close x/vt panes from the session lifecycle

**Files:**

- Modify: `pkg/derpssh/session/console.go`
- Modify: `pkg/derpssh/session/console_test.go`

### 6.1 Write optional-close tests

- [ ] Add `closingTerminalPane`, embedding `recordingTerminalPane` and recording an atomic close count. `TestTUIConsoleStopClosesTerminalPaneOnce` calls `Stop` twice and expects one close; `TestTUIConsoleProgramExitClosesTerminalPane` returns from a fake `Run` and expects one close; `TestTUIConsoleStopAcceptsPaneWithoutCloser` uses the existing fake and expects no panic.

- [ ] Run:

  ```bash
  go test ./pkg/derpssh/session -run 'TestTUIConsole.*Close.*TerminalPane'
  ```

  Expected: the close-aware fake records zero calls.

### 6.2 Implement optional ownership and idempotent close

- [ ] Add these fields to `tuiConsole`:

  ```go
  terminalCloser io.Closer
  terminalCloseOnce sync.Once
  ```

- [ ] In `newTUIConsole`, set `terminalCloser` only when the chosen pane implements `io.Closer`. Add:

  ```go
  func (c *tuiConsole) closeTerminalPane() {
      c.terminalCloseOnce.Do(func() {
          if c.terminalCloser != nil {
              _ = c.terminalCloser.Close()
          }
      })
  }
  ```

- [ ] Call it from `Stop` after program shutdown/terminal restoration and from the program goroutine after `program.Run` returns. Idempotence must cover both paths racing.

- [ ] Run:

  ```bash
  go test -race ./pkg/derpssh/session -run 'TestTUIConsole.*TerminalPane'
  ```

  Expected: pass.

### 6.3 Checkpoint

- [ ] Commit the two Task 6 files with subject:

  ```text
  derpssh: close terminal emulator on shutdown
  ```

---

## Task 7: Integrate and verify the complete behavior

**Files:**

- Modify only as failures require: files from Tasks 1–6

### 7.1 Run focused package tests

- [ ] Run:

  ```bash
  go test -race ./pkg/derpssh/tui ./pkg/derpssh/session
  ```

- [ ] Fix only feature-related failures. If an unrelated `pkg/transfertrace` change fails, report it separately and do not absorb it into this branch.

### 7.2 Run the repository build-only gate

- [ ] Run:

  ```bash
  mise run check:fast
  ```

  Expected: every derphole product builds with the new emulator dependency.

### 7.3 Perform manual PTY smoke checks

- [ ] Run derpssh in a local terminal and verify:

  - output longer than the pane scrolls three lines per wheel notch;
  - Page Up/Down traverses shell output;
  - new output does not pull a historical view to the bottom;
  - typing returns to live output;
  - forward and reverse drags copy multiline text;
  - double-click copies a Unicode/underscore word;
  - drag edge and drag-wheel scrolling extend selection;
  - Vim or htop receives SGR mouse events normally;
  - `Ctrl-X Y` forces local selection inside a mouse-aware app;
  - entering/leaving Vim does not expose primary scrollback in its alt screen.

### 7.4 Clean the unpublished history

- [ ] Run `but pull --check`. If clean and limited to this branch, create a recovery point:

  ```bash
  but oplog snapshot -m "before derpssh scrollback history cleanup"
  ```

- [ ] Use GitButler to fold the implementation checkpoints into one coherent unpublished commit based on current `origin/main`, with final subject:

  ```text
  derpssh: add terminal scrollback and selection
  ```

- [ ] Run `go test -race ./pkg/derpssh/tui ./pkg/derpssh/session` and `mise run check:fast` again if history cleanup changes the tree.

- [ ] Do not push, land on `main`, open a pull request, or cut a release without a separate user request.

## Completion Criteria

- All design goals in `docs/superpowers/specs/2026-08-10-derpssh-scrollback-selection-design.md` are represented by focused tests.
- The public `TerminalPane` interface remains unchanged.
- x/vt query responses drain and pane shutdown is idempotent under the race detector.
- Primary scrollback, alternate-screen isolation, grapheme rendering, selection extraction, mouse ownership, clipboard copy, autoscroll, page keys, and live-bottom resets all pass.
- `go test -race ./pkg/derpssh/tui ./pkg/derpssh/session` passes.
- `mise run check:fast` passes.
- The GitButler branch contains only this feature and its two design documents; unrelated transfer-trace work remains untouched.
