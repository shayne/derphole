# Terminal-native TUI Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make derpssh inherit modern terminal appearance and input behavior while preserving the existing compact top bar and 1:1 chat design.

**Architecture:** Extend the existing theme, terminal-surface, semantic scene, and input-router boundaries rather than replacing the TUI stack. Terminal capabilities are represented as small pure helpers and optional interfaces, keeping static test panes and unsupported terminals safe. Visual feedback remains scene-layer based so rendering and hit testing stay aligned.

**Tech Stack:** Go, Bubble Tea v2, Lip Gloss v2, Charmbracelet x/ansi, x/vt, and Ultraviolet.

## Global Constraints

- Implement the six confirmed items in `docs/superpowers/specs/2026-08-15-terminal-native-tui-polish.md`.
- Do not persist chat width, visibility, focus, or any other UI state.
- Do not add dependencies; update only stale direct TUI modules after checking their current releases.
- Use failing tests before every behavior change.
- Preserve the orange local-message accent and blue remote-message accent.

---

### Task 1: Terminal-derived theme and transparent canvas

**Files:**
- Modify: `pkg/derpssh/tui/theme.go`
- Modify: `pkg/derpssh/tui/styles.go`
- Modify: `pkg/derpssh/tui/app.go`
- Test: `pkg/derpssh/tui/theme_test.go`
- Test: `pkg/derpssh/tui/app_test.go`

**Interfaces:**
- Produces: `newTerminalTheme(background, foreground color.Color) Theme`
- Produces: `NewTerminalStyleSet(background, foreground color.Color) StyleSet`
- Consumes: `tea.BackgroundColorMsg` and `tea.ForegroundColorMsg`

- [x] Add tests proving `Init` requests both terminal colors, same-scheme color replies rebuild styles, generated neutral ramps follow reported colors, and the base/terminal canvas remains unpainted.
- [x] Run the focused tests and confirm they fail for missing foreground handling and dynamic styles.
- [x] Implement terminal color storage, deterministic RGB mixing, readable fallbacks, and style rebuilding without changing semantic accent roles.
- [x] Run the focused tests and `go test ./pkg/derpssh/tui` until green.

### Task 2: Native child cursor and OSC 8 hyperlinks

**Files:**
- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_surface.go`
- Modify: `pkg/derpssh/tui/scene_content.go`
- Test: `pkg/derpssh/tui/terminal_surface_test.go`
- Test: `pkg/derpssh/tui/scene_composer_test.go`

**Interfaces:**
- Produces: `terminalCursorState() terminalCursorView` through an optional terminal-pane interface.
- Extends: `terminalCursorView` with cursor shape, steady/blink, and color.
- Extends: `terminalCell` with `uv.Link`.

- [x] Add tests that feed DECSCUSR, OSC 12, cursor visibility, and OSC 8 sequences through the real VT surface and assert Bubble Tea cursor fidelity plus hyperlink preservation/reset.
- [x] Run the focused tests and confirm failure because the current renderer reverses cursor cells and drops links.
- [x] Capture x/vt cursor state, expose it to the scene, map it to Bubble Tea cursor shapes, disable reverse-cell cursor simulation for the native pane, and diff hyperlink state while rendering rows.
- [x] Run the focused tests and the whole TUI package until green.

### Task 3: Focus reporting, pointer capability, and input modality

**Files:**
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/terminal.go`
- Modify: `pkg/derpssh/tui/terminal_surface.go`
- Test: `pkg/derpssh/tui/app_test.go`
- Test: `pkg/derpssh/tui/mouse_test.go`
- Test: `pkg/derpssh/tui/terminal_surface_test.go`

**Interfaces:**
- Produces: `pointerShapesSupported(term, termProgram string) bool`.
- Extends: `TerminalInputMode` with `FocusEvents bool`.
- Adds: app input-modality and last-pointer-position state.

- [x] Add tests for Ghostty/Kitty/iTerm/Foot capability detection, unsupported terminals, stationary motion after keyboard input, real pointer movement, release cursor restoration, outer focus messages, and child focus forwarding when mode 1004 is active.
- [x] Run the focused tests and confirm the capability/modality/focus cases fail.
- [x] Enable `ReportFocus`, forward focus/blur to opted-in child terminals, gate OSC 22 commands, and update hover only after deliberate pointer movement following keyboard input.
- [x] Run mouse, app, terminal-surface, and full TUI tests until green.

### Task 4: Quiet modal composition, unified interaction feedback, and toasts

**Files:**
- Modify: `pkg/derpssh/tui/styles.go`
- Modify: `pkg/derpssh/tui/scene_modal.go`
- Modify: `pkg/derpssh/tui/scene_header.go`
- Modify: `pkg/derpssh/tui/scene_content.go`
- Create: `pkg/derpssh/tui/scene_toast.go`
- Modify: `pkg/derpssh/tui/app.go`
- Test: `pkg/derpssh/tui/scene_modal_test.go`
- Test: `pkg/derpssh/tui/scene_header_test.go`
- Test: `pkg/derpssh/tui/scene_content_test.go`
- Test: `pkg/derpssh/tui/app_test.go`

**Interfaces:**
- Produces: `interactionStyle(base, hover, pressed lipgloss.Style, target layerTarget, app *App) lipgloss.Style` or an equivalent local helper.
- Produces: `toastState` and `buildToastLayers(width, height int) []*lipgloss.Layer`.

- [x] Add tests proving modal dimming preserves ANSI hierarchy, modal controls and header actions share hover/pressed semantics, copy creates a non-modal toast, role changes create a toast, and stale toast timers cannot clear newer feedback.
- [x] Run the focused tests and confirm the new visual-state assertions fail.
- [x] Implement per-cell backdrop dimming, quieter dialog/action-footer styles, one shared interaction-state helper, and a compact top-right toast layer with sequence-safe expiry.
- [x] Run the focused tests and full TUI package until green.

### Task 5: Focus-aware silent desktop attention

**Files:**
- Create: `pkg/derpssh/tui/attention.go`
- Modify: `pkg/derpssh/tui/app.go`
- Test: `pkg/derpssh/tui/attention_test.go`
- Test: `pkg/derpssh/tui/app_test.go`

**Interfaces:**
- Produces: `desktopNotification(title, body string) tea.Cmd`.
- Consumes: app outer-focus state plus `ChatMsg` and `ApprovalRequestMsg`.

- [x] Add tests for focused suppression, blurred remote-chat notification, local-chat suppression, approval notification, ANSI/control stripping, and bounded notification text.
- [x] Run the focused tests and confirm notification cases fail.
- [x] Implement silent OSC notification commands only while blurred, with sanitized titles/bodies and no audible bell change.
- [x] Run the focused tests and full TUI package until green.

### Task 6: Verification and GitButler checkpoint

**Files:**
- Verify all modified source, test, and design-plan files.

- [x] Run `go test ./pkg/derpssh/tui`.
- [x] Run `mise run check:fast`.
- [x] Run `git diff --check` and inspect `but diff` for scope.
- [x] Commit only this session's files on `codex/terminal-native-tui-polish` with a concise scoped message using `but commit`.
- [x] Report the local commit separately from any publication state; do not push or land without a new explicit user request.
