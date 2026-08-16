# derpssh Passive Hover and Pointer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver passive hover feedback and deterministic semantic pointer shapes in Ghostty-class terminals.

**Architecture:** Bubble Tea all-motion events feed the existing semantic scene hit-test. Drag behavior continues to use pointer capture, while release feedback is recalculated from the live scene after capture clears. A one-shot post-layout reset establishes the startup arrow.

**Tech Stack:** Go 1.26, Bubble Tea v2, Lip Gloss v2, `github.com/charmbracelet/x/ansi` OSC 22 helpers.

## Global Constraints

- Use OSC 22 CSS names: `default`, `text`, and `ew-resize`.
- Preserve divider capture until release.
- Keep invite-screen mouse reporting disabled.
- Do not change visible text or control geometry to create hover feedback.
- Add regression tests before production changes.

---

### Task 1: Enable passive hover delivery

**Files:**
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/tui/keys_test.go`
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/tui/app.go`

**Interfaces:**
- Consumes: `tea.View.MouseMode`
- Produces: interactive views configured with `tea.MouseModeAllMotion`

- [x] **Step 1: Write failing tests**

Change existing mouse-mode expectations to `tea.MouseModeAllMotion` and add passive no-button motion assertions for a top-bar action and a front-modal button.

- [x] **Step 2: Verify red**

Run: `go test ./pkg/derpssh/tui -run 'TestViewDeclaresTerminalModes|TestViewKeepsMouseReportingForTerminalSelectionButNotInvite|TestMouseHoverTracksSemanticTopBarTarget|TestMouse.*Modal.*Hover' -count=1`

Expected: failures report `MouseModeCellMotion` where all-motion is required.

- [x] **Step 3: Implement minimally**

Set `view.MouseMode = tea.MouseModeAllMotion` in `configureView`, retaining `tea.MouseModeNone` for `inviteOpen`.

- [x] **Step 4: Verify green**

Run the focused command from Step 2 and expect PASS.

### Task 2: Restore semantic pointer shape after startup and drag release

**Files:**
- Modify: `pkg/derpssh/tui/mouse_test.go`
- Modify: `pkg/derpssh/tui/app_test.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/app.go`

**Interfaces:**
- Consumes: `Scene.TargetAt(x, y)`, `App.pointerCapture`, `ansi.SetPointerShape`
- Produces: `App.updatePointerForEvent(tea.MouseMsg) tea.Cmd` behavior that uses capture during drag and live hit-testing after release

- [x] **Step 1: Write failing tests**

Add tests that press and drag the divider, then release over terminal and top-bar coordinates. Assert `pointerShape` becomes `text` or `default` immediately and the returned command contains the matching OSC 22 sequence. Add a first-window-size test that expects a one-shot `default` reset.

- [x] **Step 2: Verify red**

Run: `go test ./pkg/derpssh/tui -run 'TestMouseDividerReleaseRestoresPointer|TestFirstWindowSizeResetsPointerShape' -count=1`

Expected: the pointer remains `ew-resize`, and the initial size command lacks the reset.

- [x] **Step 3: Implement minimally**

After routing a release through the captured target, rebuild the scene, hit-test the release coordinates, refresh hover from a synthetic motion target, and call `updatePointerShape` with the live target. Track the initial pointer state with an empty sentinel and return a `default` raw command from the first window-size update.

- [x] **Step 4: Verify green**

Run the focused command from Step 2 and expect PASS.

### Task 3: Verify and publish

**Files:**
- Test: `pkg/derpssh/tui/...`

**Interfaces:**
- Consumes: completed Tasks 1 and 2
- Produces: one clean commit suitable for direct landing on `main`

- [x] **Step 1: Run focused and package tests**

Run: `go test ./pkg/derpssh/tui -count=1`

- [x] **Step 2: Run the fast build gate**

Run: `mise run check:fast`

- [ ] **Step 3: Commit with GitButler**

Create one commit on `codex/tui-passive-hover-pointer` with subject `tui: fix passive hover and pointer state`.

- [ ] **Step 4: Run the exhaustive publication gate**

Run: `mise run check`

- [ ] **Step 5: Land, push, and verify CI**

After `but pull --check`, fast-forward the verified commit to `origin/main`, synchronize GitButler, confirm local and remote `main` match, then watch all GitHub Actions workflows to completion.
