# Reliable Chat Divider Dragging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make exact-divider chat resizing reliable by processing press, motion, and release as one ordered Bubble Tea input stream.

**Architecture:** Route raw `tea.MouseMsg` values synchronously through `App.Update`. Resolve the semantic scene target only when no pointer target is captured, then preserve the existing divider capture across motion and release. Remove the asynchronous `View.OnMouse` forwarding path so each physical event is handled exactly once and in arrival order.

**Tech Stack:** Go, Bubble Tea v2.0.8, Lip Gloss v2.0.5 semantic layers, GitButler, Go tests, mise verification tasks.

## Global Constraints

- Keep the visible divider and its hit area exactly one terminal cell wide.
- Do not add invisible pointer padding around the divider.
- Treat a drag as the ordered state machine press, capture, motion, release.
- Keep interaction-state mutations in `Update`; `View` remains a rendering operation.
- Use the semantic Lip Gloss scene for uncaptured pointer hit-testing.
- Route captured motion and release to the captured semantic target regardless of their coordinates.
- Preserve existing capture cancellation when a modal opens or mouse interaction is disabled.
- Do not change layout calculations, sidebar width constraints, keyboard resizing, terminal SGR encoding, or unrelated Charm v2 APIs.
- Use GitButler for commits and history operations; do not include another session's changes.

---

## File Structure

- `pkg/derpssh/tui/app.go`: accept ordered raw mouse messages in the model update loop and stop installing asynchronous view callbacks.
- `pkg/derpssh/tui/mouse.go`: resolve uncaptured semantic targets and synchronously dispatch raw pointer events through the existing mouse state machine.
- `pkg/derpssh/tui/scene.go`: retain scene hit-testing while deleting the obsolete command-producing pointer adapter.
- `pkg/derpssh/tui/mouse_test.go`: prove synchronous exact-divider capture, capture outside the divider during motion, exact adjacent-cell behavior, and direct raw-event routing for the existing mouse suite.
- `pkg/derpssh/tui/scene_header_test.go`: replace the obsolete assertion that raw mouse messages are ignored with the ordered raw-header-action contract.

### Task 1: Route Pointer Gestures Through the Ordered Update Stream

**Files:**
- Modify: `pkg/derpssh/tui/app.go:229-241,362-382`
- Modify: `pkg/derpssh/tui/mouse.go:22-35`
- Modify: `pkg/derpssh/tui/scene.go:39-57`
- Modify: `pkg/derpssh/tui/mouse_test.go:304-390,606-618`
- Modify: `pkg/derpssh/tui/scene_header_test.go:65-74`
- Test: `pkg/derpssh/tui/mouse_test.go`
- Test: `pkg/derpssh/tui/scene_header_test.go`

**Interfaces:**
- Consumes: `Scene.TargetAt(x int, y int) layerTarget`, `App.pointerCapture layerTarget`, `HandleMouse(app *App, pointer pointerMsg) tea.Cmd`, and ordered raw `tea.MouseMsg` values delivered to `App.Update`.
- Produces: `func (a *App) handleMouseMessage(msg tea.MouseMsg) tea.Cmd`, synchronous mouse routing in `App.handleInteractiveMessage`, and a `tea.View` with mouse mode enabled but `OnMouse == nil`.

- [ ] **Step 1: Add failing regression tests for synchronous exact-divider capture**

Add these tests near the existing divider-drag tests in `pkg/derpssh/tui/mouse_test.go`:

```go
func TestRawMouseExactDividerPressCapturesSynchronously(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	divider := app.layout.Divider

	app.Update(clickAt(divider.X, divider.Y+1, tea.MouseLeft))

	if app.pointerCapture != targetDivider || !app.draggingDivider {
		t.Fatalf("capture, dragging = %q, %v; want divider, true", app.pointerCapture, app.draggingDivider)
	}
}

func TestViewDoesNotAsynchronouslyForwardMouseEvents(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	view := app.View()

	if view.OnMouse != nil {
		t.Fatal("View().OnMouse is non-nil; raw mouse events must be ordered through Update")
	}
}
```

- [ ] **Step 2: Run the new tests and verify the red state**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -run 'TestRawMouseExactDividerPressCapturesSynchronously|TestViewDoesNotAsynchronouslyForwardMouseEvents' -count=1
```

Expected: FAIL because the raw divider press is ignored and `View().OnMouse` is non-nil.

- [ ] **Step 3: Add synchronous raw-event routing**

Add this method beside `newPointerMsg` in `pkg/derpssh/tui/mouse.go`:

```go
func (a *App) handleMouseMessage(msg tea.MouseMsg) tea.Cmd {
	target := a.pointerCapture
	if target == "" {
		mouse := msg.Mouse()
		target = a.buildScene().TargetAt(mouse.X, mouse.Y)
	}
	return HandleMouse(a, newPointerMsg(target, msg))
}
```

This performs a scene hit-test for an uncaptured press or independent pointer event. Once the divider captures the pointer, motion and release skip coordinate hit-testing and remain routed to `targetDivider`.

- [ ] **Step 4: Route raw mouse messages through the new method**

Replace the ignored raw-mouse case in `App.handleInteractiveMessage` in `pkg/derpssh/tui/app.go`:

```go
case tea.MouseMsg:
	return a.handleMouseMessage(msg), true
```

Keep the existing `pointerMsg` case as the internal semantic-handler boundary used by focused mouse-handler tests. Production mouse input will reach that representation synchronously through `handleMouseMessage`, not through `View.OnMouse`.

- [ ] **Step 5: Remove the asynchronous view callback and command adapter**

In `App.configureView`, delete the captured `pointerCapture` value and the `view.OnMouse` callback:

```go
func (a *App) configureView(view tea.View, scene Scene) tea.View {
	view.AltScreen = true
	view.MouseMode = tea.MouseModeCellMotion
	if a.modalActive() {
		a.clearPointerCapture()
	}
	if a.copyMode || a.inviteOpen {
		a.clearPointerCapture()
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

Delete `Scene.PointerCmd` from `pkg/derpssh/tui/scene.go`. Keep `Scene.TargetAt` unchanged; it remains the single semantic hit-testing boundary.

- [ ] **Step 6: Verify the minimal implementation turns the regression tests green**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -run 'TestRawMouseExactDividerPressCapturesSynchronously|TestViewDoesNotAsynchronouslyForwardMouseEvents' -count=1
```

Expected: PASS.

- [ ] **Step 7: Move the existing mouse suite onto the real raw-event boundary**

Rename `dispatchViewMouse` to `dispatchMouse` throughout `pkg/derpssh/tui/mouse_test.go` and `pkg/derpssh/tui/header_test.go`. Replace its implementation and delete `viewMouseCmd`:

```go
func dispatchMouse(t *testing.T, app *App, msg tea.MouseMsg) {
	t.Helper()
	app.Update(msg)
}
```

Replace the two direct `viewMouseCmd` calls with raw messages:

```go
_, cmd := app.Update(leftClick(0, 0))
```

and:

```go
_, repaint := app.Update(leftRelease(x, y))
```

Rename `TestViewOnMouseUsesRenderedLayerAndCapturesDividerDrag` to `TestRawMouseUsesRenderedLayerAndCapturesDividerDrag`.

Replace `TestRawMouseMessageDoesNotDispatchPointerAction` in `pkg/derpssh/tui/scene_header_test.go` with `TestRawMouseMessageDispatchesPointerAction`, send the existing raw chat-action click through `app.Update`, and assert that `app.sidebarOpen` is true. The old assertion encoded the superseded architecture in which raw mouse messages were deliberately discarded.

- [ ] **Step 8: Add exact adjacent-cell and captured-motion coverage**

Add the following test beside the synchronous capture regression:

```go
func TestRawMouseDividerHitAreaRemainsExactlyOneCell(t *testing.T) {
	for _, tc := range []struct {
		name string
		dx   int
	}{
		{name: "terminal neighbor", dx: -1},
		{name: "sidebar neighbor", dx: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
			app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
			app.setSidebarOpen(true)
			divider := app.layout.Divider

			app.Update(clickAt(divider.X+tc.dx, divider.Y+1, tea.MouseLeft))

			if app.pointerCapture == targetDivider || app.draggingDivider {
				t.Fatalf("neighbor dx %d captured divider", tc.dx)
			}
		})
	}
}
```

Keep `TestRawMouseUsesRenderedLayerAndCapturesDividerDrag` asserting that motion eight cells outside the divider remains captured until release. This proves capture, rather than a widened hit zone, owns the gesture.

- [ ] **Step 9: Run focused TUI tests**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -count=1
```

Expected: PASS with the entire existing semantic-target, modal, terminal-mouse, and divider suite now exercising raw ordered events.

- [ ] **Step 10: Inspect and commit only the TUI fix**

Run `but diff`, select only the IDs for:

- `pkg/derpssh/tui/app.go`
- `pkg/derpssh/tui/mouse.go`
- `pkg/derpssh/tui/scene.go`
- `pkg/derpssh/tui/mouse_test.go`
- `pkg/derpssh/tui/header_test.go`
- `pkg/derpssh/tui/scene_header_test.go`

Copy the six file IDs printed by `but diff` into one comma-separated `--changes` argument, then commit them to `codex/chat-divider-drag-ordering` with the message `tui: preserve mouse gesture ordering`. Do not hard-code IDs before reading the current diff because GitButler IDs can change as other sessions update the shared workspace.

Expected: one implementation commit above the design and plan commits, with all unrelated HTTP-proxy and transport changes still outside this branch.

### Task 2: Verify the Exact Branch in Isolation

**Files:**
- Verify: `pkg/derpssh/tui/app.go`
- Verify: `pkg/derpssh/tui/mouse.go`
- Verify: `pkg/derpssh/tui/scene.go`
- Verify: `pkg/derpssh/tui/mouse_test.go`
- Verify: `pkg/derpssh/tui/header_test.go`
- Verify: `pkg/derpssh/tui/scene_header_test.go`

**Interfaces:**
- Consumes: the committed `codex/chat-divider-drag-ordering` branch.
- Produces: clean focused, repository, and race verification evidence pinned to the exact implementation commit.

- [ ] **Step 1: Run the broader derpssh test surface in the working repository**

Run:

```bash
mise exec -- go test ./pkg/derpssh/... ./cmd/derpssh/... -count=1
```

Expected: PASS. If an unrelated applied branch prevents compilation, record the exact failure and continue with the clean-clone verification below rather than changing another session's work.

- [ ] **Step 2: Create a clean temporary clone pinned to the branch commit**

Run:

```bash
verify_dir="$(mktemp -d /tmp/derphole-divider-verify.XXXXXX)"
git clone --quiet --no-local /Users/shayne/code/derphole "$verify_dir"
git -C "$verify_dir" checkout --quiet --detach "$(git rev-parse codex/chat-divider-drag-ordering)"
git -C "$verify_dir" rev-parse HEAD
```

Expected: the printed commit equals `git rev-parse codex/chat-divider-drag-ordering` in the working repository.

- [ ] **Step 3: Run repository and race gates on the exact commit**

Run:

```bash
(
	cd "$verify_dir"
	mise run check
	mise run race
)
```

Expected: both commands PASS. Any failure belongs to the exact branch and must be diagnosed with `superpowers:systematic-debugging` before completion.

- [ ] **Step 4: Confirm the committed scope**

Run:

```bash
git diff --name-only main..codex/chat-divider-drag-ordering
git log --oneline --reverse main..codex/chat-divider-drag-ordering
```

Expected changed paths:

```text
docs/superpowers/plans/2026-07-12-divider-drag-event-ordering.md
docs/superpowers/specs/2026-07-12-divider-drag-event-ordering-design.md
pkg/derpssh/tui/app.go
pkg/derpssh/tui/header_test.go
pkg/derpssh/tui/mouse.go
pkg/derpssh/tui/mouse_test.go
pkg/derpssh/tui/scene.go
pkg/derpssh/tui/scene_header_test.go
```

Expected history: the design commit, the implementation-plan commit, and one implementation commit. Do not squash or publish unless the user explicitly requests integration.
