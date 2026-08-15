# Derpssh Chat and Mouse Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the reported chat rendering, identity, hover, pointer, divider drag, light-theme, cursor, and modal-dimming defects without replacing the existing TUI architecture.

**Architecture:** Extend the existing semantic scene targets and theme roles. Keep message layout, hit testing, modal stacking, and divider capture in their current owners, adding small helpers only where rendering or pointer-shape policy needs a single testable boundary.

**Tech Stack:** Go, Bubble Tea v2.0.8, Lip Gloss v2, `github.com/charmbracelet/x/ansi` v0.11.8, GitButler.

## Global Constraints

- The top-bar `Chat` action is the sole chat toggle; no peer count or inner close control remains.
- Local messages render as `you` with orange identity; remote messages render as their display handle with blue identity.
- Message, hover, press, and copy feedback paint the complete visible block.
- Pointer shapes are `text` over terminal, `ew-resize` over divider, and `default` elsewhere.
- Divider capture persists until release.
- Modal background is dimmed and front-modal controls have hover and pressed states.
- No new dependency is needed; use the already-pinned ANSI pointer-shape helper.

---

### Task 1: Chat identity and full-block rendering

**Files:**
- Modify: `pkg/derpssh/tui/chat.go`
- Modify: `pkg/derpssh/tui/chat_view.go`
- Modify: `pkg/derpssh/tui/scene_content.go`
- Test: `pkg/derpssh/tui/chat_test.go`
- Test: `pkg/derpssh/tui/chat_view_test.go`
- Test: `pkg/derpssh/tui/scene_content_test.go`

**Interfaces:**
- Consumes: `ChatMessage.Local`, `ChatLine.Local`, `visibleChatBlocks`, `fitSceneContent`.
- Produces: local `you` labels, echo absorption that preserves local identity, headerless chat viewport, full-cell message surfaces.

- [x] Add failing tests for local/remote labels, preserved local echo identity, missing inner header targets, and complete block backgrounds.
- [x] Run the focused tests and confirm failures are caused by the current behavior.
- [x] Implement the smallest chat-row and scene-content changes that satisfy them.
- [x] Run the focused tests until green.

### Task 2: Hover, pressed, and modal dim states

**Files:**
- Modify: `pkg/derpssh/tui/styles.go`
- Modify: `pkg/derpssh/tui/scene_header.go`
- Modify: `pkg/derpssh/tui/scene_modal.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Modify: `pkg/derpssh/tui/app.go`
- Test: `pkg/derpssh/tui/scene_header_test.go`
- Test: `pkg/derpssh/tui/scene_modal_test.go`
- Test: `pkg/derpssh/tui/mouse_test.go`

**Interfaces:**
- Consumes: `hoverTarget`, `pressedTarget`, `modalChoiceTarget`, existing button render functions.
- Produces: visible top-bar and modal hover/press styles plus a dimmed modal backdrop.

- [x] Add failing behavior tests for Chat/peer hover, front-modal button hover/press, and backdrop dimming.
- [x] Run the focused tests and confirm the expected failures.
- [x] Permit modal-control hover, track modal press state, apply shared button-state styles, and dim the fitted backdrop.
- [x] Run the focused tests until green.

### Task 3: Ghostty pointer shapes and stable divider capture

**Files:**
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/mouse.go`
- Test: `pkg/derpssh/tui/app_test.go`
- Test: `pkg/derpssh/tui/mouse_test.go`

**Interfaces:**
- Consumes: semantic `layerTarget`, `ansi.SetPointerShape`, `tea.Raw`, `pointerCapture`, `RuntimeStateMsg`.
- Produces: a pure target-to-pointer policy, transition-only OSC output, and divider capture preserved through runtime size updates.

- [x] Add failing tests for host/guest default arrow, terminal I-beam, divider resize pointer, modal arrow, pointer reset, and runtime update during drag.
- [x] Run the focused tests and confirm the expected failures.
- [x] Implement pointer-shape transitions and narrow runtime capture clearing so divider drag survives until release.
- [x] Run the focused tests until green.

### Task 4: Light palette and composer cursor

**Files:**
- Modify: `pkg/derpssh/tui/theme.go`
- Test: `pkg/derpssh/tui/theme_test.go`
- Test: `pkg/derpssh/tui/app_test.go`

**Interfaces:**
- Consumes: existing semantic theme roles and contrast helpers.
- Produces: restrained light surfaces, orange local/blue remote accents, and a non-black dark cursor.

- [x] Add failing assertions for the intended accent roles, neutral hierarchy, contrast, and dark cursor color.
- [x] Run focused tests and confirm the current palette fails them.
- [x] Update only semantic color assignments needed by the approved design.
- [x] Run focused tests until green.

### Task 5: Verification and publication

**Files:**
- Verify all files changed by Tasks 1 through 4.

**Interfaces:**
- Consumes: the final working tree and GitButler branch state.
- Produces: one clean commit landed on local and remote `main`, with CI status verified.

- [ ] Run `go test ./pkg/derpssh/tui`, then `mise run check:fast`.
- [ ] Run the exhaustive `mise run check` once on the final tree.
- [ ] Run `git diff --check`, `but diff`, and `but pull --check`.
- [ ] Commit one focused GitButler branch with a succinct message that does not mention the reference project.
- [ ] Fast-forward the verified commit to `origin/main`, synchronize GitButler, and verify local, tracking, and remote main refs.
- [ ] Watch GitHub Actions, retry only transient failures, and fix deterministic failures before reporting completion.
