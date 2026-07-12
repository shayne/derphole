# Charm v2 TUI replatform design

## Summary

Derpssh should upgrade its Charm stack as one coherent TUI replatform, not as a
mechanical import-path edit. Bubble Tea v2, Bubbles v2, and Lip Gloss v2 replace
several abstractions that Derpssh currently implements itself: terminal-mode
state, cell composition, visual layering, hit testing, background-aware styles,
mouse event modeling, and cursor rendering.

The migration will use every new abstraction that improves Derpssh's current
responsibilities. Lip Gloss canvas, compositor, and layers will replace the
custom frame compositor. Bubble Tea's declarative `View`, `OnMouse`, enhanced
key events, paste events, background query, cursor, and clipboard command will
replace the corresponding v1 and custom paths. Bubbles textarea will render the
chat composer and provide its real cursor.

The product behavior remains the contract. Shell input, terminal rendering,
mouse forwarding, chat, modals, invitation handling, selection mode, resize,
and terminal restoration must remain correct across host and guest sessions.

## Upstream baseline

Use the current stable versions verified on 2026-07-12:

| Current dependency | Target dependency | Target version |
| --- | --- | --- |
| `github.com/charmbracelet/bubbletea` | `charm.land/bubbletea/v2` | `v2.0.8` |
| `github.com/charmbracelet/bubbles` | `charm.land/bubbles/v2` | `v2.1.1` |
| `github.com/charmbracelet/lipgloss` | `charm.land/lipgloss/v2` | `v2.0.5` |
| `github.com/charmbracelet/x/ansi` | unchanged module path | `v0.11.7` |

The v2 modules require Go 1.25. Derphole already declares Go 1.26.1, so the
upgrade does not raise the repository's minimum beyond its existing baseline.

Primary migration references:

- [Bubble Tea v2 upgrade guide](https://github.com/charmbracelet/bubbletea/blob/v2.0.8/UPGRADE_GUIDE_V2.md)
- [Bubbles v2 upgrade guide](https://github.com/charmbracelet/bubbles/blob/v2.1.1/UPGRADE_GUIDE_V2.md)
- [Lip Gloss v2 upgrade guide](https://github.com/charmbracelet/lipgloss/blob/v2.0.5/UPGRADE_GUIDE_V2.md)

## Current scope

Charm usage is concentrated under `pkg/derpssh`. The direct surface includes:

- Bubble Tea program construction, lifecycle, messages, commands, keys, mouse,
  window size, alternate screen, and mouse mode.
- Bubbles textarea for chat editing state.
- Lip Gloss styles, borders, adaptive colors, and the custom frame compositor.
- `x/ansi` width, truncation, cutting, and wrapping helpers.

The largest migration surfaces are the key encoder and tests, mouse routing,
the `App.View` contract, global adaptive styles, custom `FrameCanvas`, modal
drawing, manual hit rectangles, composer rendering, and out-of-band OSC52
clipboard output.

## Goals

- Move the complete Charm TUI dependency set to its current stable APIs.
- Replace custom composition and hit-testing machinery with Lip Gloss v2
  canvas, compositor, and layers.
- Make terminal capabilities declarative through `tea.View`.
- Use the correct input and output streams for background detection and color
  downsampling, including remote terminal sessions.
- Improve PTY input fidelity with v2 key metadata and explicit paste events.
- Use Bubbles' real cursor for the chat composer.
- Remove out-of-band terminal writes that can race Bubble Tea's renderer.
- Preserve every existing user-visible Derpssh interaction and teardown path.
- Leave the TUI on abstractions that can absorb future Charm fixes without
  another repository-wide compatibility layer.

## Non-goals

- Replacing the VT terminal emulator or changing the Derpssh wire protocol.
- Redesigning the visual language, shortcuts, layout, or permission model.
- Adding key-release-driven interactions.
- Using unrelated `tea.View` features such as native progress bars or changing
  the user's terminal window title.
- Forcing terminal-wide foreground or background colors over the embedded
  shell's own default-color semantics.
- Publishing a release as part of the migration.

## Chosen approach

Perform a full rendering replatform while retaining the existing application,
session, and terminal-surface boundaries.

This is intentionally broader than a compatibility-focused port. A mechanical
port would leave Bubble Tea event details spread throughout the TUI, retain
global or blocking color behavior, and continue maintaining a custom cell and
hit-testing stack beside Lip Gloss's new implementation. Conversely, replacing
the terminal emulator or session model would combine unrelated risks with the
dependency migration.

The boundary is therefore:

- Charm v2 owns outer terminal I/O, rendering, composition, theme detection,
  cursor display, clipboard output, and decoded input events.
- Derpssh owns application state, semantic actions, layout policy, terminal
  emulation, PTY byte encoding, permissions, and session transport.

## Architecture

### Declarative root view

`App.View()` will return `tea.View`. A render pass will build an immutable
scene, then map the scene into the root view:

- `Content` is the fixed-size Lip Gloss canvas render.
- `AltScreen` is true while the TUI is active.
- `MouseMode` is cell motion during normal interaction and none during native
  selection or other states that intentionally release mouse reporting.
- `Cursor` is the offset Bubbles textarea cursor only while chat owns focus.
- `KeyboardEnhancements` requests alternate keys, all keys as escape codes,
  and associated text, but not press/release event types.
- `OnMouse` resolves the pointer target against the compositor captured by
  that render pass and emits a semantic pointer message.

The session console will stop passing `WithAltScreen` and
`WithMouseCellMotion`. Commands that imperatively enable or disable mouse mode
will disappear. Full-scene rendering should also eliminate ad hoc clear-screen
commands except where a test proves that a real terminal still requires one.

### Scene construction

Introduce a scene builder whose output contains:

- the fixed-width and fixed-height `lipgloss.Canvas`;
- the `lipgloss.Compositor` used to draw it;
- the optional real cursor and its absolute offset;
- immutable hit-test data captured by `OnMouse`;
- the selected theme and terminal-mode declarations.

All coordinates come from the existing `Layout` calculation. The scene builder
must clamp empty and tiny layouts before creating layers so a one-column or
one-row terminal cannot produce invalid bounds or nil layers.

### Layer model

The scene uses explicit Z-order bands:

1. Base application and terminal surfaces.
2. Top bar, sidebar, composer, and divider.
3. Interactive controls and their exact hit regions.
4. Modal backdrop and panel.
5. Modal labels, buttons, and focused controls.

Terminal content, chrome, chat, and each modal become positioned layers.
Structural layers fill every owned cell, including styled whitespace, so
revealing or dismissing a layer cannot leave holes from underlying content.

Interactive layers use stable semantic IDs rather than coordinates stored in
parallel data structures. Example IDs include:

- `action:toggle-chat`
- `action:show-invite`
- `peer:<peer-id>`
- `divider:chat`
- `approval:read`
- `approval:write`
- `approval:deny`
- `modal:blocker`

IDs are parsed into existing `ActionID` values or modal-specific choices. A
modal blocker is the topmost interactive surface outside modal controls, so a
dialog captures input without every handler rechecking the stack.

`FrameCanvas`, manual top-bar hit rectangles, and modal cell drawing will be
removed after their behavioral tests pass against the new scene.

### Pointer targeting and capture

`tea.View.OnMouse` will wrap v2 mouse messages in a Derpssh pointer message that
contains the semantic layer target from the rendered compositor. `Update`
handles the targeted message rather than recomputing hit rectangles from
possibly newer layout state.

Divider dragging uses pointer capture. After a press targets the divider, the
next rendered view captures motion and release for the divider regardless of
which layer is under the pointer. Modal state has higher priority and cancels
an existing divider capture.

### Terminal surface

The VT terminal surface remains responsible for consuming PTY bytes and
tracking the embedded program's grid, cursor, mouse mode, application-cursor
mode, and related terminal state. Its rendered ANSI screen becomes a clipped
Lip Gloss layer.

Lip Gloss canvas then owns outer grapheme measurement, ANSI cell drawing,
styled blank cells, clipping, and overlay composition. This replaces the
custom frame-level ANSI rune parser without pretending that Lip Gloss is a VT
emulator.

### Styles and theme selection

Replace package-level adaptive style variables with a per-`App` style set.
Style construction accepts a concrete `ColorScheme` and produces pure Lip
Gloss values from the existing semantic theme roles.

`App.Init()` returns `tea.RequestBackgroundColor`. A
`tea.BackgroundColorMsg` selects Catppuccin Latte or Mocha, rebuilds the style
set, and applies matching Bubbles textarea styles. Dark mode is the deterministic
initial fallback when a terminal does not answer the query.

Do not use `lipgloss/compat`, a global renderer, `SetColorProfile`, or
`SetHasDarkBackground`. Bubble Tea v2 performs output color downsampling. Tests
that need deterministic output use program-level color profile options or
concrete scheme construction.

### Composer and real cursor

Configure the Bubbles v2 textarea with the active theme, one-to-three visible
rows, no line numbers, no prompt, the existing placeholder, and a real cursor.
The scene uses the textarea's rendered content instead of reading `Value()` and
drawing a second composer implementation.

Set the textarea to non-virtual cursor mode. Offset `textarea.Cursor()` by the
composer layer's absolute position and assign it to `tea.View.Cursor` only
while chat is focused. This makes insertion, deletion, navigation, wrapping,
scrolling, placeholder display, blink, and cursor position come from one
component.

When terminal focus is active, the outer real cursor is nil. The embedded
terminal surface continues rendering its own emulated cursor as content.

## Input migration

### Key presses

Handle only `tea.KeyPressMsg` for user input. Key-release reporting remains
disabled to prevent duplicate PTY input. Use `Code`, `Text`, `Mod`,
`ShiftedCode`, and `BaseCode`; do not recreate v1 `KeyType` or `Runes` shims.

The PTY key encoder will support:

- printable associated text, including international input;
- Alt-prefixed printable input;
- Ctrl mappings for ASCII control characters;
- Shift and modifier-aware navigation and function keys using standard xterm
  modifier parameters;
- existing application-cursor sequences for unmodified arrow keys;
- the current prefix and modal shortcuts using semantic string or code/modifier
  matching.

If a key combination has no safe representation for the embedded terminal,
the encoder returns no bytes instead of emitting a malformed sequence.

### Paste

Handle `tea.PasteMsg` separately from key presses:

- Chat focus passes the message to Bubbles textarea.
- Terminal focus forwards the entire content as one PTY input operation.
- Modal, menu, approval, and prefix states do not interpret paste as actions.

Extend `TerminalInputMode` to track private mode `?2004`. When the embedded
program enables bracketed paste, wrap terminal-focused paste content in
`ESC[200~` and `ESC[201~`. Otherwise forward the content unchanged.

### Mouse

Use the concrete v2 message kinds:

- `tea.MouseClickMsg`
- `tea.MouseReleaseMsg`
- `tea.MouseWheelMsg`
- `tea.MouseMotionMsg`

UI events route by compositor layer ID. Terminal-targeted events translate the
v2 mouse kind, button, modifiers, and relative coordinates into SGR input only
when the embedded application has enabled a compatible mouse mode. Selection
mode disables outer mouse reporting declaratively and does not forward events.

## Lifecycle and terminal I/O

Bubble Tea's declarative view owns normal alternate-screen, cursor, mouse,
bracketed-paste, keyboard-enhancement, synchronized-output, Unicode-width, and
renderer cleanup transitions.

Derpssh retains `TerminalLifecycle` and its final restore sequence as a
defensive last resort for cancellation, panic, broken transport, or an abnormal
renderer exit. It should not be required for ordinary state changes.

Program `Send`, `Run`, `Quit`, and `Wait` remain behind the existing session
interface. No session or transport code should depend on concrete Bubble Tea
program internals.

Invitation copying returns `tea.SetClipboard(invite)`. Remove the custom
`CopyInviteCommand`, base64 OSC52 encoder, and direct writes to the program's
output stream. This keeps clipboard escape output serialized with Bubble Tea's
terminal I/O.

## Data flow

### Render

1. Runtime messages mutate `App` state.
2. `App.View` computes `Layout` and the active semantic style set.
3. The scene builder creates layers and semantic IDs.
4. Lip Gloss compositor draws layers to the fixed-size canvas.
5. The root `tea.View` declares content, terminal modes, cursor, keyboard
   enhancements, and mouse interception.
6. Bubble Tea downscales colors and renders the changed cells.

### Pointer input

1. Bubble Tea decodes a concrete mouse event.
2. `OnMouse` uses the compositor from the last rendered scene to resolve the
   topmost semantic target, unless pointer capture is active.
3. `Update` applies the target's action or forwards a terminal-relative event.
4. State changes produce a new scene and, when needed, a new capture target.

### Keyboard and paste input

1. Bubble Tea decodes enhanced key or paste events.
2. Input routing gives modal, prefix, chat, and terminal modes explicit
   precedence.
3. Chat messages update Bubbles textarea.
4. Terminal messages are encoded according to tracked embedded-terminal mode
   and emitted through the existing terminal input command.

## Failure handling

- Missing background responses leave the deterministic dark fallback intact.
- Unsupported keyboard enhancements fall back to traditional decoded events.
- Unsupported OSC52 leaves the clipboard unchanged without corrupting output.
- Unsupported PTY key combinations produce no bytes.
- Scene construction clamps invalid dimensions and omits empty optional layers.
- Unknown layer IDs are ignored, logged in diagnostic mode if appropriate, and
  never treated as terminal input.
- Modal activation cancels pointer capture.
- Renderer or session failure still reaches the idempotent terminal restore
  path exactly once.

## Migration sequence

The three major modules move together. Do not leave mixed v1 and v2 imports or
a production compatibility shim.

1. Add deterministic v2 key, mouse, paste, window-size, and color test helpers.
2. Update module paths and establish a compiling declarative `tea.View` shell.
3. Introduce per-app styles and background query handling.
4. Build the scene, canvas, layer, compositor, and semantic hit-target path.
5. Move top bar, terminal, sidebar, composer, and modals onto layers.
6. Switch the composer to Bubbles rendering and its real cursor.
7. Migrate key, paste, mouse, and pointer-capture routing.
8. Move terminal modes and clipboard handling to Bubble Tea v2.
9. Delete old frame composition, hit rectangles, adaptive globals, OSC52 code,
   obsolete commands, and superseded tests.
10. Run `go mod tidy` only after all old imports are gone.

Keep each intermediate implementation commit coherent and compilable where
practical, but treat the final migration as one atomic user-visible change.

## Testing

### Unit and component coverage

- Canvas cells, layer bounds, Z-order, and full styled-whitespace ownership.
- Semantic hits for top-bar actions, peers, divider, sidebar, terminal, modal
  blockers, and modal buttons.
- Pointer capture across press, motion, release, modal interruption, and resize.
- Catppuccin Latte and Mocha role colors without adaptive or global state.
- Wide glyphs, combining characters, emoji, ANSI styles, styled blanks,
  clipping, and one-cell terminal dimensions.
- Composer placeholder, insertion, deletion, navigation, wrap, scroll, focus,
  blur, and real-cursor coordinates.
- Key encoding across text, modifiers, international input, navigation,
  function keys, and application-cursor mode.
- Raw and bracketed paste in terminal, chat, modal, and prefix modes.
- Mouse event kinds, buttons, modifiers, terminal-relative coordinates, and SGR
  forwarding.
- Declarative view fields across normal, selection, invite, chat, and modal
  states.
- Background query response and fallback behavior.
- Native clipboard commands and removal of direct output writes.

Prefer semantic cell and scene assertions over enormous ANSI golden strings.
Use narrow golden fixtures for cases where exact renderer output is itself the
contract. Use Bubble Tea's `WithWindowSize` and `WithColorProfile` options for
deterministic integration tests.

### Lifecycle and smoke coverage

Add or retain PTY-level coverage for:

- alternate-screen entry and exit;
- mouse reporting enable and disable;
- outer and embedded bracketed-paste behavior;
- cursor visibility and restoration;
- normal quit, shell exit, cancellation, panic, guest disconnect, and transport
  close;
- resize and modal transitions without stale cells.

Verification gates:

```sh
mise exec -- go test ./pkg/derpssh/... -count=1
mise run check
mise run race
mise run build
mise run smoke-derpssh-local
mise run release:npm-dry-run
```

Run `REMOTE_HOST=<host> mise run smoke-remote-derpssh` when a configured test
host is available. The migration does not itself authorize a release.

## Acceptance criteria

- `go.mod`, `go.sum`, and `go list -m all` contain the target Charm versions and
  no v1 core modules.
- No source imports old Bubble Tea, Bubbles, or Lip Gloss module paths.
- No production source imports `lipgloss/compat` or uses global renderer,
  background, or color-profile setters.
- `FrameCanvas`, manual top-bar hit rectangles, custom OSC52 output, and
  imperative mouse-mode commands are removed.
- The root view is declarative and all visible regions are composed through Lip
  Gloss canvas, compositor, and layers.
- Chat uses Bubbles textarea rendering and a real Bubble Tea cursor.
- Shell input, terminal mouse forwarding, chat, dialogs, invitation handling,
  selection mode, resize, and terminal teardown retain their current behavior.
- Shells and rich terminal applications preserve wide glyphs, colors, styled
  blanks, cursor behavior, mouse input, function keys, and bracketed paste.
- Host and guest local smoke tests pass without leaked terminal modes or stale
  screen content.
- The complete repository check, race, build, local Derpssh smoke, and npm
  packaging dry run pass.
- Generated `dist/` contents are not hand-edited or committed.

## Release implications

This changes the compiled Derpssh dependency graph and terminal behavior but
does not change its protocol or package format. Validate npm assembly because
Derpssh ships as a vendored binary, but do not edit package template versions or
publish a release unless requested separately.
