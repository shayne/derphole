# derpssh scrollback and terminal selection design

## Summary

derpssh should provide terminal-local scrollback and mouse selection inside its
terminal pane. Users should be able to scroll through retained output, drag to
select text across visible and historical rows, and copy the selection without
temporarily releasing the entire outer terminal to native selection mode.

The implementation will replace the current `github.com/hinshun/vt10x`
emulator with `github.com/charmbracelet/x/vt`. The new emulator already exposes
a retained main-screen scrollback buffer, grapheme-aware cells, alternate-screen
state, cursor state, and terminal-mode callbacks. derpssh will add the viewport
and gesture policy around that emulator, following herdr's user-facing
selection and scrolling semantics while keeping the implementation Go-native.

## Evidence and current limitations

The current `vtTerminalSurface` wraps `vt10x.Terminal`. It renders only the
active grid and implements `Scroll(int)` as a no-op. The TUI's "Native
Selection" mode disables Bubble Tea mouse reporting so the user's outer
terminal emulator can select the currently rendered frame. That workaround
cannot access output that has already left the active grid, cannot scroll a
derpssh-owned buffer, and temporarily disables derpssh mouse interaction.

herdr solves the same product problem by keeping viewport-relative positions
mapped to retained screen-buffer rows. Mouse drag updates a terminal-owned
selection, wheel input scrolls retained rows when the embedded application does
not own the mouse, and finishing a selection copies it by default. Mouse-aware
applications retain their own mouse input.

Charm's `x/vt` added scrollback support in 2026 and defaults to 10,000 retained
main-screen lines. The selected module revision is
`github.com/charmbracelet/x/vt v0.0.0-20260803091719-3755ebad01b1`. It uses the
same Charm and Ultraviolet ecosystem already present in derpssh and requires a
lower Go version than this repository's declared toolchain.

Primary references:

- <https://github.com/herdrdev/herdr/blob/ddffb6e1d79efb517a92034ed18b75c388a36e55/src/selection.rs>
- <https://github.com/herdrdev/herdr/blob/ddffb6e1d79efb517a92034ed18b75c388a36e55/src/app/input/selection.rs>
- <https://github.com/herdrdev/herdr/blob/ddffb6e1d79efb517a92034ed18b75c388a36e55/src/app/input/mouse.rs>
- <https://github.com/charmbracelet/x/tree/3755ebad01b1366a9eeb5e4e80d664b404ab6eff/vt>

## Goals

- Retain up to 10,000 lines of normal-screen terminal output.
- Scroll retained output with the mouse wheel and appropriate page keys.
- Preserve the viewed content when new output arrives while the user is
  scrolled away from the live bottom.
- Select text by dragging across terminal cells and copy it automatically on
  release.
- Select and copy a word by double-clicking it.
- Allow a selection gesture to cross viewport boundaries through wheel and
  edge autoscroll.
- Keep selection coordinates attached to retained terminal rows while the
  viewport moves.
- Preserve mouse behavior in Vim, htop, and other mouse-aware applications.
- Turn `Ctrl-X Y` into a forced local-selection override when an embedded
  application owns the mouse.
- Preserve current terminal styling, cursor, resize, alternate-screen,
  clipboard, teardown, and session behavior.

## Non-goals

- Porting herdr's Rust code or vendored `libghostty-vt` bindings directly.
- Adding keyboard copy mode, search, rectangular selection, hyperlinks, a
  visible scrollbar, or configurable scrollback limits.
- Changing the derpssh protocol, replay buffer, PTY ownership, canonical resize
  rules, or sidechat behavior.
- Reflowing historical rows after a terminal-width change.
- Publishing or releasing derpssh as part of this feature.

## Considered approaches

### Replace `vt10x` with Charm `x/vt` and add derpssh viewport policy

This is the chosen approach. It gives derpssh a maintained Go-native emulator
with scrollback and richer cell semantics while keeping the existing
`TerminalSurface` boundary. It also aligns the emulator with the Charm stack
already used by the outer TUI.

The principal risk is an emulator behavior change. Existing ANSI, Vim,
cursor, style, resize, and mouse fixtures must therefore run against the new
surface before the old dependency is removed.

### Fork or vendor `vt10x`

Adding history to `vt10x` would require modifying its private scrolling and
screen internals. derpssh would then own a terminal-emulator fork and its VT
correctness. This is more maintenance for a less capable result.

### Bind herdr's `libghostty-vt`

This would provide the closest implementation parity with herdr, but it would
introduce CGo/Zig build requirements and significant cross-compilation and npm
packaging work. That cost is disproportionate for the requested behavior and
would make derpssh's release matrix materially more fragile.

## Architecture

### Emulator adapter

`vtTerminalSurface` remains the synchronization boundary for terminal state,
but its emulator becomes `x/vt.Emulator`. The surface continues to serialize
writes, resizes, viewport changes, selection changes, and cell snapshots with
one mutex rather than relying on pointers returned from the emulator after an
internal lock has been released.

The adapter will use `x/vt` callbacks to track cursor visibility and private
terminal modes. Mouse-reporting modes, SGR mouse encoding, application-cursor
mode, bracketed paste, alternate scroll, and alternate-screen state remain
available through the existing derpssh-facing mode types. Split escape
sequences are handled by the emulator parser rather than by concatenating a
custom mode tail.

`x/vt` can generate terminal responses for device and color queries through an
internal input pipe. The current derpssh architecture does not route emulated
client responses back to the shared PTY, and changing that ownership is outside
this feature. Each surface will therefore drain and discard that pipe for its
lifetime so a device query cannot block terminal output. The concrete pane will
implement `io.Closer`; console shutdown will close panes that support it. Test
surfaces will be explicitly closed where they exercise the real emulator.

### Cell and rendering model

`terminalCell` changes from a single rune plus `vt10x` attributes to a
grapheme string, display width, and Ultraviolet style. Rendering will skip
zero-width continuation cells, preserve styled blank cells, and emit the new
style's ANSI representation. The existing rule that suppresses underline-only
blank cells remains in place.

The visible cursor is rendered only at the live bottom. Scrolling into history
hides it. Selection highlighting inverts the selected cell's effective style
without discarding its foreground, background, underline, or other attributes.

### Viewport

The surface stores `offsetFromBottom`, measured in rows. Zero means the active
screen bottom; positive values select older rows from the combined main-screen
scrollback and live grid. `ScrollLines(delta)` clamps the offset between zero
and the current scrollback length. Positive deltas move toward older output and
negative deltas move toward the live bottom.

When the primary screen appends scrollback while `offsetFromBottom` is
positive, the surface increases the offset by the observed scrollback growth
so the same content remains visible. At the 10,000-line hard limit, eviction of
the oldest rows may require clamping the view; an in-progress selection whose
referenced rows were evicted is canceled rather than copied incorrectly.

The alternate screen has no host scrollback. Entering it resets the local
viewport to zero. Leaving it returns to the live bottom of the primary screen.
A resize clamps the viewport and clears any active selection because `x/vt`
does not reflow retained history.

### Selection model

A `terminalSelection` stores an anchor and cursor as `(row, column)` positions
in the combined retained buffer, plus one of three phases:

- `anchored`: the left button is down but has not moved to another cell;
- `dragging`: the range is visible and follows pointer movement;
- `done`: used briefly for word-selection feedback before it is cleared.

The surface converts pointer coordinates into combined-buffer rows using the
current viewport. Ordered selection bounds are derived only for rendering and
text extraction, so reverse-direction dragging remains correct.

Dragging clamps columns and rows to the terminal rectangle. Moving above or
below the pane starts a short Bubble Tea autoscroll tick. Each tick scrolls
between three and fifteen rows based on pointer distance, then recomputes the
selection endpoint against the new viewport. Returning to the pane, releasing
the button, opening a modal, resizing, or leaving forced-selection mode cancels
the tick. Wheel events during an active drag scroll locally and update the
endpoint.

Selection extraction walks cells in reading order, skips wide-character
continuation cells, trims unselected trailing blanks on each selected display
row, and joins selected display rows with newlines. Empty selections do not
write the clipboard.

### Mouse routing

Mouse routing keeps the current modal, header, sidebar, composer, divider, and
terminal target priority. Terminal behavior becomes:

1. If forced-selection mode is active, left-button and wheel events are always
   handled locally.
2. Otherwise, a supported SGR mouse-reporting mode forwards terminal clicks,
   releases, motion, and wheel input to the embedded application and resets the
   local viewport to the live bottom.
3. Without supported mouse reporting, a left press anchors a local selection,
   motion extends it, release finishes it, and wheel input scrolls locally.
4. In an alternate-screen application with alternate-scroll mode enabled but
   no mouse reporting, wheel input becomes repeated application-cursor up/down
   input instead of host scrollback.

Starting a local selection captures the pointer as a terminal gesture so drag
motion and release remain ordered even when the pointer crosses the top bar or
sidebar. A plain click that never leaves its anchor only focuses the terminal
and does not copy an empty selection.

The existing `Ctrl-X Y` action keeps its shortcut but changes from outer native
selection to forced local selection. Bubble Tea cell-motion reporting remains
enabled in this mode; derpssh consumes terminal gestures instead of forwarding
them. `Esc`, `Ctrl-X Y`, or a click on nonterminal chrome exits the mode and
clears any unfinished gesture.

### Double-click and clipboard behavior

derpssh records the last unmodified terminal click position and time. A second
click on the same terminal cell within 500 milliseconds selects the contiguous
word under that cell. Word characters are Unicode letters and numbers plus
underscore; punctuation and whitespace delimit words.

A completed drag or word selection uses `tea.SetClipboard`, matching the
existing invite-copy path. Drag highlighting is visible while the gesture is
active and clears after the copy command is created. A double-clicked word
remains highlighted for 500 milliseconds as copy feedback, matching herdr's
short-lived word highlight.

Clipboard command failures remain Bubble Tea lifecycle concerns. derpssh does
not retry, shell out to platform clipboard programs, or write OSC 52 directly.

### Keyboard scrolling and live-bottom reset

Mouse wheel movement uses three rows per notch. On the primary screen, plain
Page Up and Page Down scroll by one terminal viewport when the embedded program
is shell-like: mouse reporting is disabled and the current application-cursor
and bracketed-paste combination does not indicate a full-screen application.
Modified page keys continue to reach the embedded terminal.

Any terminal key or paste that is forwarded to the PTY resets the viewport to
the live bottom and clears temporary selection feedback. Chrome, chat, and
modal input do not change the terminal viewport.

## Interfaces and file boundaries

- `pkg/derpssh/tui/terminal_surface.go` owns the `x/vt` adapter, viewport row
  mapping, synchronized snapshots, cursor visibility, and terminal response
  draining.
- `pkg/derpssh/tui/terminal_selection.go` owns selection positions, phases,
  containment, word bounds, and text extraction helpers.
- `pkg/derpssh/tui/terminal.go` owns pane-level rendering and the optional
  interactive terminal capability used by `App`.
- `pkg/derpssh/tui/mouse.go` owns gesture routing, pointer capture, double-click
  detection, wheel behavior, and selection autoscroll commands.
- `pkg/derpssh/tui/input_router.go` resets the viewport before forwarding
  terminal keys and paste, and intercepts eligible page keys.
- `pkg/derpssh/tui/app.go` stores only app-level gesture timing and autoscroll
  state; terminal content and selection cells remain inside the pane boundary.
- `pkg/derpssh/session/console.go` closes a concrete terminal pane during
  shutdown when it implements `io.Closer`.

The existing public `TerminalPane` interface remains source-compatible for
test and custom panes. derpssh detects a private interactive capability
implemented by `vtTerminalPane`; panes without that capability retain current
focus and forwarding behavior but do not expose local scrollback or selection.

## Error handling and safety

- All emulator and viewport access is serialized by the terminal surface.
- Invalid dimensions, cells, offsets, and pointer coordinates clamp safely.
- Scroll and selection methods on nil or noninteractive panes are no-ops.
- Empty or evicted selections never write clipboard content.
- Unsupported mouse encodings fall back to local selection rather than
  emitting malformed PTY input.
- Generated emulator responses are drained so query sequences cannot deadlock
  rendering.
- Pane close is idempotent and terminates the response-drain goroutine.
- Existing modal capture and terminal restoration continue to take priority
  over selection gestures.

## Testing strategy

Implementation follows test-driven development. Each behavior is first added
as a focused failing test, then implemented minimally.

### Emulator and viewport tests

- output beyond the screen enters the 10,000-line retained buffer;
- wheel offsets clamp at the oldest row and live bottom;
- the visible viewport reads the correct mixture of history and live rows;
- new output preserves the viewed content while scrolled;
- cursor rendering disappears in history and returns at the live bottom;
- alternate-screen entry and exit reset host scrolling;
- resize clamps the viewport and clears selection safely;
- device-query output cannot block a surface write;
- pane close terminates response draining;
- split private-mode sequences update mouse, cursor, paste, and application
  modes correctly.

### Selection tests

- a click without movement copies nothing;
- forward and reverse drags produce the same ordered text;
- multiline selections trim only unselected trailing blanks;
- wide and combining graphemes copy once and render without broken columns;
- scrolling during a drag keeps the anchor attached to retained content;
- edge autoscroll advances and stops at the correct lifecycle boundaries;
- double-click selects a Unicode word and excludes punctuation;
- completing a drag produces a Bubble Tea clipboard command;
- empty and evicted ranges do not produce clipboard commands.

### Routing and regression tests

- ordinary shell clicks select locally and wheel input scrolls locally;
- SGR mouse-aware programs receive their mouse sequences unchanged;
- forced-selection mode overrides SGR mouse forwarding;
- alternate-scroll wheel input reaches alternate-screen applications;
- eligible Page Up and Page Down scroll locally while modified keys forward;
- terminal keys and paste reset the viewport to the live bottom;
- modals, chat, header actions, and divider dragging retain priority;
- existing ANSI style, styled-space, underline-only blank, cursor, Vim
  alternate-screen, resize, and mouse fixtures pass against `x/vt`.

Focused verification is `go test ./pkg/derpssh/tui ./pkg/derpssh/session`,
followed by the repository's build-only `mise run check:fast`. The exhaustive
`mise run check` remains required only immediately before an explicitly
requested push or direct landing to `main`.

## Dependency and release impact

`github.com/hinshun/vt10x` is removed after all compatibility fixtures pass.
`github.com/charmbracelet/x/vt` becomes a direct dependency at the revision
listed above. Its Ultraviolet and `x/ansi` requirements are resolved through Go
module version selection against the versions already used by derpssh.

The change affects all derpssh binary targets but does not alter package
templates, wire compatibility, npm launcher behavior, or semantic versioning
metadata. No generated `dist/` content is edited.
