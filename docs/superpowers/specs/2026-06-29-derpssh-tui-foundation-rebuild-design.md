# derpssh TUI foundation rebuild design

## Summary

derpssh should feel like a small, reliable terminal multiplexer: a shared PTY
with modern chrome, clickable controls, keyboard shortcuts, chat, permission
management, and deterministic teardown. The current implementation has reached
the point where the visible bugs are not isolated polish issues. They point to
the same structural problem: terminal lifecycle, terminal emulation, rendering,
input routing, overlays, chat, and session state are too tightly coupled.

The next pass should be a foundation rebuild. The goal is not to patch each
symptom one by one. The goal is to establish durable internal boundaries, then
rebuild the UI and terminal path on those boundaries so future fixes are local,
testable, and predictable.

## Current Failure Classes

The user-visible issues cluster into these root causes:

1. Terminal lifecycle is not owned by one component.
   Startup, raw mode, bracketed paste, mouse tracking, alternate screen,
   cursor visibility, terminal reset, program quit, and final shell restore can
   be changed by multiple paths. This causes leaked sequences such as
   `0;46;17m` or `^[[<...m`, blank screens, stuck commands, and terminals that
   need `reset` after derpssh exits.

2. Terminal emulation and rendering are not separated enough.
   Rich TUI programs such as Vim and htop expose rendering bugs, cursor bugs,
   resize panics, underline/background artifacts, and control-key pass-through
   problems. Fixing a visual artifact in a single style case is not enough if
   the emulator, renderer, and chrome compositor are sharing assumptions.

3. Overlays are not true overlays.
   Dialogs, menus, and resize warnings currently paint through or leave holes
   where cells have no text. Modal backgrounds, button rows, and chat panels
   need full cell ownership so foreground text and blank cells share the same
   intended background.

4. Input routing is too implicit.
   When the terminal is focused, everything except the derpssh prefix should go
   to the PTY. `Ctrl-R`, arrows, function keys, Vim, htop, shell editing, and
   mouse sequences must not be accidentally captured by derpssh chrome. When
   chat, select mode, a dialog, or the menu is focused, routing must be explicit
   and reversible.

5. Session state is being rendered from stale or duplicated events.
   Header chips can show disconnected peers, duplicate reconnects, or stale
   permissions. Host and guest can disagree about the effective shared terminal
   size, especially when chat opens, closes, or resizes.

6. Chat is not yet a competent chat surface.
   Chat needs correct focus, click behavior, placeholder rendering, block
   cursor placement, wrapping, auto-scroll, scrollback behavior, IRC-like
   messages, a composer that grows from one to three lines, and predictable
   overlay behavior without corrupting terminal size.

7. Copyability is being traded away for chrome.
   The initial invite screen must remain plain terminal output, selectable in a
   remote SSH session, and copyable without relying on a local clipboard. In-app
   invite views are useful, but they cannot replace the plain interstitial.

## Design Goals

- Provide a true shared-terminal experience with host-authoritative PTY size.
- Preserve rich TUI behavior for shells, htop, Vim, readline, mouse-aware apps,
  alternate-screen apps, and color-heavy programs.
- Make teardown deterministic for host quit, guest quit, shell EOF, denial,
  kick, transport close, and process crash.
- Use one visual system for top bar, menu, dialogs, resize warnings, chat, and
  placeholders.
- Make every visible action reachable by both keyboard and mouse where the
  terminal allows it.
- Keep the first invite screen plain, text selectable, and reliable over SSH.
- Build regression tests around the actual failure classes before and during
  implementation.

## Non-Goals

- Replacing derptun or changing the derphole transport model.
- Adding a web client.
- Optimizing for multiple guests beyond the state model needed to avoid stale
  duplicate peer chips.
- Publishing a release during implementation. Smoke tests should use
  `derpssh@dev` until the user asks for a semver release.
- Continuing ad hoc visual patches without moving the core boundaries first.

## Reference Repos

### ~/code/crush

Crush is the strongest reference for Charm-style structure:

- Treat actions as semantic commands, not scattered key handlers.
- Keep keybindings, menu items, and clickable affordances backed by one action
  registry.
- Use an overlay/modal stack that owns its input and rendering.
- Route mouse and key events through explicit focus and dialog state.
- Fill all modal and panel cells with explicit styles, including whitespace.
- Let Bubble Tea program lifecycle return normally instead of exiting from
  arbitrary call sites.

We should borrow the architectural patterns, not copy application-specific UI.

### ~/code/ghostty

Ghostty is the reference for terminal correctness:

- Terminal emulation and rendering should be treated as a protocol boundary,
  not as ordinary string formatting.
- Cursor state, mouse mode, alternate screen, scrollback, and SGR attributes
  are part of terminal state.
- Reset/restore behavior must be explicit and ordered.
- Conformance should be tested with real escape-sequence fixtures.

We should not copy a full terminal emulator wholesale as the first move, but
the derpssh terminal path must be designed so an emulator swap or deeper
conformance layer can happen behind a stable `TerminalSurface` seam.

### ~/code/fresh

Fresh remains the visual and interaction reference for clean TUI structure:

- Thin dividers and resize affordances.
- Click and drag behavior that feels intentional rather than heavy.
- Menus and dialogs with clear hierarchy and minimal labels.
- Mouse handling that complements keyboard shortcuts.

### sshx, tmate, asciinema, yeet

- sshx and tmate remain references for terminal sharing session semantics.
- asciinema is useful for terminal stream recording and replay concepts.
- yeet remains useful for careful PTY handling and remote smoke discipline.

## Proposed Architecture

### TerminalLifecycle

Create one owner for terminal process and terminal host state.

Responsibilities:

- Enter and leave raw mode.
- Enable and disable bracketed paste, mouse modes, cursor visibility, and
  alternate screen behavior.
- Own Bubble Tea program startup and shutdown boundaries.
- Restore terminal state exactly once on every exit path.
- Return from `Program.Run` normally where possible.
- Avoid `os.Exit` from UI/session internals.
- Emit a final user-readable reason on clean remote termination, such as
  `derpssh: session ended: host quit`, `derpssh: kicked by host`, or
  `derpssh: shell exited`.

Acceptance criteria:

- Host quit restores the terminal with no leaked SGR or mouse escape text.
- Guest quit restores the terminal with no leaked escape text.
- Shell EOF shows restart/quit on host and a clear stopped reason to guests.
- Ctrl-C, Ctrl-D, red X, menu quit, transport close, denial, kick, and panic
  recovery all pass through the same restore path.
- Restore is idempotent and tested.

### TerminalSurface

Create a stable boundary around terminal emulation and screen state.

Responsibilities:

- Accept PTY output bytes.
- Maintain terminal grid, cursor, alternate-screen, scrollback, mouse mode, and
  active style state.
- Expose a safe read API that clamps row and column access.
- Render the current visible grid without panics during resize.
- Preserve background-styled blank cells when they are semantically meaningful.
- Avoid drawing underline-only blank cells as visible horizontal rules unless
  the terminal state truly calls for that cell to be visible.

The first implementation may wrap the current vt10x path, but the interface
must allow replacing it if conformance testing shows it is not reliable enough.

Acceptance criteria:

- No index-out-of-range panics when host and guest dimensions differ.
- Vim no longer shows spurious horizontal lines.
- htop colors, arrows, mouse, and function keys work.
- Readline `Ctrl-R` reaches the shell when terminal is focused.
- Alternate-screen apps leave terminal state correctly.
- Mouse tracking is enabled only when needed and disabled on exit or selection
  mode.

### Frame and Compositor

Create a compositor that combines the terminal surface, top bar, chat panel,
menus, and overlays from rectangular layers.

Responsibilities:

- Fill every cell in each owned rectangle, including whitespace.
- Keep the shell itself visually untouched except for clipping to the terminal
  viewport.
- Render a single top bar, no bottom status bar.
- Support a compact powerline-inspired header.
- Ensure modal overlays float above terminal and chat without cutting through
  either one.
- Repaint terminal regions after chat open, close, resize, or dialog dismissal.

Acceptance criteria:

- Dialogs have no white or blank holes in light or dark mode.
- Button rows fill with dialog background across the full width.
- Chat border is thin, not a thick multi-cell block.
- Closing chat fully restores terminal contents.
- Menu and dialogs look consistent with Catppuccin Latte and Mocha.

### Theme System

Use Catppuccin Latte for light mode and Catppuccin Mocha for dark mode, but
never use palette colors directly at call sites.

Create semantic roles:

- `ChromeBase`
- `ChromeMuted`
- `ChromeActive`
- `ChromeDanger`
- `ChromeNotice`
- `DialogBase`
- `DialogBorder`
- `DialogText`
- `DialogMuted`
- `ButtonDefault`
- `ButtonFocused`
- `ButtonDanger`
- `ChatBase`
- `ChatHeader`
- `ChatMessageUser`
- `ChatMessageSelf`
- `ChatPlaceholder`
- `ComposerBase`
- `ComposerCursor`
- `SelectionMode`

Acceptance criteria:

- Light mode remains readable and restrained.
- Dialogs are not hot pink or garish.
- Low-contrast top-bar text is eliminated.
- Placeholder text has the composer background and muted foreground.
- Focused empty composer cursor starts at the beginning of the placeholder and
  still makes the placeholder understandable.

### ActionRegistry

Create one source of truth for commands.

Examples:

- Quit
- Toggle chat
- Focus chat
- Focus terminal
- Toggle native/select mode
- Show menu
- Show invite
- Grant read
- Grant write
- Deny guest
- Kick peer
- Change peer permission
- Restart shell

Each action defines:

- id
- label
- optional shortcut
- visibility predicate
- enabled predicate
- handler
- optional mouse/click target

Acceptance criteria:

- Guest shortcut overlay does not show host-only invite actions.
- Header menu contains clickable entries with shortcuts on the right.
- Header peer chip can be clicked by the host to show read/write/kick actions.
- Keyboard shortcuts and menu entries call the same handlers.

### InputRouter

Route every input event through one explicit router.

Priority order:

1. Terminal lifecycle shutdown state.
2. Active modal or overlay.
3. Prefix sequence state.
4. Select/native-selection mode.
5. Chat composer focus.
6. Terminal focus.

Rules:

- Terminal focus passes all keys and mouse events to the PTY except the
  derpssh prefix.
- Prefix mode is visible in the top bar and exits reliably.
- Select mode is obvious, easy to exit, and can be exited by clicking out,
  pressing Esc, or using the prefix shortcut.
- Dialogs and menus consume only the input they own.
- Chat focus sends text to the composer and Enter sends the message.

Acceptance criteria:

- `Ctrl-R` shell history search works.
- Arrow keys work in htop and shell prompts.
- Clicking Chat opens chat and focuses the composer.
- Clicking the terminal returns focus to the terminal.
- Select mode never traps the user without visible feedback.

### ChatPane

Chat should be a polished IRC-like overlay panel.

Responsibilities:

- Open as an overlay/panel without corrupting terminal state.
- Keep host terminal dimensions canonical.
- On guest, opening chat should not create a false host-size requirement if it
  can be rendered as an overlay.
- Wrap messages to the panel width.
- Auto-scroll when the user is at the bottom.
- Preserve scrollback when the user has intentionally scrolled up.
- Show unread notification in the header when chat is hidden.
- Use compact display names: username when unique, `user@host` when needed,
  and shortened host portions when long.
- Composer grows from one to three lines, showing all visible lines before
  scrolling older composer text out of view.
- Placeholder and cursor render correctly in light and dark themes.

Acceptance criteria:

- No duplicate local chat messages.
- No `root` and `hetz` split messages for `root@hetz`.
- Long messages wrap.
- Composer line 1, 2, and 3 are all visible before scrolling begins.
- Empty focused composer shows a clear block cursor at the start.

### Session State Adapter

Normalize host, guest, permission, transport, size, and shell state before UI
rendering.

Responsibilities:

- Maintain active peers by stable connection id.
- Remove disconnected peers.
- De-duplicate reconnects.
- Surface pending approval state to both host and guest.
- Keep host terminal size authoritative.
- Broadcast size changes when the host resizes or when host chrome changes the
  terminal viewport.
- Represent transport as direct or relayed in the header.
- Represent shell state as running, exited, restarting, or closed.

Acceptance criteria:

- Guest waiting for approval sees a modal, not a blank screen.
- Host sees approval modal even if guest connects before host presses Enter on
  the initial invite interstitial.
- Guest header and host header agree on canonical terminal size.
- Guest gets a persistent resize warning only when the shared terminal truly
  cannot fit.
- Guest quit notifies host and removes peer info.
- Host quit immediately terminates guests with a reason.

### Invite Flow

The first host screen is intentionally plain terminal output, not an alternate
screen TUI.

Rules:

- Print the full command as one logical line so terminal-native wrapping keeps
  manual copying possible.
- Do not rely on clipboard APIs for the primary path.
- Do not enter full TUI mode until the host presses Enter or a guest connects.
- If a guest connects while the host is on the invite screen, transition the
  host into the TUI and show the approval modal.
- If the host quits while a guest is connecting, terminate the guest cleanly
  with a reason.
- In-app invite display can exist behind the menu for host only, but it must
  not compromise the plain initial flow.

Acceptance criteria:

- Manual selection from an SSH session copies a usable connect command.
- Triple-click or drag selection does not require editing embedded newlines
  when the terminal supports logical-line wrapping.
- The host can quit from the initial screen and the command returns to shell.

## Testing Strategy

### Unit Tests

- `TerminalLifecycle` restore order and idempotence.
- Input routing for terminal, prefix, chat, menu, dialogs, and select mode.
- Action registry visibility for host and guest.
- Session state peer de-duplication and disconnection.
- Chat composer wrapping and one-to-three-line growth.
- Theme role contrast sanity for Latte and Mocha.

### Rendering Tests

Use golden tests for:

- Header in light and dark mode.
- Menus and dialogs with full background fill.
- Approval dialog.
- Shell-exited dialog.
- Resize warning overlay.
- Chat hidden, open, focused, unfocused, and unread states.
- Empty focused composer placeholder and cursor.

### Terminal Conformance Tests

Build a fixture set around:

- Vim-style alternate-screen rendering.
- htop-style color, function keys, mouse, and arrows.
- Readline `Ctrl-R`.
- Mouse tracking enable/disable sequences.
- Bracketed paste.
- Cursor visibility.
- SGR reset and background handling.
- Resize during dialog and chat open.

The tests should verify both state and rendered output where practical.

### Live Smoke Tests

Before claiming the rebuild is ready:

- Run local package tests and smoke tests through `mise`.
- Smoke test `derpssh@dev` without publishing.
- Live test from `root@hetz`.
- Live test from `root@pve1`.
- Cover share/connect/approval/read/write/chat/quit/kick/shell-exit/restart.
- Verify host and guest terminal restoration after every exit path.

## Migration Plan

1. Create the new internal interfaces with the existing behavior still wired
   through them.
2. Move lifecycle ownership into `TerminalLifecycle`.
3. Replace scattered key/mouse handling with `InputRouter` and
   `ActionRegistry`.
4. Replace direct string composition of chrome with `Frame` and `Compositor`.
5. Move all colors to semantic theme roles.
6. Rebuild dialogs, menus, and chat on the overlay stack.
7. Move peer, permission, transport, size, and shell state behind the session
   adapter.
8. Harden `TerminalSurface` with safe access and fixture tests.
9. Decide whether vt10x can remain behind the seam or whether a replacement is
   needed for correctness.
10. Run full local and live smoke verification.

## Risks

- Terminal emulation correctness can grow quickly. The seam must prevent this
  from spreading into UI code.
- Clipboard and native selection behavior differ by terminal emulator and SSH
  path. The design must treat plain terminal copyability as the reliable
  baseline.
- Bubble Tea lifecycle shortcuts can make `os.Exit` tempting. The design must
  keep shutdown centralized and testable.
- Chat overlay sizing can accidentally change the shared terminal viewport.
  Host-size authority must be explicit and tested.

## Open Decisions

1. Whether to keep vt10x after the first conformance pass or replace it behind
   `TerminalSurface`.
2. Whether guest chat should always be an overlay independent of shared
   terminal size, or whether some small-terminal cases still need a persistent
   resize warning.
3. How much terminal scrollback derpssh should own versus delegating to native
   terminal selection and scrollback.
4. Whether invite display inside the app should offer a local clipboard action
   in addition to the plain manual-copy path.

## Definition of Done

The rebuild is done when the following are true:

- The old failure classes have dedicated tests or live smoke checks.
- Terminal restore is clean for host and guest after quit, kick, denial,
  transport close, and shell EOF.
- Vim, htop, readline, and shell editing behave correctly in live testing.
- Host and guest agree on canonical terminal size across resize and chat
  changes.
- The initial invite command is manually copyable over SSH.
- Chat is polished, focusable, clickable, wrapping, auto-scrolling, and usable
  in light and dark mode.
- Menus, dialogs, and top bar use the same semantic Catppuccin-based theme.
- Peer permission changes are available from the clickable header peer chip.
- `derpssh@dev` passes local and live smoke tests on both `root@hetz` and
  `root@pve1`.
