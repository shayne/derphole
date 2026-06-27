# derpssh terminal sharing design

## Summary

`derpssh` is a new terminal-sharing product in this repository. It should ship as a sibling binary and npm package to `derphole` and `derptun`.

The target host workflow is:

```sh
npx -y derpssh@latest share
```

The host receives a copyable command for the other person:

```sh
npx -y derpssh@latest connect <invite>
```

The guest enters a simple display name. The host sees an incoming request in the TUI and can approve it as read-only or read/write. During the session, the host can promote, demote, or disconnect the guest. V1 supports one approved guest at a time and a fresh host-side PTY by default.

The design uses the existing derphole tunnel model: no open ports, DERP rendezvous, encrypted peer-to-peer data when a direct path is available, and relay fallback when it is not.

## Goals

- Provide terminal sharing with no inbound ports, no Tailscale account, and no external SSH daemon requirement.
- Keep the simple `npx -y derpssh@latest share` and `npx -y derpssh@latest connect ...` workflow.
- Reuse `derptun`'s token, claim, transport, QUIC, and mux concepts rather than creating a second tunnel stack.
- Run a fresh host-side shell in a PTY for v1.
- Respect the host terminal size. The host PTY size is canonical; guest windows adapt around it.
- Provide a shared TUI with a terminal pane, sidechat, live status, and permission controls.
- Enforce read-only/read-write on the host side, not only in guest UI.
- Package `derpssh` for npm with the existing vendored binary launcher pattern.

## Non-goals for v1

- Multiple simultaneous guests.
- Browser/web terminal UI.
- Existing `tmux` attach as the default path.
- Full tmux-compatible layout sync.
- Windows support.
- File transfer, clipboard sync, voice, persistent rooms, or recording export.
- Full terminal semantic state sync beyond bounded replay/snapshot support.

## Chosen approach

Use a native `derpssh` app protocol over shared derptun internals.

`derptun` already has the parts `derpssh` needs below the TCP forwarding layer:

- JSON server/client credentials with a signed client proof.
- DERP rendezvous and authenticated claims.
- Direct UDP probing and promotion, with relay fallback.
- QUIC carrier setup.
- A reconnectable mux with logical streams, ACKs, ping/pong, and carrier replacement.

`derpssh` should not wrap `derptun serve --tcp 127.0.0.1:22` or require SSH. That would make terminal approval, read/write gating, sidechat, and shared UI feel bolted on. Instead, `derpssh` should reuse the transport substrate and carry terminal-sharing messages over mux streams.

## Product behavior

### Host: `share`

`derpssh share` starts a TUI and creates a short-lived invite. It prints the guest command before or inside the TUI:

```sh
npx -y derpssh@latest connect <invite>
```

By default, `share` starts a fresh login-like shell in a local PTY. A future `--cmd` or `--tmux-session` option can reuse the same protocol, but v1 should not depend on tmux.

The host TUI has:

- a terminal pane showing the host PTY,
- a sidechat pane,
- a status line with transport state, host size, guest state, and guest role,
- an incoming-connection prompt,
- keyboard controls for approve read, approve write, deny, promote, demote, kick, and chat focus,
- mouse affordances where the terminal supports them.

Host input always goes to the PTY when terminal focus is active. Guest input goes to the PTY only while the host has granted write access.

### Guest: `connect`

`derpssh connect <invite>` starts a TUI and asks for a simple display name if one was not passed explicitly. The guest then waits in a pending state until the host approves or denies.

After approval:

- read-only guests receive terminal output, status, and chat,
- read/write guests can send terminal input,
- the UI clearly shows the current role,
- role changes are reflected immediately,
- kicked or disconnected guests see a clean terminal-state message instead of raw stream corruption.

The guest does not resize the host PTY. It renders the host terminal size as the canonical viewport. If the guest terminal is smaller or larger, the guest UI should fit, crop, scroll, or letterbox around the host dimensions without sending a host resize.

## Architecture

### Packages and commands

Add:

- `cmd/derpssh`
- `pkg/derpssh/protocol`
- `pkg/derpssh/session`
- `pkg/derpssh/pty`
- `pkg/derpssh/tui`

Expected responsibilities:

- `cmd/derpssh`: CLI parsing, help text, version command, display-name prompt, invocation of share/connect session runners.
- `pkg/derpssh/protocol`: message structs, stream kinds, versioning, encoding/decoding, validation, role and event types.
- `pkg/derpssh/session`: host and guest runtime orchestration over derptun-derived tunnel setup.
- `pkg/derpssh/pty`: PTY creation, shell spawning, winsize handling, byte copy, lifecycle cleanup.
- `pkg/derpssh/tui`: render model, input modes, terminal pane, sidechat, approval modal, permission controls.

Shared derptun internals may need small extraction work so `derpssh` can create an authenticated mux without pretending to serve TCP. Keep that extraction narrow and package-scoped around reusable tunnel primitives.

### Transport layer

The derpssh session flow should mirror derptun's claim lifecycle:

1. Host generates a server-side session credential and guest invite.
2. Guest decodes invite and sends an authenticated claim over DERP.
3. Host validates the claim and creates a pending join request.
4. Host approval produces an accepted decision with an initial role.
5. Both sides establish QUIC over the active derphole transport path.
6. Both sides wrap the QUIC carrier in `derptun.Mux`.
7. `derpssh` opens app-level streams over the mux.

V1 can keep the existing one-client derptun gate behavior. The design should not make multi-client impossible later: protocol messages should include participant IDs even if v1 has only one guest.

### Logical streams

Use separate mux streams for clear ownership and backpressure:

- `control`: hello, protocol version, display name, pending request, approve, deny, role change, kick, resize notice, ping/pong, close reason.
- `terminal-out`: host PTY output events with monotonically increasing sequence numbers.
- `terminal-in`: guest input events. Host consumes these only when the current guest role is read/write.
- `chat`: display-name chat messages, join/leave notices, and sanitized text.
- `snapshot` or control-embedded snapshot messages: bounded terminal replay state for reconnect and late initialization.

The exact stream encoding can start as length-prefixed JSON for control/chat and raw bytes with small binary headers for terminal streams. Avoid over-optimizing before the protocol is stable, but keep room for binary framing if JSON overhead becomes visible.

### Terminal event model

The host is the source of truth for terminal state.

Terminal output events include:

- sequence number,
- byte payload,
- host terminal size at or before the event when changed,
- timestamp or monotonic offset if useful for debug/replay.

The host keeps a bounded replay buffer. On guest reconnect, the host sends:

- protocol hello,
- current role,
- host dimensions,
- a snapshot/replay baseline,
- terminal output events after the baseline.

This follows the useful shape from asciinema's init-plus-events model and sshx's sequence/sync model, without requiring a full terminal emulator in v1. A later version can add a true VT snapshot if bounded byte replay is not enough.

### PTY handling

Use the `yeet` PTY path as the closest Go reference for edge cases:

- use `github.com/creack/pty` or equivalent to open the PTY on Unix,
- duplicate PTY fds where separate read/write ownership prevents shutdown deadlocks,
- set initial winsize before starting the shell interaction,
- apply host SIGWINCH changes to the PTY and broadcast the new host size,
- set `TERM` from the host environment, defaulting conservatively,
- run the shell with `Setsid`/`Setctty` where needed,
- treat EOF, EIO, broken pipe, closed websocket/QUIC stream, and closed network errors as normal shutdown paths,
- always restore local terminal raw mode before returning to the shell.

Use sshx and asciinema as additional references for PTY spawn/read/resize semantics. Do not copy code from GPL references into BSD-licensed files unless the project explicitly decides to accept the licensing consequences.

### TUI and input modes

The TUI should have explicit modes:

- terminal passthrough,
- chat focus,
- approval/permissions modal,
- status/help overlay if needed.

Terminal passthrough is the default. Chat and permission controls must be reachable by keyboard. Mouse support is useful but cannot be the only path for approval.

Fresh's design is useful here: render layout and hit targets from the same layout model, let modal overlays capture input before terminal forwarding, and avoid hardcoded rows. Terminal mouse input should only be forwarded when the terminal pane owns focus and the app is not handling a drag, modal, or sidechat action.

### Permission model

Roles:

- `pending`: connected but not approved.
- `read`: receives terminal and chat, cannot write to PTY.
- `write`: receives terminal and chat, can send input to PTY.
- `denied` or `kicked`: terminal state is closed with a user-facing reason.

Rules:

- The host always owns the session.
- Token possession never grants PTY write by itself.
- The host approval decision sets the first active role.
- Host-side input enforcement is required. Dropping or rejecting unauthorized guest input in the host runtime is the security boundary.
- Promotion/demotion/kick are live control messages.
- The guest UI should reflect role state, but UI state is not trusted.

### Sidechat

Sidechat is built into the app protocol, not a separate service. Display names are simple strings chosen at connect time or generated by default. The implementation should trim names, reject empty names, limit length, and strip terminal control characters.

Chat messages should be:

- associated with participant ID and display name,
- length-limited,
- sanitized before display,
- preserved in a bounded in-memory history for reconnect.

### Tokens and invites

There are two viable implementation details:

- Add a new derpssh-specific token type and compact invite.
- Extend derptun credentials with a capability/kind so the same machinery can validate derpssh sessions while preventing cross-use as generic TCP tunnels.

Prefer a derpssh-specific wrapper around derptun credential machinery. The CLI should expose only the simple invite command by default. Long-lived server/client token management can remain a derptun feature unless a later derpssh use case needs it.

The invite should be short-lived by default because it grants the ability to request access to a live terminal session. Approval still gates access, but expiry reduces accidental reuse.

### Packaging and release

Add `derpssh` as a third product anywhere the repo currently enumerates `derphole derptun`:

- `.mise.toml` build tasks,
- `tools/packaging/build-vendor.sh`,
- `tools/packaging/build-npm.sh`,
- `tools/packaging/build-release-assets.sh`,
- `.github/workflows/release.yml` matrices, artifact downloads, version checks, release asset lists, npm dry runs, npm publishing,
- `scripts/release-package-smoke.sh`,
- release workflow tests and package smoke tests.

Add:

- `packaging/npm/derpssh/package.json`,
- `packaging/npm/derpssh/bin/derpssh.js`,
- `cmd/derpssh/depaware.txt`.

The npm launcher should follow the existing `derptun` launcher pattern: platform/arch to vendored triple, spawn vendored binary with inherited stdio, forward signals, and return signal-compatible exit codes.

### Reference repo mapping

#### Old derpcat history

Use derpcat history for CLI/product shape:

- standalone `cmd/<product>` with yargs-style parsing,
- one-invite UX,
- npm package as a thin JS launcher around vendored Go binaries,
- release packaging patterns,
- specs for share/open and direct upgrade that evolved into current derphole/derptun concepts.

Do not resurrect derpcat directly. Use it as precedent for adding another product binary and npm package cleanly.

#### sshx

Use sshx for collaboration semantics:

- PTY session lifecycle,
- terminal data/input/size messages,
- sequence numbers and sync,
- write-permission flag,
- display names and presence,
- sidechat behavior,
- reconnect and latency concepts.

sshx is a web collaboration product, so derpssh should borrow the protocol ideas rather than the browser/canvas architecture for v1.

#### tmate

Use tmate for terminal-sharing control-plane ideas:

- separate read-only and read/write roles,
- join/leave and status messages,
- layout/snapshot/control message separation,
- reconnect behavior,
- host-visible client state.

Do not fork tmux or copy tmux/tmate internals for v1. Derpssh should provide its own small multiplexer-like TUI around one PTY first.

#### yeet

Use yeet as the Go PTY edge-case reference:

- PTY open and duplicated fd handling,
- initial winsize and live resize,
- terminal raw-mode setup and cleanup,
- session stdin proxy behavior,
- expected copy errors during normal shutdown,
- `Setctty`/`Setsid` shell process setup,
- preserving clean terminal output on exit.

#### asciinema

Use asciinema for event-stream shape:

- terminal output/input/resize/exit events,
- init event for late subscribers,
- bounded stream semantics,
- EOF/EIO handling around PTYs.

The local asciinema checkout is GPL. Treat it as a design reference unless the project intentionally decides to license copied code under GPL-compatible terms.

#### fresh

Use fresh for TUI interaction design:

- explicit input modes,
- terminal passthrough vs UI focus,
- modal capture before terminal forwarding,
- cached hit areas for mouse dispatch,
- side panel ergonomics,
- careful terminal mode setup and teardown.

The local fresh checkout is GPL-2.0. Treat it as a design reference unless the project intentionally decides to license copied code under GPL-compatible terms.

## Error handling

The user-facing rule is that transport and terminal failures should become clean session states.

Examples:

- guest denied: guest TUI shows denied reason and exits cleanly,
- guest kicked: guest TUI shows kicked reason and exits cleanly,
- host exits: guest sees host ended session,
- shell exits: both sides see shell exit code/status,
- direct path fails: telemetry shows fallback and the session continues over relay when possible,
- guest disconnects: host sees disconnected state and can keep the PTY running,
- reconnect fails because another guest is active: deterministic claimed-session message,
- terminal raw-mode setup fails: fall back or exit with a plain error before corrupting terminal state.

All cleanup paths must restore terminal mode, close PTY fds, close mux streams, and cancel transport goroutines.

## Testing plan

Unit tests:

- protocol encode/decode/version negotiation,
- role transitions and unauthorized input rejection,
- display-name and chat sanitization,
- bounded replay buffer behavior,
- PTY lifecycle helpers using fakes where possible,
- CLI parsing/help text for `share`, `connect`, and `version`.

Integration tests:

- local fake DERP share/connect handshake,
- pending request then read approval,
- pending request then write approval and guest input reaches PTY,
- demote blocks later guest input,
- kick closes guest cleanly,
- host size is broadcast and guest resize does not resize host PTY,
- reconnect receives replay/snapshot,
- one active guest gate rejects a contender deterministically.

Packaging tests:

- `mise run build` builds `dist/derpssh`,
- release smoke checks all derpssh vendor triples,
- npm dry run includes `dist/npm-derpssh`,
- packaged launcher runs `version`.

Manual smoke:

1. Run `npx -y derpssh@latest share`.
2. Run the printed connect command in a second terminal.
3. Approve read-only and verify guest cannot type into PTY.
4. Promote to write and verify guest input reaches PTY.
5. Use sidechat both directions.
6. Resize host and verify guest follows host dimensions.
7. Kick guest and verify clean exit.

Live remote smoke before declaring the implementation ready:

- Run the share/connect workflow with the share side on `root@hetz`.
- Run the share/connect workflow with the share side on `root@pve1`.
- In each live run, verify read-only approval, promotion to write, sidechat, host-size resize behavior, kick/clean exit, and transport telemetry.
- If the implementation is not yet published to npm, stage the built `derpssh` binary on the remote host and use the same command shape the npm launcher will run.

## Open implementation choices

These should be decided during implementation planning, not in this design:

- exact protocol framing format for terminal streams,
- initial TUI library choice,
- whether the first replay buffer is byte-only or includes a small VT state snapshot,
- exact default invite lifetime,
- exact keyboard shortcuts.

The constraints above should hold regardless of those choices.
