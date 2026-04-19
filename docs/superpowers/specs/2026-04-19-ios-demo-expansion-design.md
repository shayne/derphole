# iOS Demo Expansion Design

## Purpose

Derphole should grow from a proof-of-concept file receiver into a native iOS demo for three related workflows: file receive, web tunnel browsing, and SSH over a TCP tunnel. The app should feel Apple-native, minimal, and focused. The transport and tunnel behavior should stay in Go so mobile uses the same direct-preferred paths as the CLI, while Swift owns presentation, local persistence, camera scanning, browser chrome, and terminal UI.

The first implementation milestone should make Files and Web functional and polished. SSH should be designed, routed in the UI, and given stable bridge boundaries, but the working terminal can land after Files and Web are stable.

## Current State

The repository has a SwiftUI app under `apple/Derphole`. It currently supports the file-receive proof of concept through `pkg/derpholemobile`, a gomobile-generated `DerpholeMobile.xcframework`, and `TransferState`. The app can receive a CLI file payload, reports relay versus direct status, and has a repeatable physical-device transfer task.

The current app is still organized around one receive screen. It embeds the camera scanner in the main UI and always shows manual payload controls. That is useful for early automation but is not the right product shape for a real device demo.

The Go mobile bridge currently exposes file receive only. It calls `pkg/derphole.Receive`, which reuses the normal session receive path and direct-preferred transport behavior.

`derptun` already has reusable Go session code for serving TCP targets, opening a local listener, and connecting one stream over stdio. The CLI is oriented around `derptun serve`, `derptun open`, and `derptun connect`. The mobile app needs a bridge to `session.DerptunOpen`, not a Swift reimplementation of the tunnel.

`/Users/shayne/code/vvterm` provides the terminal reference. The useful pieces for this app are the iOS `GhosttyTerminalView` custom I/O mode, the libssh2-based SSH client/session code, and the SwiftUI wrapper pattern that connects terminal input/output to an SSH shell. The Derphole app should not copy vvterm's server manager, CloudKit sync, multi-workspace UI, SFTP, Mosh, tmux, store, or advanced settings for the first SSH milestone.

## Goals

- Replace the single receive screen with a three-tab app: Files, Web, and SSH.
- Keep physical-device Files UI minimal: one `Scan QR Code` entry point and state-driven transfer surfaces.
- Move camera scanning into a modal scanner sheet or full-screen cover.
- Hide manual payload/debug controls unless a test/debug launch flag enables them.
- Show clear transfer stages and a HIG-style progress UI with MiB/s.
- Show at-a-glance connection path information, especially relay versus direct.
- Add `Save File` and `Discard` completion actions for file receive.
- Add intent-aware QR payloads for file, web tunnel, and generic TCP tunnel.
- Add `derptun serve --tcp <target> --qr` for TCP QR payloads.
- Add `derptun serve --tcp <target> --web --qr` for web QR payloads.
- Persist opaque Web and TCP tunnel tokens across app launches, shown only as truncated labels or fingerprints.
- Never persist SSH usernames or passwords.
- Expand `pkg/derpholemobile` into a small native mobile bridge for file receive and derptun local tunnel opening.
- Use as much existing Go session code as possible and keep direct-preferred transport behavior aligned with the CLI.
- Include subagent-based live testing in the later implementation plan.

## Non-Goals

- Rewriting Derphole or derptun transport logic in Swift.
- Using WASM.
- Shipping full SSH terminal support in the first milestone before Files and Web are stable.
- Copying the full vvterm application architecture.
- Persisting SSH credentials.
- Adding account systems, cloud sync, history lists, or multi-session management.
- Supporting background transfers in the first demo.

## App Architecture

The app should use a native SwiftUI `TabView` with three tabs:

- Files
- Web
- SSH

Each tab gets its own state model and view composition. Shared services should cover:

- QR scanner presentation.
- typed payload parsing through the Go bridge.
- token persistence for Web and SSH.
- route/status event normalization.
- formatted byte, MiB, MiB/s, and token fingerprint display.
- launch-time test payload injection.

The Go bridge should expose long-lived objects rather than one-shot static calls. The bridge should look conceptually like:

- `FileReceiver`: receive, cancel, status callbacks, progress callbacks.
- `TunnelClient`: open local derptun listener, cancel, status callbacks, route callbacks, bound address callback.
- shared payload parser/classifier.

Callbacks from Go should be coalesced before driving SwiftUI updates. Transfer and tunnel throughput must not be limited by UI render frequency. Swift can compute MiB/s from coalesced progress snapshots.

## QR Payloads

Breaking QR payload changes are allowed. The app and CLI should converge on three intent-aware payloads:

```text
derphole://file?v=1&token=<url-escaped-file-token>
derphole://web?v=1&token=<url-escaped-client-token>&scheme=http&path=/
derphole://tcp?v=1&token=<url-escaped-client-token>
```

`file` carries the existing Derphole receive token. `web` carries a derptun client token plus web metadata. `tcp` carries a derptun client token for a generic TCP service. The SSH tab treats `tcp` payloads as SSH because the selected tab supplies that intent.

The parser should be implemented in Go and shared by CLI tests and the mobile bridge. Swift should ask the bridge to classify scanned payloads and receive a typed result instead of hand-parsing query strings.

Raw token fallback can remain available for tests and debug launch injection, but the normal QR path should use the versioned URLs.

## CLI Design

`derptun serve --tcp <target> --qr` emits a terminal QR containing a `derphole://tcp` payload. The surrounding terminal text should explain that this is a TCP tunnel QR for the Derphole iOS app.

`derptun serve --tcp <target> --web --qr` emits a terminal QR containing a `derphole://web` payload. It should also print clear text that the iOS app will connect the tunnel and open the service through a local browser URL. The web metadata defaults to scheme `http` and path `/`.

The first design does not add top-level `derphole web` or `derphole ssh` aliases. `derptun` owns tunnel QR sharing.

The existing file send QR path should migrate from `derphole://receive` to `derphole://file` as part of the breaking payload cleanup.

## Files Tab

The Files tab zero state should be minimal:

- short title/status text
- one primary `Scan QR Code` button
- no embedded camera viewport
- no visible manual payload controls by default

Tapping `Scan QR Code` presents the camera scanner modally. A successful scan dismisses the scanner and transitions into receive state.

Normal physical-device UI should not expose manual payload entry. Simulator and automated tests can enable debug/manual entry through launch arguments or environment variables. This preserves repeatability without making test affordances part of the default product surface.

After scanning, the user should see clear stages:

- validating QR code
- claiming offer
- connecting through relay
- probing or promoting direct
- connected direct
- receiving
- complete
- failed
- canceled

The receive UI should use native iOS controls and clear hierarchy:

- file name when available
- current MiB and total MiB
- MiB/s
- linear `ProgressView`
- route badge: Negotiating, Relay, Direct
- concise status text
- cancel during active receive

On completion, actions are:

- `Save File`: presents the existing document picker export flow, but uses user-facing "Save File" wording.
- `Discard`: deletes temporary receive output and resets the Files tab to zero state.

If the user cancels Save File, the completed file remains available until Save File succeeds, Discard is tapped, or a new receive starts.

## Web Tab

The Web tab zero state contains:

- `Scan QR Code`
- remembered web token row if present, shown as a truncated fingerprint
- `Reconnect` when a remembered token exists
- no raw token entry unless test/debug mode is enabled

Scanning accepts `derphole://web` payloads. A valid scan persists the opaque token and starts a tunnel. Reconnect starts a tunnel from the persisted token.

The mobile bridge should expose a web/tunnel open API backed by `session.DerptunOpen`:

- listen address defaults to `127.0.0.1:0`
- bridge returns the bound address through callback or return value
- tunnel remains open until canceled
- route/status callbacks report relay/direct state

After the local listener is bound, Swift pushes a full-screen browser screen. The browser opens:

```text
http://<bound-local-address><path>
```

The browser should use `WKWebView`, not an external Safari handoff. The screen should feel like a lightweight Safari-style browser:

- full-screen web content
- compact chrome with address display
- back, forward, reload or stop
- route badge
- Disconnect or Close

Chrome may collapse or reduce prominence while scrolling. The first milestone can keep this simple, but the visual result should feel like a browser screen rather than a card embedded in the tab.

Disconnect cancels the Go tunnel, pops or returns to the Web tab connect state, and preserves the remembered token.

## SSH Tab

The SSH tab mirrors the Web tab at the connection level:

- `Scan QR Code`
- remembered TCP token row if present, shown as a truncated fingerprint
- `Reconnect` when a remembered token exists
- no raw token entry unless test/debug mode is enabled

Scanning accepts `derphole://tcp` payloads. A valid scan persists the opaque TCP token. Username and password are never persisted.

On connect, the app prompts with a native credentials dialog for username and password. The prompt appears on every connect or reconnect attempt.

The transport path should match Web:

1. open a local derptun listener through the Go mobile bridge on `127.0.0.1:0`
2. connect a Swift/libssh2 SSH client to the bound local address
3. render the SSH shell through a borrowed vvterm terminal slice

The vvterm slice should include only:

- libssh2 runtime/client/session pieces required for password SSH
- `GhosttyTerminalView` custom I/O mode
- SwiftUI terminal wrapper pattern
- enough resize/input/output handling for a minimal interactive SSH shell

The SSH terminal screen is pushed full-screen and shows:

- terminal content
- compact top bar with connection state and route
- Disconnect

If the remote shell exits, the app closes the tunnel and returns to the SSH connect screen with the persisted token still available. Reconnect prompts for credentials again. Scanning a new QR replaces the remembered token after validation.

SSH is not required to be functionally complete in milestone 1, but the route, state model, and bridge interfaces should be designed so it can land without reorganizing Files and Web.

## Token Persistence

Web and SSH tokens persist across app launches through a small app-local store such as `UserDefaults`. The stored values are opaque access tokens, so the UI should show a truncated fingerprint rather than the full token.

The token display should avoid implying semantic meaning. A format like `dtc1_abc...xyz` or a short hash-derived fingerprint is enough.

The app must never persist SSH usernames or passwords. Test automation can inject credentials at runtime for live tests, but no fixed credentials should land in source.

## Permissions

The app needs camera usage and local network usage descriptions:

- `NSCameraUsageDescription`
- `NSLocalNetworkUsageDescription`

Camera permission is requested when opening the scanner, not on app launch.

Local-network permission should be triggered when a transfer or tunnel needs it. If denied, the app should show a concise blocked state. Relay fallback may still work for file receive or tunnels, but direct success remains an explicit verification requirement.

## Error Handling

Invalid QR payloads fail before network work starts. The scanner should dismiss to a readable error state with an option to scan again.

Expired, wrong-purpose, unsupported-version, or malformed tokens should produce mode-specific messages:

- Files: "This is not a file receive code."
- Web: "This is not a web tunnel code."
- SSH: "This is not a TCP tunnel code."

File receive cancellation cancels the Go receiver, cleans partial output, and resets to a canceled state. Discard after completion deletes temp output.

Web disconnect cancels the tunnel but keeps the remembered token. Browser load failures stay in the browser with reload and disconnect available.

SSH disconnect closes the SSH shell and derptun tunnel. Shell exit returns to the connect screen. Authentication failures return to the credentials prompt path without persisting entered values.

## Mise Tasks And Live Testing

The existing `apple:physical-transfer` task remains the file receive live test. It should continue injecting live tokens at runtime and should never rely on hardcoded source tokens.

New implementation tasks should include:

- `apple:web-tunnel`: start a local HTTP fixture, run `derptun serve --tcp <fixture> --web --qr`, inject or scan the live payload, verify `WKWebView` loads fixture content through the tunnel, and confirm route status.
- `apple:ssh-tunnel`: later task that starts a controlled local SSH fixture, runs `derptun serve --tcp <ssh> --qr`, injects or scans the live TCP payload, injects test credentials only at runtime, and verifies terminal output.

Simulator tests can use launch-injected payloads. Physical tests should prefer scanning when practical, but runtime injection is acceptable for repeatability as long as source does not contain live tokens.

The implementation plan should explicitly use subagents for independent testing lanes:

- Go/mobile bridge lane: QR parser, mobile tunnel APIs, Go tests.
- iOS UI lane: Swift state/view models, scanner modal, browser screen, persistence tests, simulator UI tests.
- Live verification lane: CLI-generated QR/token flows with simulator and physical device through `mise` tasks.

## Testing

Go tests should cover:

- parsing and encoding `file`, `web`, and `tcp` payloads
- rejection of wrong mode and unsupported version
- `derptun serve --qr` output behavior
- `derptun serve --web --qr` output behavior
- mobile bridge file receiver lifecycle
- mobile bridge tunnel open/cancel lifecycle using test seams

Swift tests should cover:

- tab-level zero states
- scanner modal state transitions
- debug/manual controls hidden by default and visible in test mode
- file receive state transitions
- MiB/s formatting from progress snapshots
- Save File and Discard state behavior
- Web token persistence and reconnect state
- Web browser URL construction from bound local address and path
- SSH token persistence without credential persistence

UI tests should cover:

- Files zero state only shows Scan QR Code by default
- scanner presentation and injected payload dismissal path
- file receive progress and completion state
- Web scan or injection to browser load against fixture
- Web disconnect returns to connect state with token remembered
- SSH tab shows reconnect from remembered token and prompts for credentials

Required baseline verification after milestone 1:

```bash
mise run test
mise run apple:build
mise run apple:test
APPLE_PHYSICAL_TRANSFER_MIB=2 mise run apple:physical-transfer
mise run apple:web-tunnel
```

## Implementation Milestones

Milestone 1:

1. Shared intent-aware QR payload parser and CLI payload changes.
2. Swift app shell with Files, Web, SSH tabs.
3. Modal scanner service.
4. Files UI polish: progress, MiB/s, route badge, Save File, Discard, hidden debug input.
5. Mobile derptun open bridge.
6. Web tab persistence, connect flow, pushed `WKWebView` browser, disconnect.
7. SSH tab scaffold: persisted TCP token, scan/reconnect shell, credentials prompt design, and terminal integration boundary.
8. New tests and live `mise` tasks for Files and Web.

Milestone 2:

1. Import the minimal vvterm/libghostty/libssh2 terminal slice.
2. Connect SSH to the local derptun listener.
3. Add SSH terminal lifecycle, resize, input/output, disconnect, and shell-exit handling.
4. Add live SSH tunnel task and simulator coverage.

## Risks

The largest risk is SSH scope. Keeping SSH functional work out of milestone 1 keeps the first demo achievable while preserving the right architecture.

The second risk is pulling too much vvterm code. The implementation plan should identify exact files and dependencies before copying code and should prefer a tiny compatibility layer over importing unrelated vvterm app systems.

The third risk is local network behavior on physical devices. Files has already proven a direct physical route. Web and SSH tunnel flows must be verified the same way because their local listener plus tunnel lifecycle differs from one-shot file receive.

## Success Criteria

- The iOS app opens to native Files, Web, and SSH tabs.
- Files has a minimal physical-device UI with modal scanner, clear transfer progress, MiB/s, route, Save File, and Discard.
- Web scans or reconnects a persisted web token and opens a local tunnel in a full-screen `WKWebView` browser.
- SSH has the designed scan/reconnect/token/credential shell and stable bridge boundary, even if terminal function lands in milestone 2.
- The Go mobile bridge owns file and tunnel transport behavior using existing Go code paths.
- Web and SSH tokens persist across app launches; usernames and passwords do not.
- CLI QR payloads are intent-aware for file, web, and tcp modes.
- Live `mise` tasks prove file receive and web tunnel flows with runtime-generated tokens and no hardcoded source tokens.
