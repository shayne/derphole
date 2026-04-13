# derphole web proof of concept

`derphole-web.zip` is a static browser proof of concept for one-file derphole
transfers over DERP rendezvous with relay-first delivery and a WebRTC direct
upgrade when the browser and network allow it.

The zip contains:

- `index.html`
- `app.js`
- `webrtc.js`
- `styles.css`
- `wasm_exec.js`
- `wasm_payload.js`
- `derphole-web.wasm`

Unzip the artifact and open `index.html`. The build embeds the WASM payload in
`wasm_payload.js` so the page can load from `file://` without a local static
server. Serving the directory over HTTP also works.

The same static directory is also built for GitHub Pages from
`dist/web/derphole-web`. The page doubles as the project demo landing page and
keeps the live browser sender/receiver UI on the same page as the CLI install
examples.

## Scope

The browser build reuses the repository's DERP rendezvous primitives:

- `pkg/token`
- `pkg/rendezvous`
- `pkg/derpbind`

It does not import `pkg/session`, because that package intentionally includes
native UDP, WireGuard, QUIC, and socket tuning code that is not available in a
browser WASM runtime.

## Transfer Model

The browser build starts every transfer on DERP relay immediately. That keeps
small transfers and first bytes from waiting on NAT traversal. In parallel, the
browser creates an ordered, reliable WebRTC DataChannel and exchanges WebRTC
offer, answer, and ICE candidate messages through DERP control frames. When the
data channel opens and both sides agree on the current byte offset and sequence,
the sender switches subsequent data frames to the direct WebRTC path.

If WebRTC is unavailable or fails before handoff, the transfer remains on DERP
relay. If WebRTC fails after handoff, the transfer fails instead of guessing at
resumption state. This matches the native direct-path rule: fallback is safe
before path switch, but post-switch failure must be explicit.

DERP still uses DERP-over-WebSocket through Tailscale's DERP HTTP client when
compiled for `GOOS=js GOARCH=wasm`.

Data is sent as bounded binary frames defined in `pkg/derphole/webproto`. The
sender waits for cumulative ACKs before advancing, and retries the current frame
when an ACK does not arrive. This keeps browser memory bounded and avoids
overrunning DERP server queues. Browser relay frames are capped below DERP's
theoretical packet maximum because near-64 KiB WebSocket frames have been
observed to close public DERP browser connections; the current frame payload
limit is 16 KiB.

## Browser Storage

The sender uses modern file picker APIs when available and falls back to an
`<input type="file">`.

The receiver prefers a directory handle so the final filename from sender
metadata can be used without buffering the entire file in memory. If the
directory picker is unavailable, the page falls back to buffering chunks in the
browser and creating a download at the end. That fallback is acceptable for a
small proof of concept but is not suitable for very large files.

## Browser Direct Path

The WebRTC direct path uses browser ICE with public STUN servers. It is not the
native derpcat UDP engine and does not reuse Tailscale magicsock sockets, because
browser JavaScript cannot open raw UDP sockets. WebRTC is still the practical
browser primitive for NAT traversal and direct browser-to-browser data.

Some browsers require secure-context APIs for parts of the storage and WebRTC
stack. The artifact is built to open from `file://`, but direct upgrade behavior
is browser-dependent. DERP relay remains the correctness fallback.

## Limitations

- One file per transfer.
- No direct UDP upgrade in the browser; direct mode uses WebRTC DataChannel.
- No directory archive format yet.
- Relay throughput is correctness-first and does not target native derphole UDP
  speeds.
