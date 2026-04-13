# derphole web proof of concept

`derphole-web.zip` is a static browser proof of concept for one-file derphole
transfers over DERP relay.

The zip contains:

- `index.html`
- `app.js`
- `styles.css`
- `wasm_exec.js`
- `wasm_payload.js`
- `derphole-web.wasm`

Unzip the artifact and open `index.html`. The build embeds the WASM payload in
`wasm_payload.js` so the page can load from `file://` without a local static
server. Serving the directory over HTTP also works.

## Scope

The browser build reuses the repository's DERP rendezvous primitives:

- `pkg/token`
- `pkg/rendezvous`
- `pkg/derpbind`

It does not import `pkg/session`, because that package intentionally includes
native UDP, WireGuard, QUIC, and socket tuning code that is not available in a
browser WASM runtime.

## Transfer Model

The current proof of concept is relay-only. It uses DERP-over-WebSocket through
Tailscale's DERP HTTP client when compiled for `GOOS=js GOARCH=wasm`.

Data is sent as bounded binary frames defined in `pkg/derphole/webproto`. The
sender waits for cumulative ACKs before advancing, and retries the current frame
when an ACK does not arrive. This keeps browser memory bounded and avoids
overrunning DERP server queues.

## Browser Storage

The sender uses modern file picker APIs when available and falls back to an
`<input type="file">`.

The receiver prefers a directory handle so the final filename from sender
metadata can be used without buffering the entire file in memory. If the
directory picker is unavailable, the page falls back to buffering chunks in the
browser and creating a download at the end. That fallback is acceptable for a
small proof of concept but is not suitable for very large files.

## Limitations

- One file per transfer.
- No direct UDP upgrade in the browser.
- No directory archive format yet.
- Relay throughput is correctness-first and does not target native derphole
  speeds.
