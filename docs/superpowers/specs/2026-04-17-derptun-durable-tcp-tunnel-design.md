# `derptun` durable TCP tunnel design

## Summary

`derptun` is a new user-facing CLI and npm package for durable, token-addressed tunnels between two machines that may both be behind NAT. The first release is TCP-first and targets long-running SSH sessions over the existing derphole NAT traversal, relay fallback, and direct UDP transport stack.

The v1 goal is to make this workflow practical:

```sh
# ALPHA, the host with sshd on localhost:22
derptun token --days 7 > alpha.token
derptun serve --token alpha.token --tcp 127.0.0.1:22

# BETA, the client machine
derptun open --token alpha.token --listen 127.0.0.1:2222
ssh -p 2222 foo@127.0.0.1
```

It should also support an SSH `ProxyCommand` path for users who want one SSH command:

```sh
ssh -o ProxyCommand='derptun connect --token alpha.token --stdio' foo@alpha
```

UDP is not part of the first implementation gate. The design must still keep protocol and package seams ready for future UDP forwarding, with Minecraft-style UDP game server access as the concrete pressure case.

## Goals

- Establish a tunnel between two machines anywhere on the internet without requiring either side to expose a public inbound port.
- Support TCP forwarding in v1, especially SSH to a target host behind NAT.
- Generate stable tokens before either side starts the tunnel.
- Let both sides restart and reuse the same token until expiry.
- Default token expiry to 7 days.
- Allow expiry by relative days or an absolute timestamp.
- Reconnect automatically when the network path drops while both `derptun` processes remain alive.
- Preserve active TCP sessions across transient network drops where feasible.
- Publish `derptun` as an npm package in parallel with `derphole`.
- Keep the design ready for future UDP forwarding without blocking v1 on UDP.

## Non-Goals

- V1 does not implement UDP forwarding.
- V1 does not provide a general VPN, subnet router, or stable private address space.
- V1 does not promise to keep an existing SSH session alive if either `derptun` process exits. When a process exits, the local TCP socket or backend TCP socket is gone.
- V1 does not add SSH key management. Existing `derphole ssh invite` remains the key authorization flow.
- V1 does not require kernel TUN/TAP setup or elevated privileges.

## Existing Context

The current `derphole share/open` flow already exposes a local TCP service through DERP rendezvous, relay fallback, direct UDP promotion, and multiplexed QUIC streams. It is a strong base for `derptun` v1, but it is session-scoped:

- tokens are issued by the serving process at runtime;
- token expiry is fixed to one hour in the session constructors;
- a share token is intentionally claimed by one client;
- the serving token contains serving-side DERP and QUIC public keys;
- the serving process currently creates those identities when it starts.

Those constraints mean `derptun` should not be a thin alias for `derphole share/open`. It needs a stable tunnel credential model and a reconnect contract.

The repository also has experimental WireGuard netstack code under `pkg/wg` and `pkg/session/external_wg*`. That path is a better long-term foundation for generic TCP and UDP tunnel behavior, but it is larger than the v1 SSH-focused release. V1 should use the proven QUIC stream service-sharing path and leave a clear upgrade path toward a netstack-backed UDP-capable tunnel.

## Product Shape

`derptun` is a separate binary and npm package:

```sh
derptun token [--days N | --expires RFC3339]
derptun serve --token TOKEN --tcp HOST:PORT [--force-relay]
derptun open --token TOKEN [--listen HOST:PORT] [--force-relay]
derptun connect --token TOKEN --stdio [--force-relay]
derptun version
```

`serve` runs on ALPHA and forwards incoming tunnel streams to the target TCP service. `open` runs on BETA and exposes a local TCP listener. `connect --stdio` runs one proxied TCP stream over stdin/stdout so OpenSSH can use it as `ProxyCommand`.

The first release should document SSH as the primary example, but the TCP tunnel is generic. It should work for any TCP service where reconnecting the outer tunnel is useful.

## Token Model

`derptun token` creates a durable token before the tunnel is started. The token must contain or derive:

- tunnel ID;
- expiry;
- bearer authorization secret;
- serving-side DERP identity;
- serving-side QUIC identity;
- protocol capabilities;
- optional future tunnel metadata.

Current `derphole` tokens include the serving side's DERP public key and QUIC public key. Because `derptun` tokens are generated before `serve` starts, the token command must also generate stable serving-side private identity material and encode it in a secure serve credential.

V1 should use one pasteable token artifact that can bring up either side. This keeps the first UX simple and matches the requested stable-token restart behavior. The security model should state plainly that the token is a bearer secret: anyone with the token can connect to the tunnel and may be able to serve it. A future split-token model can produce separate `serve` and `connect` credentials if needed.

Expiry behavior:

- default: `--days 7`;
- relative: `--days N`;
- absolute: `--expires 2026-04-24T12:00:00Z`;
- validation should reject expired tokens before attempting rendezvous;
- `serve` should reject claims after token expiry;
- `open` and `connect` should retry until context cancellation, token expiry, or a non-retryable auth/protocol error.

Capability bits should distinguish `derptun` TCP from current `derphole` share/open tokens. This avoids accidental cross-use.

## Rendezvous And Reconnect

V1 should reuse the existing public DERP bootstrap, claim, decision, candidate exchange, direct UDP promotion, and QUIC stream transport where possible.

The new behavior is that a tunnel token may be claimed repeatedly over time by the same role. The rendezvous gate should therefore support a durable tunnel mode:

- one active connector at a time for v1;
- reconnects from the same token after transport loss;
- rejection of concurrent competing connectors unless explicitly allowed later;
- fresh direct candidates on each reconnect;
- stable serving identity across restarts.

The existing `rendezvous.Gate` is one-shot and stores the first claim. `derptun` should either add a new durable gate type or extend the gate with a mode that permits reconnect epochs. The durable mode should avoid weakening one-shot `derphole` transfer semantics.

## TCP Session Durability

There are three durability levels to distinguish in docs and implementation:

1. **Path recovery**: direct UDP fails and the transport falls back to relay or re-promotes. Existing transport logic already handles much of this.
2. **Outer connection recovery**: DERP, QUIC, or local network state drops while both `derptun` processes continue running. `derptun` should reconnect and keep active TCP streams alive where feasible.
3. **Process restart recovery**: either side exits and restarts with the same token. The tunnel address remains stable, but any active TCP session is lost because the process-owned socket is gone.

V1 should target levels 1 and 2. It should be explicit about level 3: users who need shell continuity across process death should run SSH inside `tmux` or `screen`.

To preserve active TCP sessions through transient tunnel loss, `derptun` should introduce an internal TCP stream envelope rather than exposing raw QUIC streams directly to the local TCP bridge. Each accepted local TCP connection gets a logical stream ID. If the tunnel transport reconnects while both endpoint processes still have their local/backend TCP sockets open, the peers can resume carrying bytes for the same logical stream ID over the new QUIC connection.

The logical stream envelope should be scoped and conservative:

- one tunnel generation at a time;
- monotonically increasing logical stream IDs;
- ordered byte stream per logical stream;
- half-close propagation;
- backpressure through normal stream writes;
- reconnection timeout after which the local/backend TCP socket is closed;
- no replay beyond bytes already accepted by the local TCP stack in v1.

This is enough for many SSH network blips because OpenSSH sees a paused TCP path rather than an immediate local disconnect. It does not turn TCP into a fully resumable protocol after process death.

## SSH UX

The documented default should be two-process because it is debuggable and works with all SSH clients:

```sh
derptun open --token alpha.token --listen 127.0.0.1:2222
ssh -p 2222 foo@127.0.0.1
```

The one-command option should use `ProxyCommand`:

```sshconfig
Host alpha-derptun
  HostName alpha
  User foo
  ProxyCommand derptun connect --token ~/.config/derptun/alpha.token --stdio
```

Then:

```sh
ssh alpha-derptun
```

`connect --stdio` should open exactly one TCP stream to the served target and bridge it to stdin/stdout. This avoids having `derptun` shell out to `ssh`, avoids depending on an SSH library for v1, and keeps OpenSSH in charge of authentication, host keys, ciphers, agent forwarding, and terminal behavior.

## Future UDP Design

UDP should be designed but not implemented in v1. The future CLI can extend the same shape:

```sh
derptun serve --token TOKEN --udp 127.0.0.1:19132
derptun open --token TOKEN --udp-listen 127.0.0.1:19132
```

This would support a Minecraft Bedrock-style server or any other UDP service behind NAT.

The future UDP data plane needs different semantics than TCP:

- local UDP listener on BETA;
- backend UDP association mapping on ALPHA;
- datagram framing with source association IDs;
- idle timeouts for UDP associations;
- packet size and MTU handling;
- optional datagram loss stats;
- no ordered stream abstraction;
- direct UDP path preference with relay fallback.

V1 code should leave comments and types around a tunnel protocol abstraction so TCP and UDP do not become tangled:

- `ProtocolTCP` implemented;
- `ProtocolUDP` reserved;
- `ForwardSpec` with protocol, listen address, target address, and future idle timeout fields;
- transport/session code comments identifying where datagram framing will attach later.

The WireGuard netstack path remains the likely long-term option for richer TCP/UDP tunnel support. The QUIC-stream path is still the right v1 path because it is already proven for TCP service sharing.

## Packaging And Release

The release surface becomes two products:

- `derphole`;
- `derptun`.

Packaging should mirror the previous multi-product workflow pattern while keeping current source naming:

- add `cmd/derptun`;
- add `packaging/npm/derptun/package.json`;
- add `packaging/npm/derptun/bin/derptun.js`;
- build native release binaries for both products on Linux and macOS amd64/arm64;
- stage npm artifacts for both products;
- dry-run publish both packages;
- publish both packages on release tags when npm ownership/trusted publishing is ready;
- keep `publish-npm-if-missing.sh --skip-unclaimed` behavior so unbootstrapped npm packages do not fail GitHub release publication.

Manual npm bootstrap from this Mac is expected before CI publishing can succeed for the new package.

## Documentation

The README should add a concise `derptun` section once implementation lands:

- what it is;
- how to create a token;
- how to serve SSH;
- how to connect through a local port;
- how to use `ProxyCommand`;
- what survives reconnects;
- what does not survive process exits;
- token expiry and bearer-secret warnings;
- UDP is planned, with Minecraft UDP server forwarding as a future example.

`docs/releases/` should mention the breaking addition as a new product surface if the release notes are updated for the feature release.

## Testing Strategy

Focused tests should cover:

- token generation default expiry;
- token generation absolute expiry;
- expired token rejection;
- token capability isolation from current `derphole` share/open tokens;
- serving-side identity stability across token decode;
- durable gate allows reconnect after a prior transport loss;
- durable gate rejects concurrent competing connectors;
- `open` local TCP forwarding to a loopback backend;
- `connect --stdio` bridges one TCP stream;
- reconnect loop preserves the local listener process after transient tunnel failure;
- npm launcher selects and executes the vendored `derptun` binary;
- release package smoke test includes both products.

Live verification should extend `smoke-remote-share` or add `smoke-remote-derptun`:

```sh
REMOTE_HOST=my-server.example.com mise run smoke-remote-derptun
```

The smoke should prove that ALPHA can serve a loopback TCP echo or SSH-like service and BETA can connect through a local port over the public DERP path.

## Risks

- Active TCP stream resume can become complicated if implemented as full byte-level replay. V1 should avoid pretending to be fully resumable after bytes leave the local TCP socket.
- A single bearer token for both serving and connecting is easy to use but broad. Split serve/connect tokens may be needed later.
- Stable serving identity material in a pasteable token increases token sensitivity.
- Adding a second product reintroduces release-matrix complexity.
- UDP support will need a real datagram design; bolting UDP onto TCP stream code would be a mistake.

## Recommendation

Build `derptun` v1 as a TCP-first product with stable token generation, durable reconnect semantics, SSH examples, and npm/release packaging. Use the existing QUIC stream service-sharing transport as the base, add a durable tunnel token and reconnect gate, and reserve explicit protocol seams for future UDP. Do not block v1 on the WireGuard netstack path, but keep that path in view for Minecraft-style UDP forwarding and richer tunnel behavior.
