# Derptun Serve Invite And Token Cleanup Design

Date: 2026-07-03

Status: design approved in session. Implementation planning starts only after this spec is reviewed.

## Summary

Make `derptun serve` print the command the other side should run, matching the practical share flow users already get from `derphole send` and `derpssh share`.

At the same time, simplify derptun client credentials down to one public format:

- `dts1_...` remains the private server authority token.
- `DT1...` becomes the only public derptun client token format.
- The old JSON/base64 client token format is removed from product behavior, docs, tests, examples, and normal parsing.

This is intentionally a cleanup, not a compatibility migration. Old client tokens become invalid. The CLI should report them as invalid client tokens without recommending a legacy path.

## Goals

- Let a user run `derptun serve --tcp HOST:PORT` and copy the printed `derptun open` command to the other machine.
- Generate an ephemeral server token automatically when `serve` is run without a token source.
- Preserve persistent tunnel use by allowing `serve` to use `--token`, `--token-file`, or `--token-stdin` for an existing server token.
- Use `--token`, `--token-file`, and `--token-stdin` consistently for client credentials on `open` and `connect`; do not make the token positional.
- Make `DT1...` the canonical client token string everywhere derptun accepts or emits client access.
- Keep derpssh and derphole on the same shared credential infrastructure so this does not fork product behavior by interface.
- Delete obsolete code and docs instead of leaving dual token formats around.

## Non-Goals

- Do not foreground SSH as the derptun use case. `derpssh` owns SSH sharing.
- Do not keep parsing the old client token format for compatibility.
- Do not add a migration command for old client token files.
- Do not require users to generate a server token before trying a one-off tunnel.
- Do not remove persistent server tokens or token-file workflows.

## User-Facing CLI Shape

### One-Off Tunnel

The simple path becomes:

```bash
npx -y derptun@latest serve --tcp 127.0.0.1:3000
```

`serve` generates a process-local ephemeral server token, derives a client token, starts serving, and prints:

```bash
On the other machine, run:
  npx -y derptun@latest open --token DT1...
```

The generated server token is not printed and does not outlive the process.

### Persistent Tunnel

Users who need a stable tunnel can still create and reuse a server token:

```bash
npx -y derptun@latest token server > server.dts
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:3000
```

This serves with the supplied server token and prints a derived client command:

```bash
On the other machine, run:
  npx -y derptun@latest open --token DT1...
```

Users who want to provision client credentials ahead of time can run:

```bash
npx -y derptun@latest token client --token-file server.dts > client.dt1
npx -y derptun@latest open --token-file client.dt1
```

The file extension is only documentation. The meaningful contract is the token contents.

### Token Sources

`open` and `connect` keep the explicit token-source flags:

- `--token DT1...`
- `--token-file PATH`
- `--token-stdin`

Exactly one source is required. This keeps the CLI consistent with server token handling and works for copy-paste, scripts, files, and secret managers.

### QR Mode

`serve --qr` should reuse the same derived `DT1...` client token. Plain `serve` always prints the CLI command. QR mode adds the QR payload below that command rather than becoming a separate credential path.

## Token Model

There are two credential roles:

- server authority token: private, starts a serve side, can mint client tokens
- client token: public enough to share with the connecting side, authorizes opening the tunnel

`DT1...` is no longer treated as a secondary compact invite wrapper around another token. It is the public derptun client token format.

The implementation should rename concepts where practical:

- use "client token" for `DT1...`
- use "invite" for the human-facing share artifact, such as the printed command or QR payload
- avoid "compact invite" as a core credential name once it is the canonical token

The binary contents of `DT1...` remain the client credential data needed to connect: session identity, client identity, expiry, public keys, bearer secret, and proof MAC. If future metadata no longer fits this shape, introduce a versioned successor such as `DT2...` instead of preserving the removed legacy format.

## Internal Data Flow

1. `serve` validates `--tcp`.
2. `serve` resolves a server token source if one was supplied.
3. If no server token source was supplied, `serve` generates an ephemeral server token for this process.
4. `serve` starts the tunnel using the server authority token.
5. `serve` derives a canonical `DT1...` client token.
6. `serve` prints an `open --token DT1...` command.
7. `open` and `connect` resolve exactly one client token source.
8. The session layer decodes the `DT1...` client token to a typed client credential before using it for dialing.

The session layer should prefer typed client credentials internally where that keeps boundaries cleaner. Passing raw token strings through many layers should be reduced when it is touched for this feature.

## Error Handling

- If `serve` receives more than one server token source, fail with the existing token-source exclusivity error.
- If `serve` receives no token source, generate an ephemeral server token instead of failing.
- If `open` or `connect` receives no client token source, fail and show the supported token-source flags.
- If `open` or `connect` receives a server token, fail with a clear role error: server tokens are for `serve`; use a client token or copy the command printed by `serve`.
- If `open` or `connect` receives any malformed or removed client token format, fail with a generic invalid client token error.
- Do not include special recovery instructions for the removed client token format.

## Documentation

Update README and command help so the primary derptun workflow starts with:

```bash
npx -y derptun@latest serve --tcp 127.0.0.1:3000
```

Then show the printed `open --token DT1...` command as the normal next step.

Persistent tokens should be documented after the one-off path. The docs should use `server.dts` for server tokens and a neutral client token filename such as `client.dt1` when a file example is needed.

Remove docs and examples that teach the removed client token encoding or present a separate "compact invite" concept to users.

## Testing And Verification

Add focused coverage for:

- `derptun serve --tcp ...` with no token source generates an ephemeral server token and prints an `open --token DT1...` command.
- `derptun serve --token-file server.dts --tcp ...` uses the persistent server token and prints a derived `open --token DT1...` command.
- `derptun token client ...` emits `DT1...`.
- `derptun open --token DT1...`, `--token-file`, and `--token-stdin` all resolve through the canonical parser.
- `derptun connect --token DT1...`, `--token-file`, and `--token-stdin` all resolve through the canonical parser.
- old client token strings are rejected as invalid client tokens.
- server tokens passed to `open` or `connect` fail with the clearer role-specific error.
- QR generation uses the same canonical client token as the printed command.
- derpssh share/connect still work when their embedded derptun client credential uses the canonical token.
- mobile payload parsing accepts the canonical token without converting through a removed legacy representation.

Run focused package tests for touched CLI, token, session, derpssh, and mobile packages, then run the full suite with `mise run test`.

## Cleanup Boundary

The implementation should remove obsolete public APIs, constants, tests, fixtures, README sections, scripts, and names that only exist to support the removed client token format.

If a low-level encoder or decoder is temporarily useful for constructing tamper tests, keep it unexported and named as test support rather than product support. The final user-facing and exported package behavior should have one public client token format: `DT1...`.

## Implementation Plan Boundary

The implementation plan should decompose this into:

1. canonical token API cleanup
2. CLI token-source and serve-default behavior
3. derpssh, derphole, and mobile integration updates
4. README/help/example cleanup
5. focused tests and full-suite verification

Do not start implementation until this spec is reviewed and accepted.
