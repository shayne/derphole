# Public Security Hardening Design

## Goal

Harden `derphole` before wider open source distribution without changing its core product model:

- no Tailscale account
- no `tailscaled`
- bearer-token session setup
- simple `listen` / `send` and `share` / `open` workflows

The target is not "perfect security". The target is to fix practical, real issues that are worth shipping, while preserving ergonomics.

## Current Findings

### 1. QUIC Peer Authentication Is Too Weak

Public sessions currently use QUIC with a self-signed certificate and `InsecureSkipVerify: true`. That provides encryption in transit but does not sufficiently bind the QUIC peer to the intended session peer. An active attacker who can interfere with the relay or network path should not be able to impersonate a peer just by presenting any certificate.

This does **not** require a public CA or user-managed certificates. The right fix is session-bound authentication using ephemeral session identity material.

### 2. The Token Carries Unnecessary Data

The token is intentionally a bearer capability, so it is acceptable that the holder can decode it. However, it should only contain fields required for bootstrap, authorization, and useful UX. It should not carry stale fields from earlier transport designs or let remote token contents drive unnecessary local behavior.

Examples of fields to remove or reconsider:

- transport leftovers no longer required by the current QUIC-based public session path
- `ShareTargetAddr`, which leaks the sharer's local backend target without being required by `open`
- token-driven local bind defaults, which should instead be a safe local default on the opener side

### 3. Some Runtime Limits Are Too Loose

The public path should defend itself better against malformed claims, oversized control data, and stream abuse. This is not about hostile internet exposure of a public server; it is about making malicious or buggy peers fail closed and cheaply.

## Design

### Session-Authenticated QUIC

Public sessions will keep using ephemeral self-signed certificates, but peer authentication will be explicit:

- `listen` / `share` generates an ephemeral QUIC identity keypair for the session
- the token includes the public identity material needed for peer verification
- the server presents a self-signed cert derived from that session identity
- `send` / `open` pins and verifies the expected server identity from the token
- `send` / `open` also presents their own ephemeral QUIC identity
- the listener verifies the accepted claimant's QUIC identity against the accepted claim

This preserves zero-setup UX while eliminating "accept any cert" behavior.

### Token Tightening

The token remains a pure bearer capability and still contains everything needed to connect, but only fields with a clear current purpose remain.

Keep:

- version
- session ID
- expiry
- bootstrap DERP region hint
- listener DERP routing public key
- bearer secret
- capability flags
- QUIC server identity material needed for client-side pinning

Remove:

- fields only used by the retired inner WireGuard transport
- `ShareTargetAddr`
- token-driven bind defaults that should instead be local policy

`open` should continue to default to `127.0.0.1:0` unless the user supplies an explicit bind address.

### Runtime Hardening

Add defensive bounds and fail-closed behavior:

- cap candidate counts accepted from peers
- cap control-message sizes
- cap concurrent incoming QUIC streams to a practical maximum for `share/open`
- reject malformed claims, malformed decisions, and capability mismatches early
- fail closed on QUIC identity mismatch
- keep token lifetime at 1 hour

No extra mandatory user step is added. An optional passphrase layer can be considered later, but it is not part of this pass.

## User-Facing Behavior

The command surface remains:

```bash
npx -y derphole@latest listen
printf 'hello\n' | npx -y derphole@latest send <token>

npx -y derphole@latest share 127.0.0.1:3000
npx -y derphole@latest open <token>
```

Status output remains similar, including relay-to-direct promotion messages under `--verbose`.

## Verification Plan

### Automated

- unit tests for token encode/decode and new token shape
- unit tests for QUIC identity verification and mismatch rejection
- unit tests for malformed claim / decision handling
- tests for stream and candidate limit enforcement

### Live

Run both one-shot and `share/open` flows across:

- local -> `hetz`
- `hetz` -> local
- local -> `pve1`
- `pve1` -> local

Success means:

- existing workflows still succeed
- relay-first/direct-upgrade behavior still works
- peer-auth mismatch fails closed
- malformed or excessive peer input is rejected without destabilizing sessions

## Out of Scope

- introducing account-backed authentication
- requiring public CA certificates
- changing the token model away from bearer-capability semantics
- adding a required passphrase or confirmation code
