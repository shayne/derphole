# Scoped Multi-Service Derptun Implementation Plan

> Execute this plan with test-driven development. Keep versions 1 and 2
> behavior unchanged and checkpoint each coherent task on one GitButler branch.

**Goal:** Ship versioned Derptun credentials that expose several named TCP
services with signed per-client scopes, bounded stream opens, local revocation,
and a restricted child-process proxy.

**Design:** [Scoped multi-service credential and stream protocol](../specs/2026-08-29-derptun-multi-service-wire-design.md)

**Prerequisite:** Complete the shared Tailcat-derived resolver/selection
foundation and the inspection/access-artifact tasks. The magicsock experiment
is not a prerequisite.

## Task 1: Add named-forward validation without changing legacy credentials

**Files:**

- Create: `pkg/derptun/named_forward.go`
- Create: `pkg/derptun/named_forward_test.go`
- Modify: `pkg/derptun/token.go`

1. Write table tests for valid names, every rejected name form, loopback target
   normalization, explicit non-loopback permission, duplicate names, forward
   counts, concurrency limits, and idle limits.
2. Run the focused test and observe failures because the new validator and
   types do not exist:

   ~~~sh
   mise exec -- go test ./pkg/derptun -run 'TestNamedForward|TestValidateNamedForward' -count=1
   ~~~
3. Add `NamedForward`, `ForwardNames`, and package-owned canonicalization. Keep
   the legacy `ForwardSpec` and version 1/2 validation untouched.
4. Add deep-copy helpers so decoded server and client credentials cannot share
   mutable forward slices.
5. Rerun the focused tests and `mise run check:fast`.
6. Checkpoint as `derptun: validate named forward scopes`.

## Task 2: Implement version 3 and 4 credential encodings

**Files:**

- Modify: `pkg/derptun/token.go`
- Modify: `pkg/derptun/client_token.go`
- Modify: `pkg/derptun/token_test.go`
- Modify: `pkg/derptun/client_token_test.go`
- Create: `pkg/derptun/testdata/server-v3.golden`
- Create: `pkg/derptun/testdata/server-v4.golden`
- Create: `pkg/derptun/testdata/client-v3.golden`
- Create: `pkg/derptun/testdata/client-v4.golden`
- Create: `pkg/derptun/testdata/scope-v1.hex`
- Create: `pkg/derptun/testdata/proof-v3.hex`
- Create: `pkg/derptun/testdata/proof-v4.hex`

1. Add failing literal-golden tests for `dts3_`, `dts4_`, `DT3`, and `DT4`.
   Include round trips, deterministic sorting, exact scope bytes, exact proof
   input, and exact decode consumption.
2. Add negative tests for prefix/version/route mismatches, zero or excessive
   scopes, unsorted and duplicate names, a token over 1,024 decoded bytes,
   unknown new server JSON fields, and a one-byte mutation in every signed
   field.
3. Implement the new constants and exact encodings from the companion design.
   Use a dedicated scope encoder/decoder and `json.Decoder.DisallowUnknownFields`
   only for versions 3 and 4.
4. Extend proof generation and verification with the v3/v4 domain strings and
   binary expiry encoding. Continue to use `hmac.Equal`.
5. Keep all existing v1/v2 golden tests byte-identical.
6. Run:

   ~~~sh
   mise exec -- go test ./pkg/derptun -run 'Test.*(Token|Credential|Scope|Proof|Prefix)' -count=1
   mise exec -- go test -race ./pkg/derptun
   mise run check:fast
   ~~~
7. Checkpoint as `derptun: encode scoped credentials`.

## Task 3: Bind scope negotiation to authenticated rendezvous

**Files:**

- Modify: `pkg/token/token.go`
- Modify: `pkg/token/token_test.go`
- Modify: `pkg/rendezvous/messages.go`
- Modify: `pkg/rendezvous/durable_gate.go`
- Modify: `pkg/rendezvous/rendezvous_test.go`
- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/derptun_test.go`

1. Write failing tests for the distinct named-TCP capability, canonical scope
   digest, claim construction, server proof reconstruction, accept echo, and
   rejection of altered protocol version or digest.
2. Extend the optional client proof and accept info. Update bearer-MAC input so
   the new optional negotiation fields are covered when present while legacy
   fixture inputs remain unchanged.
3. Make version 3/4 `SessionToken` values use
   `CapabilityDerptunNamedTCP`. Reject attempts to use named credentials with
   the legacy capability.
4. Reconstruct and verify the full v3/v4 client credential before the client
   gate allocates transport state.
5. Require the client to verify the echoed protocol version and digest before
   direct-path or QUIC dialing.
6. Run:

   ~~~sh
   mise exec -- go test ./pkg/token ./pkg/rendezvous ./pkg/session -run 'Test.*(Named|Scope|Claim|Capability|Decision)' -count=1
   mise run check:fast
   ~~~
7. Checkpoint as `session: negotiate scoped derptun clients`.

## Task 4: Implement the bounded open-forward codec

**Files:**

- Create: `pkg/derptun/forward_protocol.go`
- Create: `pkg/derptun/forward_protocol_test.go`
- Create: `pkg/derptun/testdata/open-forward-v1.hex`
- Create: `pkg/derptun/testdata/open-responses-v1.json`

1. Add byte-golden tests for one request, success, and each rejection code.
2. Add short read/write tests, maximum name/message bounds, wrong magic,
   unknown version/flags/code, trailing-byte behavior, deadlines, and response
   text validation.
3. Implement `WriteForwardOpen`, `ReadForwardOpen`, `WriteForwardResponse`, and
   `ReadForwardResponse` over `io.Reader`/`io.Writer`. Require callers to set
   the connection deadline; codecs perform no hidden goroutine or background
   context work.
4. Add fuzz targets whose seed corpus includes every golden. Enforce the hard
   bound before allocation.
5. Run:

   ~~~sh
   mise exec -- go test ./pkg/derptun -run 'TestForward(Open|Response)' -count=1
   mise exec -- go test ./pkg/derptun -run '^$' -fuzz 'FuzzForward' -fuzztime 10s
   mise run check:fast
   ~~~
6. Checkpoint as `derptun: add named stream handshake`.

## Task 5: Add bounded revocation state

**Files:**

- Create: `pkg/derptun/revocation.go`
- Create: `pkg/derptun/revocation_test.go`
- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/derptun_test.go`

1. Add failing tests for the exact JSON format, size and mode checks, unknown
   fields, uppercase/short/duplicate IDs, no final-symlink following, atomic
   replacement, invalid reload retaining prior state, and cancellation when an
   active TokenID becomes revoked.
2. Implement an immutable snapshot parser and a context-owned five-second
   watcher. Inject the clock/stat/open seams needed for deterministic tests;
   do not poll in unit tests.
3. Add `RevocationFile` to the version 3/4 serve configuration. Load it before
   DERP startup. Check it at claim and forward-open boundaries.
4. Ensure watcher shutdown is joined and warning output is rate-limited and
   credential-free.
5. Run:

   ~~~sh
   mise exec -- go test -race ./pkg/derptun ./pkg/session -run 'Test.*Revocation' -count=1
   mise run check:fast
   ~~~
6. Checkpoint as `derptun: enforce local client revocation`.

## Task 6: Route native and mux streams by signed name

**Files:**

- Create: `pkg/session/derptun_forward.go`
- Create: `pkg/session/derptun_forward_test.go`
- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/derptun_app.go`
- Modify: `pkg/session/derptun_test.go`
- Modify: `pkg/derptun/mux.go`
- Modify: `pkg/derptun/mux_test.go`

1. Write end-to-end package tests with two loopback echo targets and two
   disjoint client scopes. Prove unauthorized names never cause a backend dial.
2. Add tests for per-forward and per-client concurrency accounting, backend
   timeout, idle timeout, cancellation, half-close, and counter release on all
   rejection/error paths.
3. Build a package-owned forward registry from the decoded server credential.
   It returns detached target/limit values and owns counters.
4. For native mode, assemble striped lanes into one logical connection, read
   exactly one open request, authorize and dial, acknowledge, then bridge.
5. For app-mux mode, open the existing generic stream and perform the bounded
   forward handshake above it. Prove existing pending-data replay preserves
   the request across carrier replacement; do not add a named Mux API unless a
   failing replay test demonstrates that the existing data path cannot do so.
6. Send rejection responses on one stream without closing the carrier or other
   streams. Emit only name, rejection class, and counters in network-debug.
7. Run:

   ~~~sh
   mise exec -- go test -race ./pkg/derptun ./pkg/session -run 'Test.*(NamedForward|ForwardRegistry|Mux.*Forward|Derptun.*Forward)' -count=1
   mise run check:fast
   ~~~
8. Checkpoint as `session: route scoped derptun forwards`.

## Task 7: Add token and serving CLI surfaces

**Files:**

- Modify: `cmd/derptun/token.go`
- Modify: `cmd/derptun/token_test.go`
- Modify: `cmd/derptun/serve.go`
- Modify: `cmd/derptun/command_test.go`
- Modify: `cmd/derptun/root.go`
- Modify: `cmd/derptun/root_test.go`
- Modify: `cmd/derptun/token_source.go`

1. Add command tests for repeated server `--forward NAME=HOST:PORT`, repeated
   client `--forward NAME`, `--allow-non-loopback`, `--revocation-file`, stable
   help, secret-safe errors, and all legacy command forms.
2. Parse repeated flags into the package validation API. Do not duplicate name
   or target validation in `cmd/`.
3. Select versions 3/4 only when server-token `--forward` is present. Require at
   least one client scope for a version 3/4 server token.
4. Make `derptun serve` derive its forward table from the server credential;
   reject `--tcp` combined with versions 3/4 and reject `--forward` runtime
   overrides.
5. Recognize all exact prefixes in token-source diagnostics without echoing
   input.
6. Run:

   ~~~sh
   mise exec -- go test ./cmd/derptun -run 'Test.*(Token|Serve|Prefix|Help)' -count=1
   mise run check:fast
   ~~~
7. Checkpoint as `cli: create and serve named derptun forwards`.

## Task 8: Add scoped open and connect commands

**Files:**

- Modify: `cmd/derptun/open.go`
- Modify: `cmd/derptun/connect.go`
- Modify: `cmd/derptun/command_test.go`
- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/derptun_test.go`

1. Add failing tests for explicit selection, single-scope defaulting, missing or
   ungranted names, versions 1/2 with `--forward`, bind-address reporting, and
   remote rejection messages.
2. Add `ForwardName` to the named credential session configs. Keep legacy
   configs and dispatch behavior byte-for-byte compatible.
3. Route each local accepted connection and stdio connection through the open
   protocol before bridging bytes.
4. Preserve listener cleanup, half-close semantics, exit codes, telemetry
   levels, and access-artifact readiness behavior.
5. Run:

   ~~~sh
   mise exec -- go test -race ./cmd/derptun ./pkg/session -run 'Test.*(Open|Connect).*Forward' -count=1
   mise run check:fast
   ~~~
6. Checkpoint as `cli: open scoped derptun forwards`.

## Task 9: Add the restricted child-process proxy

**Files:**

- Create: `pkg/derptunproxy/socks.go`
- Create: `pkg/derptunproxy/socks_test.go`
- Create: `cmd/derptun/run.go`
- Create: `cmd/derptun/run_test.go`
- Modify: `cmd/derptun/root.go`

1. Add protocol tests for SOCKS5 no-auth CONNECT to authorized
   `NAME.derptun.invalid` values and rejection of raw IP, arbitrary DNS,
   localhost, malformed names, BIND, UDP ASSOCIATE, and unavailable names.
2. Implement a loopback-only listener with a callback that opens a named
   Derptun stream. Ignore the requested URL port after validating it is
   non-zero.
3. Add command tests for `--` parsing, child environment, inherited stdio,
   signal/cancellation propagation, listener readiness, cleanup, and exact
   child exit status.
4. Set only `ALL_PROXY` and `all_proxy` in the child environment. Do not expose
   a token or general proxy through environment variables.
5. Run:

   ~~~sh
   mise exec -- go test -race ./pkg/derptunproxy ./cmd/derptun -run 'Test.*(SOCKS|Run)' -count=1
   mise run check:fast
   ~~~
6. Checkpoint as `derptun: run commands through scoped forwards`.

## Task 10: Add revocation CLI management

**Files:**

- Modify: `cmd/derptun/token.go`
- Modify: `cmd/derptun/token_test.go`
- Modify: `pkg/derptun/revocation.go`
- Modify: `pkg/derptun/revocation_test.go`

1. Add failing tests for creating, extending, deduplicating, and atomically
   replacing a mode-0600 revocation file from a version 3/4 client token.
2. Implement `derptun token revoke --token-file CLIENT --revocation-file PATH`.
   Reject server and legacy client credentials. Print only the lowercase
   TokenID and destination path.
3. Preserve the original file when decode, permission, fsync, close, or rename
   fails.
4. Run focused CLI and package tests, then `mise run check:fast`.
5. Checkpoint as `cli: manage derptun client revocations`.

## Task 11: Inspection, artifacts, docs, and compatibility regression

**Files:**

- Modify the package inspection models introduced by the cross-product plan
- Modify: `docs/derp/derptun.md`
- Modify: `docs/derp/client-runtime.md`
- Modify: `README.md`
- Modify: `cmd/derptun/depaware.txt` through its generator

1. Extend redacted inspection with forward names and limits for a server, and
   signed scope names plus TokenID for a client. Never include targets in
   client inspection.
2. Extend access artifacts with the selected forward name, not the complete
   server table.
3. Document migration-free coexistence, least-privilege examples, revocation,
   non-loopback risk, `.derptun.invalid`, and exact failure behavior.
4. Run the repository's dependency-awareness generator rather than editing the
   generated file by hand.
5. Prove all v1/v2 package and command golden tests still pass.
6. Run:

   ~~~sh
   mise exec -- go test ./pkg/derptun ./pkg/session ./cmd/derptun
   mise run vuln
   mise run smoke-local
   mise run check:fast
   ~~~
7. Checkpoint as `docs: document scoped derptun services`.

## Task 12: Remote and final verification

1. Run forward and reverse remote smoke with one v1 client and two disjoint v3
   clients. Confirm relay-first and direct-upgrade behavior, correct targets,
   unauthorized rejection, and cleanup on both hosts.
2. Exercise active revocation and verify the client cannot reconnect.
3. Run the restricted command proxy against an HTTP service and confirm an
   arbitrary destination is rejected.
4. Run the full race-sensitive packages and exhaustive repository gate:

   ~~~sh
   mise exec -- go test -race ./pkg/derptun ./pkg/derptunproxy ./pkg/rendezvous ./pkg/session ./cmd/derptun
   mise run check
   ~~~
5. Inspect `but status` and ensure the branch contains only this plan's work.
   Do not push or land without explicit user authorization.

## Stop Conditions

Stop and return to design review if implementation would require any of the
following:

- assigning named-forward meaning to versions 1 or 2;
- sending server targets to clients;
- allowing arbitrary SOCKS destinations or UDP;
- admitting transport state before scope proof verification;
- weakening the one-active-client Derptun rule;
- adding a remote database or control plane for revocation;
- changing the production transport default.
