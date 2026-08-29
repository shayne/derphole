# Tailcat-Derived Cross-Product Operability Implementation Plan

> **For agentic workers:** Implement one task at a time with test-driven development. Use GitButler for every version-control write and keep this stack separate from the completed transport-foundation stack until review.

**Goal:** Add safe token inspection, authenticated connectivity diagnosis, network-debug telemetry, and automation-ready access files across derphole, derptun, and derpssh without exposing credentials or changing their wire formats.

**Architecture:** Secret-bearing packages own redacted metadata. `pkg/session` owns the authenticated Derptun transport probe; Derpssh wraps it without entering the app mux. A small internal CLI input package enforces the same one-source rule everywhere. `pkg/accessartifact` owns one versioned JSON document and one private atomic writer used by all three CLIs.

**Spec:** `docs/superpowers/specs/2026-08-29-tailcat-derived-transport-modernization-design.md`, Milestones 2A through 2C.

## Global Constraints

- Preserve Derphole v5/v6, Derptun dts1/dts2/DT1/DT2, and Derpssh DSH1 encodings byte-for-byte.
- Never serialize the internal credential structs or return secret-bearing fields from inspection APIs.
- Never print tokens, invites, private keys, bearer/signing secrets, proof MACs, complete identifiers, embedded client credentials, or map URLs.
- Human output goes to stdout; usage and failures go to stderr. Usage exits 2 and operational/validation failures exit 1.
- `--debug-network` is required for raw addresses. `--verbose` remains redacted.
- Doctor/probe opens only the authenticated control connection. It never opens a target stream, host approval, shell, terminal, or chat.
- `--write-access` never accepts `-`, never creates a missing parent directory, and writes mode 0600 through same-directory fsync plus atomic rename.
- Use focused package tests, golden redaction tests, fuzz entry points, `mise run check:fast` during iteration, and `mise run check` once before publication.

---

### Task 1: Centralize one-of secret input handling

**Files:**
- Create: `internal/cliinput/secret.go`
- Create: `internal/cliinput/secret_test.go`
- Inspect and later consume: `cmd/derptun/token_source.go`

**API:**

```go
type SecretSource struct {
	Value     string
	File      string
	FromStdin bool
}

func (s SecretSource) Read(stdin io.Reader) (string, error)
```

- [ ] Write table-driven tests for zero sources, multiple sources, direct value, a mode-0600 fixture file, first-line stdin, CRLF trimming, empty input, oversized input, and unreadable files. Set a 1 MiB bound and never include input content in an error.
- [ ] Run `mise exec -- go test ./internal/cliinput -count=1` and observe the missing package failure.
- [ ] Implement exact-one selection. Read one bounded line from stdin, trim only line terminators and surrounding ASCII whitespace already rejected by token decoders, and return a generic source-specific error.
- [ ] Replace Derptun's existing token-source helper only after its command tests prove unchanged behavior.
- [ ] Run `mise exec -- go test ./internal/cliinput ./cmd/derptun -count=1` and `mise run check:fast`.
- [ ] Checkpoint as `cli: centralize secret input sources` on a dedicated `tailcat-operability` GitButler branch.

### Task 2: Add package-owned redacted inspection metadata

**Files:**
- Modify: `pkg/token/token.go`, `pkg/token/token_test.go`
- Modify: `pkg/derptun/token.go`, `pkg/derptun/client_token.go`, matching tests
- Modify: `pkg/derpssh/session/invite.go`, add `pkg/derpssh/session/invite_inspect_test.go`

**APIs:** Use the exact `Metadata`, `TokenMetadata`, and `InviteMetadata` types and `Inspect`, `InspectToken`, and `InspectInvite` signatures from Milestone 2A.

- [ ] Add fixtures for every current public/custom token version, valid expired input, malformed checksum, unsupported version, invalid route, unknown capability bits, and DSH1 with a known embedded client-token canary.
- [ ] Add a shared test assertion that scans formatted metadata and JSON for every fixture secret and every complete identifier.
- [ ] Run the three focused packages and observe missing inspection APIs.
- [ ] Implement metadata construction inside the owning package after complete structural validation. Truncate identifiers to four lowercase-hex bytes plus `...`; sort capability names in bit order and preserve unknown bits as `unknown-0x%08x`.
- [ ] Ensure expired-but-valid input returns `Expired: true` and no error. Any malformed input returns a zero metadata value and an error.
- [ ] Implement `InspectInvite` by decoding DSH1 and delegating the embedded credential to `derptun.InspectToken`; never return the embedded string.
- [ ] Add fuzz tests for all three inspection entry points, asserting no panic and no known secret in any returned error.
- [ ] Run `mise exec -- go test ./pkg/token ./pkg/derptun ./pkg/derpssh/session -count=1` and `mise run check:fast`.
- [ ] Checkpoint as `token: expose redacted credential metadata`.

### Task 3: Add inspect commands to every product

**Files:**
- Create: `cmd/derphole/token.go`, `cmd/derphole/token_test.go`
- Modify: `cmd/derphole/root.go`
- Modify: `cmd/derptun/token.go`, `cmd/derptun/token_test.go`
- Create: `cmd/derpssh/invite.go`, `cmd/derpssh/invite_test.go`
- Modify: `cmd/derpssh/root.go`

- [ ] Add golden tests for the exact human and schema-version-1 JSON output in the spec. Test exit 0 for valid and expired input, exit 1 for malformed/unreadable input, and exit 2 for source/flag errors.
- [ ] Assert JSON is encoded from command-owned output DTOs rather than directly from package credential or metadata structs.
- [ ] Implement `derphole token inspect`, `derptun token inspect`, and `derpssh invite inspect` with direct/file/stdin sources and `--json`.
- [ ] Keep all secret material out of usage strings, diagnostics, and error wrapping. Reject extra positional arguments.
- [ ] Run `mise exec -- go test ./cmd/derphole ./cmd/derptun ./cmd/derpssh -run 'Test.*Inspect' -count=1` plus each command's root tests.
- [ ] Verify help text from built binaries and checkpoint as `cli: inspect access credentials safely`.

### Task 4: Add a network-debug telemetry level

**Files:**
- Modify: `pkg/telemetry/telemetry.go`, `pkg/telemetry/telemetry_test.go`
- Modify root/config parsing in `cmd/derphole`, `cmd/derptun`, and `cmd/derpssh`
- Modify existing raw-address call sites found by `rg 'transport-direct-path|selected_address|candidate'`

- [ ] Write telemetry matrix tests proving normal, quiet, silent, verbose, and network-debug routing. `Debug` is enabled for verbose and network-debug; `NetworkDebug` writes only for network-debug.
- [ ] Add command parser tests proving `--debug-network` conflicts with every other telemetry-level flag and is visible in help.
- [ ] Implement `LevelNetworkDebug` and `(*Emitter).NetworkDebug`. Preserve current default and verbose output.
- [ ] Move raw selected/candidate address diagnostics from `Debug` to `NetworkDebug`; keep endpoint class, counts, RTT, upgrade, fallback, and reason redacted at `Debug`.
- [ ] Run telemetry and all three command test suites, then scan verbose golden output for IP-address canaries.
- [ ] Checkpoint as `telemetry: gate raw network diagnostics`.

### Task 5: Expose an authenticated Derptun control-plane probe

**Files:**
- Modify: `pkg/session/derptun.go`
- Create: `pkg/session/derptun_probe.go`, `pkg/session/derptun_probe_test.go`
- Reuse: existing claim, transport-manager, QUIC identity, path-snapshot, and path-event helpers

**API:** Implement `DerptunProbeConfig`, `DerptunProbeReport`, and `DerptunProbe` exactly as specified in Milestone 2B. Report fields are detached strings, integers, booleans, and durations only.

- [ ] Add end-to-end fixture tests for accepted relay control, accepted direct promotion, `--force-relay`, invalid/expired credential, active-client claimed rejection, server disappearance, timeout, and immediate normal reconnect after probe cleanup.
- [ ] Add a target spy proving the probe opens no application stream and sends zero bytes to the configured TCP service.
- [ ] Run the focused test and observe the missing API.
- [ ] Factor the minimum existing unexported helpers needed to establish and close the authenticated control connection without exposing `transport.Manager`.
- [ ] Bound the whole operation by the earlier of caller context and `cfg.Timeout`. Resolve the actual route, claim normally, require acceptance, establish authenticated control, snapshot/events, and optionally wait for direct.
- [ ] Count candidate classes without retaining addresses unless `IncludeAddresses` is true. Always close, wait for claim release, and detach the final report before returning.
- [ ] Run `mise exec -- go test ./pkg/session -run 'TestDerptunProbe|TestDerptun.*Claim' -count=1`, the race detector for probe tests, and `mise run check:fast`.
- [ ] Checkpoint as `session: add authenticated Derptun probe`.

### Task 6: Add `derptun probe`

**Files:**
- Create: `cmd/derptun/probe.go`, `cmd/derptun/probe_test.go`
- Modify: `cmd/derptun/root.go`, `cmd/derptun/service.go`

- [ ] Add command tests for direct token/file/stdin input, service-registry lookup, exactly-one source, positive timeout, `--until-direct` versus `--force-relay`, JSON schema omissions, optional addresses, and exit codes.
- [ ] Resolve a service to its client credential before calling `session.DerptunProbe`. Do not reimplement transport logic in `cmd/`.
- [ ] Format the exact bootstrap/authentication/control/path/candidate schema from the spec. Omit unmeasured values and all addresses by default.
- [ ] Add human output that states claim/control success, selected path, upgrade/fallback counts, and timeout reason without secrets.
- [ ] Run `mise exec -- go test ./cmd/derptun -run 'TestProbe' -count=1` and a live local probe followed immediately by a normal connection.
- [ ] Checkpoint as `derptun: add authenticated transport probe`.

### Task 7: Add `derpssh doctor` as a Derptun probe wrapper

**Files:**
- Create: `pkg/derpssh/session/doctor.go`, `pkg/derpssh/session/doctor_test.go`
- Create: `cmd/derpssh/doctor.go`, `cmd/derpssh/doctor_test.go`
- Modify: `cmd/derpssh/root.go`, `cmd/derpssh/service.go`

- [ ] Add tests proving invite/service resolution delegates only the embedded Derptun client credential, no host approval or app-mux frame is sent, and `ApplicationTested` is always false.
- [ ] Implement `Doctor` as the thin wrapper specified in Milestone 2B. It calls `session.DerptunProbe` and owns no alternate network path.
- [ ] Add command parity with Derptun probe, including `--include-addresses`, flag conflicts, timeout, JSON wrapping, and exit codes.
- [ ] Ensure human output ends with `derpssh-application=not-tested`; JSON contains `application.tested: false`.
- [ ] Run `mise exec -- go test ./pkg/derpssh/session ./cmd/derpssh -run 'TestDoctor' -count=1` and existing share/connect tests.
- [ ] Checkpoint as `derpssh: add transport doctor`.

### Task 8: Implement the private atomic access-artifact writer

**Files:**
- Create: `pkg/accessartifact/document.go`, `pkg/accessartifact/document_test.go`

- [ ] Add tests for every schema-v1 kind, missing required fields, unsupported product/kind, invalid timestamps, no useful output, missing parent, final-component symlink, existing permissive file, partial write, fsync/close/rename failure, mode 0600, atomic replacement, and secret-free errors.
- [ ] Run the package test and observe the missing API.
- [ ] Implement `Document.Validate` and `Write`. Marshal before touching the destination. Require an existing parent directory, reject `-`, inspect the final component with `Lstat`, and refuse symlinks.
- [ ] Create a same-directory temporary file, chmod 0600, write all bytes, sync, close, and rename. Never chmod an existing destination to be more permissive; replacement remains 0600.
- [ ] Inject filesystem operations into one private write helper for failure tests instead of mutable package globals.
- [ ] Run package tests with race coverage and checkpoint as `access: write private automation artifacts`.

### Task 9: Add `--write-access` without changing ordinary output

**Files:**
- Modify creation commands in `cmd/derphole`: listen, share, send, ssh invite
- Modify creation/listener commands in `cmd/derptun`: serve, open
- Modify: `cmd/derpssh/share.go`
- Modify matching command tests and end-to-end smoke fixtures

- [ ] For every command, capture current stdout/stderr/status behavior in tests before adding the flag.
- [ ] Add success tests for exact schema/product/kind/access/command/address fields and expiry, plus failure tests that prove an already-open listener/session is closed if writing fails.
- [ ] Add the flag without accepting `-`. Build the document only after the final token, invite, copyable command, or ready address is known.
- [ ] Write the artifact before printing readiness that automation might act on. On failure, close opened resources and return an error that names only the path and operation.
- [ ] Prove ordinary output is byte-for-byte unchanged when the flag is absent and secret values do not appear in access-file errors.
- [ ] Run all three command suites and `mise run smoke-local`.
- [ ] Checkpoint as `cli: write automation-ready access files`.

### Task 10: Document, fuzz, and verify the operability release

**Files:**
- Modify relevant CLI reference docs and `README.md` only after using the repository's required README prose skill
- Add a release note under `docs/releases/` when a release is requested
- Modify this plan only to mark completed steps

- [ ] Document every command, source flag, exit code, JSON schema, redaction boundary, `--debug-network` risk, and access-file permission/lifetime contract.
- [ ] Run all inspection fuzz targets for a bounded CI duration and scan human/JSON golden output for fixture secrets.
- [ ] Run `mise exec -- go test ./pkg/token ./pkg/derptun ./pkg/derpssh/session ./pkg/session ./pkg/accessartifact ./internal/cliinput ./cmd/derphole ./cmd/derptun ./cmd/derpssh -count=1`.
- [ ] Set `REMOTE_HOST` to an explicitly configured test host, then run `mise run vuln`, `mise run smoke-local`, `mise run smoke-remote-derptun`, `mise run smoke-remote-derpssh`, and `mise run check`.
- [ ] Inspect the final GitButler stack for secret fixtures, generated output, machine-specific paths, and unrelated work. Keep it local unless the user explicitly asks to publish or land it.
