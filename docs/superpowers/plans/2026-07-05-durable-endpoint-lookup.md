# Durable Endpoint Lookup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in durable service-name lookup for persistent `derptun` and `derpssh` workflows without changing one-shot `derphole` transfers.

**Architecture:** Add a small resolver/registry layer that maps a user-chosen service name to an existing dial artifact: a derptun client token with the `DT1` prefix or a derpssh invite with the `DSH1` prefix. Lookup finds bearer credentials; existing tokens/invites still authorize sessions. The first implementation is local/file-based only, with interfaces for future resolvers and no hosted control plane.

**Tech Stack:** Go, `pkg/derptun` tokens, `pkg/derpssh/session` invites, `yargs`, JSON file registry, `mise`, GitButler.

---

## Branch

Use GitButler branch `codex/durable-endpoint-lookup`.

Run before editing:

```bash
but status -fv
but pull --check
but branch new codex/durable-endpoint-lookup
mise exec -- go test ./cmd/derptun ./cmd/derpssh ./pkg/derptun ./pkg/derpssh/session ./pkg/session -count=1
```

Expected: no active branch owns `cmd/derptun`, `cmd/derpssh`, `pkg/endpointlookup`, `README.md`, or derptun/derpssh token/session files.

## File Structure

- Create `pkg/endpointlookup/lookup.go`: `Kind`, `Record`, `RecordSummary`, `Resolver`, `Publisher`, validation, redacted summaries.
- Create `pkg/endpointlookup/file.go`: local JSON `FileRegistry` with atomic writes, `0700` parent dirs, `0600` files.
- Create `pkg/endpointlookup/file_test.go`: validation, round trip, expiration, redaction, remove, file mode tests.
- Create `cmd/derptun/service.go`: `derptun service set|list|rm` for client tokens only.
- Modify `cmd/derptun/root.go`, `open.go`, `connect.go`, `serve.go`, `token_source.go`, tests.
- Create `cmd/derpssh/service.go`: `derpssh service set|list|rm` for invites.
- Modify `cmd/derpssh/root.go`, `connect.go`, `share.go`, tests.
- Modify `cmd/derphole/root_test.go`: no-regression assertion that one-shot CLI does not expose lookup.
- Modify `README.md`: optional service lookup docs and security note.

## Task 1: Core Resolver And File Registry

**Files:**
- Create: `pkg/endpointlookup/lookup.go`
- Create: `pkg/endpointlookup/file.go`
- Create: `pkg/endpointlookup/file_test.go`

- [ ] **Step 1: Write failing tests**

Create tests:

```go
func TestValidateName(t *testing.T)
func TestFileRegistryRoundTripDerptunToken(t *testing.T)
func TestFileRegistryRejectsExpiredRecord(t *testing.T)
func TestFileRegistryListRedactsValues(t *testing.T)
func TestFileRegistryRemove(t *testing.T)
func TestFileRegistryWritesPrivateMode(t *testing.T)
```

Name validation allows `web`, `alpha-ssh`, `prod.api`, `home_lab_1`, and rejects empty, path traversal, slash, leading dot, leading dash, spaces, and names longer than 128 chars.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./pkg/endpointlookup -count=1
```

Expected: FAIL because package does not exist.

- [ ] **Step 3: Add resolver types**

Define:

```go
type Kind string
const (
	KindDerptunClientToken Kind = "derptun-client-token"
	KindDerpsshInvite Kind = "derpssh-invite"
)

type Record struct { Version int; Name string; Kind Kind; Value string; CreatedUnix int64; ExpiresUnix int64 }
type RecordSummary struct { Name string; Kind Kind; CreatedUnix int64; ExpiresUnix int64; Display string }
type Resolver interface { Resolve(context.Context, string, Kind) (Record, error) }
type Publisher interface { Publish(context.Context, Record) error; Remove(context.Context, string) error; List(context.Context) ([]RecordSummary, error) }
```

Add `ErrNotFound`, `ErrInvalidName`, `ErrInvalidKind`, `ErrExpired`, `ValidateName`, `ValidateKind`, `NewRecord`, `Record.Expired`, `RedactedSummary`.

- [ ] **Step 4: Add file registry**

Implement `FileRegistry{Path string, Now func() time.Time}` with `Resolve`, `Publish`, `Remove`, `List`. Read/write JSON atomically through a temp file and `os.Rename`. Create parent directory `0700`, registry file `0600`. `List` must never expose record `Value`.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/endpointlookup/lookup.go pkg/endpointlookup/file.go pkg/endpointlookup/file_test.go
mise exec -- go test ./pkg/endpointlookup -count=1
but status -fv
but commit -m "endpointlookup: add local registry"
```

Expected: PASS.

## Task 2: `derptun service`

**Files:**
- Create: `cmd/derptun/service.go`
- Modify: `cmd/derptun/root.go`
- Modify: `cmd/derptun/open.go`
- Modify: `cmd/derptun/connect.go`
- Modify: `cmd/derptun/serve.go`
- Modify: `cmd/derptun/token_source.go`
- Modify: `cmd/derptun/command_test.go`
- Modify: `cmd/derptun/root_test.go`

- [ ] **Step 1: Write failing CLI tests**

Add tests:

```go
func TestRunServiceSetAndOpenService(t *testing.T)
func TestRunOpenRejectsServiceWithTokenSource(t *testing.T)
func TestRunConnectServicePreservesPayload(t *testing.T)
func TestRunServeRegisterRequiresPersistentServerToken(t *testing.T)
```

The tests must verify service set stores a client token, `open --service` resolves it, `connect --service --stdio` preserves stdin, and `serve --register` fails unless a persistent server token source is supplied.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./cmd/derptun -run 'TestRunServiceSetAndOpenService|TestRunOpenRejectsServiceWithTokenSource|TestRunConnectServicePreservesPayload|TestRunServeRegisterRequiresPersistentServerToken' -count=1
```

Expected: FAIL due unknown command/flags.

- [ ] **Step 3: Implement command**

Add `derptun service set NAME (--token TOKEN|--token-file PATH|--token-stdin) [--registry PATH]`, `service list`, and `service rm`. Validate with existing client token validation, decode expiry, store only `KindDerptunClientToken`, and never accept server tokens.

- [ ] **Step 4: Wire root/open/connect/serve**

Add `service` to root registry. Add `--service` and `--registry` to `open` and `connect`; service is mutually exclusive with token sources. Add `--register` and `--registry` to `serve`; `--register` requires a persistent server token source and publishes the derived client token.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w cmd/derptun/service.go cmd/derptun/root.go cmd/derptun/open.go cmd/derptun/connect.go cmd/derptun/serve.go cmd/derptun/token_source.go cmd/derptun/*_test.go
mise exec -- go test ./cmd/derptun -run 'TestRunServiceSetAndOpenService|TestRunOpenRejectsServiceWithTokenSource|TestRunConnectServicePreservesPayload|TestRunServeRegisterRequiresPersistentServerToken' -count=1
but status -fv
but commit -m "derptun: add local service lookup"
```

Expected: PASS.

## Task 3: `derpssh service`

**Files:**
- Create: `cmd/derpssh/service.go`
- Modify: `cmd/derpssh/root.go`
- Modify: `cmd/derpssh/connect.go`
- Modify: `cmd/derpssh/share.go`
- Modify: `cmd/derpssh/connect_test.go`
- Modify: `cmd/derpssh/share_test.go`

- [ ] **Step 1: Write failing tests**

Add:

```go
func TestRunConnectServiceResolvesInvite(t *testing.T)
func TestRunConnectRejectsServiceAndInvite(t *testing.T)
func TestRunShareDoesNotRegisterByDefault(t *testing.T)
func TestRunShareRegisterWritesInviteRecord(t *testing.T)
```

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./cmd/derpssh -run 'TestRunConnectServiceResolvesInvite|TestRunConnectRejectsServiceAndInvite|TestRunShareDoesNotRegisterByDefault|TestRunShareRegisterWritesInviteRecord' -count=1
```

Expected: FAIL due unknown command/flags.

- [ ] **Step 3: Implement command**

Add `derpssh service set NAME INVITE [--registry PATH]`, `service list`, and `service rm`, where `INVITE` is an existing derpssh invite string with the `DSH1` prefix. Validate invite through existing derpssh invite decode, derive expiry from embedded derptun client token, store `KindDerpsshInvite`, never print invite values in list.

- [ ] **Step 4: Wire connect/share**

Add `--service` and `--registry` to connect. `--service` and a positional invite are mutually exclusive. Add `--register` and `--registry` to share. Share registration is explicit only and does not make sessions durable beyond the running host.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w cmd/derpssh/service.go cmd/derpssh/root.go cmd/derpssh/connect.go cmd/derpssh/share.go cmd/derpssh/*_test.go
mise exec -- go test ./cmd/derpssh -run 'TestRunConnectServiceResolvesInvite|TestRunConnectRejectsServiceAndInvite|TestRunShareDoesNotRegisterByDefault|TestRunShareRegisterWritesInviteRecord' -count=1
but status -fv
but commit -m "derpssh: add local service lookup"
```

Expected: PASS.

## Task 4: One-Shot Derphole Non-Regression

**Files:**
- Modify: `cmd/derphole/root_test.go`
- Optional test-only use: `pkg/session/session_test.go`

- [ ] **Step 1: Add help test**

Add `TestRootHelpDoesNotAdvertiseServiceLookup`, asserting `derphole --help` does not mention `service` or `registry`.

- [ ] **Step 2: Verify**

Run:

```bash
mise exec -- go test ./cmd/derphole -run TestRootHelpDoesNotAdvertiseServiceLookup -count=1
mise exec -- go test ./pkg/session -run 'TestListen|TestSend|TestReceive|TestOffer|TestAttach' -count=1
```

Expected: PASS.

- [ ] **Step 3: Checkpoint**

Run:

```bash
gofmt -w cmd/derphole/root_test.go
but status -fv
but commit -m "test: keep derphole lookup-free"
```

Expected: checkpoint contains only non-regression test changes.

## Task 5: README And Security

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Use README writing constraint**

Before editing `README.md`, use the Caveman skill per `AGENTS.md`; keep prose tight, grammatical, and technical.

- [ ] **Step 2: Document derptun lookup**

After persistent token examples, add a concise local-service example:

```bash
npx -y derptun@latest service set web --token-file client.dt1
npx -y derptun@latest open --service web --listen 127.0.0.1:3001
```

State that the registry is local name-to-token storage, not a hosted control plane.

- [ ] **Step 3: Document derpssh lookup**

After `derpssh connect <invite>`, add:

```bash
npx -y derpssh@latest service set ops-shell <invite>
npx -y derpssh@latest connect --service ops-shell
```

State that the host still approves the guest and the service name only finds the invite.

- [ ] **Step 4: Update security model**

State that registry entries are bearer secrets because they contain derptun client tokens or derpssh invites; list output redacts values; registry file must be protected like token files; no lookup server is contacted by default.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
mise exec -- go test ./cmd/derptun ./cmd/derpssh ./cmd/derphole -count=1
but status -fv
but commit -m "docs: describe local service lookup"
```

Expected: PASS.

## Final Verification

Run:

```bash
mise exec -- go test ./pkg/endpointlookup ./cmd/derptun ./cmd/derpssh ./cmd/derphole ./pkg/derptun ./pkg/derpssh/session ./pkg/session -count=1
mise run test
mise run build
mise run check:hooks
mise run smoke-local
but status -fv
```

Expected: all PASS; one-shot `derphole` does not import or expose endpoint lookup; no manual edits to generated `dist/`.

## Acceptance Criteria

- Local registry is opt-in and file-based.
- `derptun` stores only client tokens, never server tokens.
- `derpssh` stores invites only when explicitly set/registering.
- One-shot `derphole` commands remain unchanged.
- List output redacts bearer values.
- No DNS/Pkarr/HTTP/DHT/mDNS/default control-plane dependency is added.

## Self-Review Notes

- Spec coverage: opt-in local registry, resolver interfaces, derptun/derpssh CLI, derphole non-regression, docs, and security are covered.
- Red-flag scan: clean for unresolved markers, ellipses, and incomplete implementation steps.
- Type consistency: `endpointlookup.KindDerptunClientToken`, `KindDerpsshInvite`, `FileRegistry`, `Record`, and `RecordSummary` are introduced before use.
