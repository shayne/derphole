# Derpcat QUIC Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current inner WireGuard + gVisor payload path with a QUIC stream transport over the existing relay/direct peer transport so `derpcat` can materially exceed the current `~320 Mbps` ceiling.

**Architecture:** Keep the current DERP bootstrap, token claim flow, and direct-upgrade transport manager. Add a new QUIC transport adapter that rides on top of the single-peer datagram transport, first for `listen/send`, then for `share/open`, and finally delete the old payload path once the new path is live-tested.

**Tech Stack:** Go 1.26, `quic-go`, existing `pkg/transport`, existing session/token flow, `mise`, ssh-based live verification against `pve1` and `hetz`.

---

### Task 1: Add QUIC transport adapter primitives

**Files:**
- Create: `pkg/quicpath/adapter.go`
- Create: `pkg/quicpath/adapter_test.go`
- Create: `pkg/quicpath/config.go`
- Modify: `go.mod`
- Modify: `go.sum`
- Test: `pkg/quicpath/adapter_test.go`

- [ ] **Step 1: Write failing adapter tests for packet send, receive, and shutdown**

```go
func TestAdapterDeliversInboundPackets(t *testing.T) { /* fake transport -> ReadFrom */ }
func TestAdapterWriteToUsesTransportSend(t *testing.T) { /* WriteTo -> fake transport */ }
func TestAdapterCloseUnblocksReaders(t *testing.T) { /* Close -> ReadFrom returns net.ErrClosed */ }
```

- [ ] **Step 2: Run the new package tests to confirm failure**

Run: `mise exec -- go test ./pkg/quicpath -count=1`
Expected: FAIL because `pkg/quicpath` does not exist yet.

- [ ] **Step 3: Add `quic-go` and implement the adapter around a narrow transport interface**

```go
type PeerDatagramConn interface {
	SendDatagram([]byte) error
	RecvDatagram(context.Context) ([]byte, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}
```

Implement a `net.PacketConn`-compatible adapter that:
- copies inbound datagrams into caller buffers
- blocks until a datagram or close
- translates shutdown into `net.ErrClosed`
- leaves relay/direct selection entirely below the adapter

- [ ] **Step 4: Run the new package tests and make them pass**

Run: `mise exec -- go test ./pkg/quicpath -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum pkg/quicpath
git commit -m "feat: add quic transport adapter"
```

### Task 2: Teach the transport manager to expose a single-peer datagram endpoint

**Files:**
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/control.go`
- Modify: `pkg/transport/fake_test.go`
- Modify: `pkg/transport/manager_test.go`
- Test: `pkg/transport/manager_test.go`

- [ ] **Step 1: Write failing manager tests for datagram send/receive over relay and direct**

```go
func TestManagerPeerDatagramConnSendsViaCurrentBestPath(t *testing.T) { /* relay first, then direct */ }
func TestManagerPeerDatagramConnReceivesPeerDatagrams(t *testing.T) { /* incoming packet path */ }
func TestManagerPeerDatagramConnSurvivesPathUpgrade(t *testing.T) { /* direct upgrade without reconnect */ }
```

- [ ] **Step 2: Run the transport tests and confirm failure**

Run: `mise exec -- go test ./pkg/transport -count=1`
Expected: FAIL because the new API does not exist.

- [ ] **Step 3: Add a narrow peer-datagram API on top of the existing manager**

Expose a single-peer datagram endpoint that:
- sends via relay until direct is active
- uses the same control and probing loops already in `pkg/transport`
- continues to function across relay/direct transitions
- presents one logical local/remote addr pair to the QUIC layer

- [ ] **Step 4: Run the transport tests and make them pass**

Run: `mise exec -- go test ./pkg/transport -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/transport
git commit -m "feat: expose peer datagram transport"
```

### Task 3: Move `listen/send` to QUIC streams

**Files:**
- Create: `pkg/session/quic_conn.go`
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/listen.go`
- Modify: `pkg/session/send.go`
- Modify: `pkg/session/session_test.go`
- Test: `pkg/session/session_test.go`

- [ ] **Step 1: Write failing session tests for one-shot QUIC payload transfer**

```go
func TestExternalListenSendTransfersPayloadOverQUIC(t *testing.T) { /* listener stdout matches sender stdin */ }
func TestExternalListenSendCanStartRelayAndFinishDirect(t *testing.T) { /* status transitions observed */ }
```

- [ ] **Step 2: Run the targeted session tests and confirm failure**

Run: `mise exec -- go test ./pkg/session -run 'TestExternalListenSend' -count=1`
Expected: FAIL because the old WG overlay is still in use.

- [ ] **Step 3: Implement a QUIC session constructor and switch external `listen/send` to one bidirectional stream**

Implementation requirements:
- dial side: create one QUIC client connection and one stream
- accept side: create one QUIC server connection and accept one stream
- preserve current status emission and teardown behavior
- keep the old code path only where local-only relay tests still need it during migration

- [ ] **Step 4: Run targeted and broader tests**

Run:
- `mise exec -- go test ./pkg/session -run 'TestExternalListenSend' -count=1`
- `mise exec -- go test ./cmd/derpcat ./pkg/session -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/session cmd/derpcat
git commit -m "feat: move listen send to quic streams"
```

### Task 4: Benchmark and live-test Stage 1 against current baseline

**Files:**
- Modify: `scripts/promotion-test.sh`
- Create: `scripts/quic-stdio-bench.sh`
- Modify: `.mise.toml`
- Test: live runs only

- [ ] **Step 1: Add a repeatable QUIC `listen/send` benchmark script**

The script should:
- stage the current Linux binary to a target host
- run `listen` remotely
- send 1 GiB locally
- record status transitions and elapsed time
- print effective Mbps

- [ ] **Step 2: Run local validation for the new script**

Run: `bash ./scripts/quic-stdio-bench.sh pve1 1024`
Expected: completes and prints throughput plus path transitions

- [ ] **Step 3: Run live Stage 1 benchmarks**

Run:
- `bash ./scripts/quic-stdio-bench.sh pve1 1024`
- `bash ./scripts/quic-stdio-bench.sh hetz 1024`

Expected:
- relay-first then direct-upgrade still works
- throughput materially exceeds the prior `~303 Mbps` one-shot baseline

- [ ] **Step 4: Commit benchmark harness changes**

```bash
git add scripts/quic-stdio-bench.sh scripts/promotion-test.sh .mise.toml
git commit -m "test: add quic stdio benchmark harness"
```

### Task 5: Move `share/open` to a single QUIC connection with many streams

**Files:**
- Modify: `pkg/session/share.go`
- Modify: `pkg/session/open.go`
- Modify: `pkg/session/external_share.go`
- Modify: `pkg/session/attach.go`
- Modify: `pkg/session/session_test.go`
- Modify: `cmd/derpcat/share_test.go`
- Modify: `cmd/derpcat/open_test.go`
- Test: `pkg/session/session_test.go`, `cmd/derpcat/share_test.go`, `cmd/derpcat/open_test.go`

- [ ] **Step 1: Write failing tests for concurrent forwarded connections over one QUIC session**

```go
func TestShareOpenForwardsMultipleSequentialConnectionsOverOneQUICSession(t *testing.T) { /* two clients, one claim */ }
func TestShareOpenForwardsConcurrentConnectionsOverOneQUICSession(t *testing.T) { /* N clients, all succeed */ }
func TestShareOpenBackendDialFailureOnlyKillsOneStream(t *testing.T) { /* session stays alive */ }
```

- [ ] **Step 2: Run targeted tests and confirm failure**

Run: `mise exec -- go test ./pkg/session ./cmd/derpcat -run 'TestShare|TestOpen' -count=1`
Expected: FAIL because the old overlay listener path is still in use.

- [ ] **Step 3: Replace the current overlay listener/dial path with one long-lived QUIC connection carrying many streams**

Implementation requirements:
- `share` accepts streams and bridges each to the backend TCP target
- `open` keeps the local listener and opens one QUIC stream per accepted local connection
- session token remains single-claimer
- active stream failure does not kill the whole session

- [ ] **Step 4: Run targeted and broader tests**

Run:
- `mise exec -- go test ./pkg/session ./cmd/derpcat -run 'TestShare|TestOpen' -count=1`
- `mise exec -- go test ./cmd/derpcat ./pkg/session ./pkg/transport ./pkg/quicpath -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/session cmd/derpcat
git commit -m "feat: move share open to quic streams"
```

### Task 6: Remove the old payload overlay and dead code

**Files:**
- Delete: `pkg/wg/netstack/tun.go`
- Delete: `pkg/wg/netstack/tun_test.go`
- Modify: `pkg/wg/device.go`
- Modify: `pkg/wg/wg_test.go`
- Modify: `pkg/session/external_share.go`
- Modify: `pkg/session/external.go`
- Test: package tests touching the removed path

- [ ] **Step 1: Write one failing compile-level cleanup test expectation**

Use the existing package test slices as the safety net:

Run:
- `mise exec -- go test ./pkg/wg ./pkg/session ./cmd/derpcat -count=1`

Expected: FAIL once the old payload path references are partially removed.

- [ ] **Step 2: Delete the unused inner payload overlay code and references**

Remove only code that is no longer used once both Stage 1 and Stage 2 are on QUIC:
- old payload-oriented WG/node overlay plumbing
- old overlay port listener code
- unused netstack payload helpers

- [ ] **Step 3: Run the affected package tests**

Run: `mise exec -- go test ./pkg/wg ./pkg/session ./cmd/derpcat -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: remove legacy payload overlay"
```

### Task 7: Full verification, benchmarking, and ship

**Files:**
- Modify: `README.md`
- Modify: `docs/derp/README.md`
- Modify: `docs/releases/npm-bootstrap.md`
- Test: full suite and live runs

- [ ] **Step 1: Update docs to describe QUIC-based payload transport**

Document:
- relay/direct outer transport unchanged
- payload path now QUIC streams
- any updated performance expectations

- [ ] **Step 2: Run full local verification**

Run:
- `mise run check`
- `mise run test`

Expected: PASS

- [ ] **Step 3: Run full live verification**

Run:
- `bash ./scripts/quic-stdio-bench.sh pve1 1024`
- `bash ./scripts/quic-stdio-bench.sh hetz 1024`
- `./scripts/smoke-remote-share.sh pve1`
- `./scripts/smoke-remote-share.sh hetz`
- a `share/open` iperf run to `pve1`
- a `share/open` throughput run to `hetz`

Expected:
- all sessions still work
- relay-first then direct-upgrade still works
- throughput is materially above the current shipped baseline

- [ ] **Step 4: Commit, push, and tag only if the gain is real**

```bash
git add README.md docs/derp/README.md docs/releases/npm-bootstrap.md scripts .mise.toml
git commit -m "perf: move derpcat payload transport to quic"
git push origin main
```

- [ ] **Step 5: Record final numbers in the completion summary**

Include:
- raw baseline
- old shipped throughput
- new throughput
- path transitions
- CPU observations
