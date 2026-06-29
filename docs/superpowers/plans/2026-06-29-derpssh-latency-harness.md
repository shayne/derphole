# derpssh latency harness implementation plan

> **For agentic workers:** REQUIRED SUB-SKILLS: Use `superpowers:test-driven-development` for transport changes and `superpowers:executing-plans` while executing. Update each checkbox as it is completed.

**Goal:** Add an autonomous latency harness and reduce derpssh input latency toward the standard SSH baseline.

**Primary hypothesis:** derptun mux writes currently behave like stop-and-wait. Consecutive small writes on a stream wait for cumulative ACKs before the next frame is sent, which can add at least one network RTT to interactive input.

## Task 1: Preserve the approved design

**Files:**

- `docs/superpowers/specs/2026-06-29-derpssh-latency-harness-design.md`
- `docs/superpowers/plans/2026-06-29-derpssh-latency-harness.md`

**Steps:**

- [x] Record the user-approved design and acceptance criteria.
- [x] Keep the scope explicit: no release tag.

**Verification:**

- [x] Files are present and only document the current derpssh latency work.

## Task 2: Add a failing mux pipelining regression test

**Files:**

- `pkg/derptun/mux_test.go`

**Steps:**

- [x] Add a test that opens a mux stream over a manually controlled carrier.
- [x] Withhold the ACK for the first data frame.
- [x] Write a second small payload.
- [x] Assert the second data frame arrives before the first ACK is sent.
- [x] Run the focused test and confirm it fails on current code.

**Verification:**

```sh
mise exec -- go test ./pkg/derptun -run TestMuxPipelinesSmallWritesWithoutWaitingForAck -count=1
```

## Task 3: Pipeline mux data frames

**Files:**

- `pkg/derptun/mux.go`
- `pkg/derptun/mux_test.go`

**Steps:**

- [x] Replace the single pending write slot with an ordered unacked write queue.
- [x] Copy payload bytes into the queue before sending so reconnect replay can resend them.
- [x] Make `sendChunk` return after the data frame is written instead of waiting for ACK.
- [x] On cumulative ACK, remove all fully acknowledged queued writes.
- [x] On carrier replacement, replay open streams and all still-unacked data frames in stream order.
- [x] Preserve existing duplicate-delivery and failed-delivery semantics.

**Verification:**

```sh
mise exec -- go test ./pkg/derptun -run TestMux -count=1
```

## Task 4: Add standalone latency command

**Files:**

- `cmd/derpssh-latency/main.go`
- supporting package files if the command grows beyond a small main package
- `.mise.toml` if a convenience task is useful
- `docs/benchmarks.md`

**Steps:**

- [x] Add `run`, `compare`, and hidden helper modes.
- [x] Implement SSH baseline probing against `--remote`.
- [x] Implement derptun mux stream echo probing.
- [x] Emit `summary.json`, `samples.jsonl`, and `events.jsonl`.
- [x] Include enough metadata to make before/after runs comparable.
- [x] Document the harness in `docs/benchmarks.md`.

**Verification:**

```sh
mise exec -- go run ./cmd/derpssh-latency run --remote ubuntu@derphole-testing --samples 20 --warmup 5 --out .tmp/latency/smoke
mise exec -- go run ./cmd/derpssh-latency compare .tmp/latency/smoke .tmp/latency/smoke
```

## Task 5: Run local verification

**Steps:**

- [x] Run focused mux tests.
- [x] Run all derptun tests.
- [x] Run full Go tests.
- [x] Build all local binaries.

**Verification:**

```sh
mise exec -- go test ./pkg/derptun -count=1
mise run test
mise run build
```

## Task 6: Run live latency feedback loop

**Remote:**

```sh
ubuntu@derphole-testing
```

**Steps:**

- [x] Run the harness against the remote host.
- [x] Capture SSH baseline and derptun diagnostics.
- [x] If derptun remains much slower than SSH, inspect the next largest contributor.
- [x] Repeat until latency is close enough to SSH to justify landing or until a clearly documented blocker remains.

**Verification:**

- [x] `summary.json` contains SSH and derptun measurements.
- [ ] Final response reports p50/p95 and the remaining gap.

## Task 7: Land and push

**Steps:**

- [ ] Run `but pull --check`.
- [ ] Commit this session's changes on a dedicated GitButler branch.
- [ ] Land the final commit on local `main` and `origin/main`.
- [ ] Verify local `main`, `origin/main`, and `git ls-remote origin refs/heads/main`.
- [ ] Do not tag a release.

**Verification:**

```sh
git ls-remote origin refs/heads/main
```
