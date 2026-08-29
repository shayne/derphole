# Tailcat-Derived Magicsock Carrier Experiment Implementation Plan

> Execute only as an experimental, build-tagged branch. Use TDD, keep the
> production transport default unchanged, and remove the experiment if it
> satisfies neither promotion path in the approved design.

**Goal:** Determine with correctness, topology, performance, and ownership
evidence whether upstream magicsock improves long-lived Derptun app-mux and
Derpssh recovery enough to justify a separate production design.

**Design:** [Tailcat-derived transport modernization, Milestone 4](../specs/2026-08-29-tailcat-derived-transport-modernization-design.md#milestone-4-tailcat-derived-magicsock-carrier-experiment)

**Reference snapshot:** Tailcat commit `88929418b1a3f3c74904a3136d6a9e87b1b5b9bb`
is research evidence only. Do not import the Tailcat module or copy its
`reflect`/`unsafe` TCP-drain mechanism.

## Task 1: Establish build-tag and packaging isolation

**Files:**

- Create: `internal/magicsockcarrier/carrier_stub.go`
- Create: `internal/magicsockcarrier/carrier_experiment.go`
- Create: `internal/magicsockcarrier/carrier_test.go`
- Modify: `.mise.toml`
- Modify: `tools/packaging/build-release-assets.sh`
- Modify: `tools/packaging/build-vendor.sh`

1. Add a failing untagged test for `ErrExperimentUnavailable` and a tagged
   compile test for the concrete API from the design.
2. Put every Tailscale engine/netstack import in files guarded by
   `//go:build derphole_magicsock_experiment`. Keep the untagged stub free of
   those imports.
3. Add `experiment:build` and `experiment:build-linux-amd64` mise tasks. They
   write clearly suffixed binaries under `dist/experimental/` and add the build
   tag explicitly.
4. Add release-script assertions that fail if an experimental binary or build
   tag enters normal release assembly.
5. Verify both build graphs:

   ~~~sh
   mise exec -- go test ./internal/magicsockcarrier -count=1
   mise exec -- go test -tags derphole_magicsock_experiment ./internal/magicsockcarrier -count=1
   mise run build
   mise run experiment:build
   ~~~
6. Checkpoint as `experiment: isolate magicsock carrier builds`.

## Task 2: Implement authenticated admission codecs first

**Files:**

- Create: `internal/magicsockcarrier/admission.go`
- Create: `internal/magicsockcarrier/admission_test.go`
- Create: `internal/magicsockcarrier/testdata/hello-v1.hex`
- Create: `internal/magicsockcarrier/testdata/ack-v1.hex`
- Create: `internal/magicsockcarrier/testdata/bind-v1.hex`

1. Write literal byte-golden tests for hello, acknowledgment, and TCP bind
   prelude using fixed credentials and keys.
2. Add negative tests for every length, version, source-key, session, expiry,
   proof, nonce, node-key, disco-key, and MAC check in the exact validation
   order from the design.
3. Implement bounded encode/decode functions over byte slices. Check the 4 KiB
   bound before allocation and use `hmac.Equal` for every authenticator.
4. Reconstruct a detached `derptun.ClientCredential` and call the existing
   verifier; do not duplicate credential validation.
5. Add fuzz targets for all three frames and run them for ten seconds each.
6. Run:

   ~~~sh
   mise exec -- go test -tags derphole_magicsock_experiment ./internal/magicsockcarrier -run 'Test.*(Hello|Ack|Bind|Admission)' -count=1
   mise exec -- go test -tags derphole_magicsock_experiment ./internal/magicsockcarrier -run '^$' -fuzz 'Fuzz.*Frame' -fuzztime 10s
   ~~~
7. Checkpoint as `experiment: authenticate magicsock admission`.

## Task 3: Build a cleanup-safe Tailscale subsystem owner

**Files:**

- Create: `internal/magicsockcarrier/system_experiment.go`
- Create: `internal/magicsockcarrier/system_test.go`

1. Define narrow local interfaces for engine, magicsock, netstack, netmon, and
   watcher close/start operations. Write fault-injection tests that fail each
   construction stage in turn and assert reverse-order cleanup.
2. Add tests for idempotent close, no constructor-retained request context,
   bounded goroutine exit, and repeated start/fail/close returning to baseline
   goroutine/file-descriptor counts.
3. Implement a cleanup stack and one lifecycle owner. Every goroutine must be
   in its wait group and observe the owner context or close channel.
4. Create the userspace engine with `DERPAppName: "derphole"`, a cryptographic
   `ForceDiscoKey`, and injected DERP hooks. Never use Tailcat's application
   names or node-key-to-disco-key conversion.
5. Create/start netstack only after engine construction is owned by the cleanup
   stack. Expose no upstream concrete types outside this file.
6. Do not add `netns.SetEnabled(false)` yet. Make the test prove engine setup
   remains isolated without that global mutation; if upstream requires it,
   record the blocker before proceeding.
7. Run tagged race tests and checkpoint as
   `experiment: own magicsock carrier lifecycle`.

## Task 4: Add deterministic userspace identity and filters

**Files:**

- Create: `internal/magicsockcarrier/identity.go`
- Create: `internal/magicsockcarrier/identity_test.go`
- Modify: `internal/magicsockcarrier/system_experiment.go`

1. Add tests for deterministic node-key-to-ULA addressing, server/client
   separation, no host-route installation, fixed carrier port, and rejection
   of all non-carrier TCP and UDP traffic.
2. Implement the derivation behind package-owned functions rather than
   exposing upstream prefix types.
3. Configure a filter that admits only inbound TCP SYN traffic to the fixed
   server userspace address and carrier port. Add packet-level tests for
   source/destination/protocol/port variations.
4. Checkpoint as `experiment: confine userspace carrier traffic`.

## Task 5: Authenticate unknown peers over DERP before admission

**Files:**

- Create: `internal/magicsockcarrier/derp_experiment.go`
- Create: `internal/magicsockcarrier/derp_test.go`
- Modify: `internal/magicsockcarrier/system_experiment.go`

1. Write a fake DERP hook test proving malformed, expired, replayed,
   source-mismatched, or bad-MAC hellos do not update the netmap or lazy
   WireGuard configuration.
2. Add success tests that admit exactly the authenticated ephemeral node key,
   bind its independent disco key and derived userspace address, and return an
   acknowledgment bound to the nonce and both node keys.
3. Implement `OnDERPRecv` classification so non-experiment packets are passed
   to normal magicsock processing. Silently drop invalid experiment packets and
   expose only a redacted rejection class in network-debug.
4. Enforce eight pending peers, 64 recent nonces, a 30-second pending lifetime,
   and one active client. Use an injected clock and one owner timer loop.
5. Retry hello sends only within the four-second bound and respect caller
   cancellation on every send.
6. Run tagged race tests and checkpoint as
   `experiment: gate dynamic magicsock peers`.

## Task 6: Use stock encrypted endpoint discovery

**Files:**

- Create: `internal/magicsockcarrier/discovery_experiment.go`
- Create: `internal/magicsockcarrier/discovery_test.go`
- Modify: `internal/magicsockcarrier/derp_experiment.go`

1. Add tests that collect, normalize, sort, and deduplicate engine endpoints,
   marshal `disco.CallMeMaybe`, and call `SendDERPPacketTo` for the authenticated
   peer and selected region.
2. Add tests for no endpoints, endpoint churn, duplicate events, send failure,
   cancellation, and a late event after close.
3. Implement with stable upstream disco types and magicsock handling. Do not
   introduce a custom punch or ping protocol.
4. Capture direct/relay transition observations through an injected observer,
   not by parsing logs.
5. Run tagged race tests and checkpoint as
   `experiment: advertise stock magicsock endpoints`.

## Task 7: Bind authenticated netstack TCP connections

**Files:**

- Create: `internal/magicsockcarrier/tcp_experiment.go`
- Create: `internal/magicsockcarrier/tcp_test.go`
- Modify: `internal/magicsockcarrier/carrier_experiment.go`

1. Add tests for the five-second bind deadline, source-address-to-peer lookup,
   nonce/key/session mismatch, truncation, extra bytes, invalid MAC, and valid
   delivery.
2. Ensure invalid TCP connections are closed before they reach `Accept` and do
   not consume the active-carrier slot.
3. Implement `Server.Accept` and `Client.Dial` through exported netstack APIs
   only. Do not use `reflect`, `unsafe`, or a private gVisor field.
4. Add half-close, reset, context cancellation, and reconnect tests over a fake
   in-memory carrier.
5. If clean close cannot be achieved through exported APIs, stop and write an
   upstream API gap note; do not port Tailcat's `DrainTCP` workaround.
6. Checkpoint as `experiment: bind authenticated userspace tcp`.

## Task 8: Expose detached path observations

**Files:**

- Create: `internal/magicsockcarrier/observe.go`
- Create: `internal/magicsockcarrier/observe_test.go`
- Modify: `internal/magicsockcarrier/carrier_experiment.go`

1. Add tests for unknown-to-relay, relay-to-direct, direct-to-relay, RTT-only
   updates, bounded event buffering, slow consumers, cancellation, and no raw
   address fields in JSON.
2. Implement immutable `Snapshot` values and transition-only `Events`.
3. Put raw endpoint diagnostics behind a separate network-debug method whose
   return type has no JSON tags.
4. Run tagged race tests and checkpoint as
   `experiment: observe magicsock path transitions`.

## Task 9: Add like-for-like Derptun app-mux adapters

**Files:**

- Create: `pkg/session/derptun_experimental_transport.go`
- Create: `pkg/session/derptun_experimental_transport_stub.go`
- Create: `pkg/session/derptun_experimental_transport_test.go`
- Modify: `pkg/session/derptun_app.go`
- Modify: `pkg/session/derptun_app_test.go`
- Modify: `pkg/derptun/mux.go`

1. Add an internal transport enum with `quic-native`, `quic-mux`, and
   `magicsock`. Untagged code accepts only production behavior and returns
   `ErrExperimentUnavailable` for experiment modes.
2. Write tests that quic-mux wraps one current authenticated QUIC stream below
   the existing `derptun.Mux`, while magicsock passes one authenticated
   userspace TCP connection below the same mux.
3. Add carrier replacement tests for both modes using the same stream workload.
   Prove open streams, ACK state, and pending data behave identically.
4. Keep normal `DerptunServe`, `DerptunOpen`, and `DerptunConnect` on native
   striped QUIC. The adapter is for the app API and experiment harness only.
5. Run untagged and tagged focused race tests and checkpoint as
   `experiment: compare derptun app mux carriers`.

## Task 10: Add experiment-only CLI selection

**Files:**

- Create: `cmd/derptun/experiment_transport.go`
- Create: `cmd/derptun/experiment_transport_stub.go`
- Create: `cmd/derptun/experiment_transport_test.go`
- Create: `cmd/derpssh/experiment_transport.go`
- Create: `cmd/derpssh/experiment_transport_stub.go`
- Create: `cmd/derpssh/experiment_transport_test.go`

1. Add tagged tests for the exact
   `--experimental-transport=quic-native|quic-mux|magicsock` flag and untagged
   tests proving it is unavailable from standard help and binaries.
2. Require both endpoints to be launched explicitly with the same mode. Do not
   write the mode into existing credentials or silently retry another mode.
3. Wire Derptun app serving/dialing first. Add Derpssh only after the lower-level
   correctness tests pass, and keep approval, role, terminal, and chat paths
   unchanged.
4. Emit selected transport and redacted transitions at verbose level. Raw
   endpoint details require network-debug.
5. Run command and session tests in both build modes and checkpoint as
   `experiment: expose app mux carrier selection`.

## Task 11: Make probe reports transport-aware

**Files:**

- Modify: `cmd/derphole-probe/matrix.go`
- Modify: `cmd/derphole-probe/matrix_test.go`
- Modify: `pkg/probe/report.go`
- Modify: `pkg/probe/report_test.go`
- Modify: `pkg/probe/summary.go`
- Modify: `pkg/probe/summary_test.go`

1. Add failing tests for `--tools derptun`, repeatable transports, invalid
   transport/tool combinations, and grouping by tool/host/direction/transport.
2. Add `Transports` to matrix config and `Transport` to `matrixSeries` and
   comparisons. Normalize missing legacy report values to each tool's current
   production transport.
3. Add footer parsing for transport, relay connection time, direct-selection
   time, upgrades, fallbacks, CPU, RSS, goroutines, descriptors, and binary
   size. Preserve old report decoding.
4. Ensure baseline comparisons never pool or compare different transports.
5. Run:

   ~~~sh
   mise exec -- go test ./pkg/probe ./cmd/derphole-probe -run 'Test.*(Transport|Matrix|Report|Summary)' -count=1
   mise run check:fast
   ~~~
6. Checkpoint as `probe: compare derptun carrier transports`.

## Task 12: Add safe forward/reverse experiment harnesses

**Files:**

- Create: `scripts/derptun-carrier-benchmark.sh`
- Create: `scripts/derptun-carrier-benchmark-reverse.sh`
- Create: `scripts/derptun-carrier-benchmark_test.go`
- Modify: `docs/benchmarks.md`
- Modify: `.mise.toml`

1. Read and reuse the storage preflight, exact process identity, readiness,
   checksum, resource sampling, and cleanup patterns in the existing promotion
   scripts. Add harness tests before the shell implementation.
2. Exercise the same payload and Derptun app-mux workload for quic-mux and
   magicsock. Exercise equivalent target/identity setup for quic-native.
3. Produce every required benchmark footer even on failure, with a truthful
   success value and cleanup result.
4. Add topology controls for UDP blocked, IPv6 preference, interface change,
   and suspend/resume only where the host supports them. Mark unsupported
   scenarios; never count them as passes.
5. Keep all output and staging under preflighted explicit roots and remove it
   after each case. Do not assume `/tmp` has payload plus working capacity.
6. Add mise tasks for one case and the full experimental matrix. Do not add
   them to release or normal check tasks.
7. Run harness unit tests and a small local payload before any remote matrix.
8. Checkpoint as `bench: measure derptun carrier experiment`.

## Task 13: Execute correctness and resource gates

1. Run 100 connect/authenticate/stream/close cycles for quic-mux and magicsock.
2. Run malformed, expired, replayed-from-another-node, bad-MAC, and TCP-bind
   rejection campaigns while sampling peers, goroutines, descriptors, and RSS.
3. Run interface-change, suspend/resume, DERP interruption, and carrier
   replacement tests. Verify active mux streams meet the approved continuity
   expectations.
4. Run:

   ~~~sh
   mise exec -- go test -race -tags derphole_magicsock_experiment ./internal/magicsockcarrier ./pkg/derptun ./pkg/session ./cmd/derptun ./cmd/derpssh
   mise run build
   mise run experiment:build
   mise run vuln
   mise run check
   ~~~
5. Record binary size, idle RSS, transfer CPU, goroutine baseline, descriptor
   baseline, and cleanup results. Any mandatory gate failure stops before the
   remote performance matrix.

## Task 14: Run the topology matrix and write the keep/remove decision

**Files:**

- Create: `docs/experiments/derptun-magicsock-carrier-2026-08-29.md`

1. Preflight every configured host for binary architecture, SSH identity,
   available storage plus working overhead, tools, and controllable topology.
2. Run ten iterations in both directions for quic-native, quic-mux, and
   magicsock in every supported required scenario.
3. Compare magicsock with quic-mux for architectural attribution and with
   quic-native for product acceptability. Apply every numeric mandatory gate
   from the design mechanically.
4. Name the concrete Derphole traversal files/state machines that a production
   upstream carrier would delete. Do not count an adapter beside retained
   duplicate traversal as an internal benefit.
5. Write one evidence-backed result:

   - **remove:** neither promotion path passed; delete the experiment branch;
   - **retain for upstream work:** mandatory gates passed, but a named upstream
     API blocker prevents production design;
   - **propose production design:** mandatory gates and at least one product or
     internal promotion path passed.

6. A passing result authorizes only a new production negotiation specification.
   It does not change defaults, packaging, or credentials.

## Stop Conditions

Stop the experiment immediately if it requires:

- importing Tailcat as a production dependency;
- using Tailcat's DERP application names;
- `reflect` or `unsafe` access to Tailscale/gVisor internals;
- admitting a peer before Derptun credential verification;
- a process-wide netns change that cannot be isolated or proven harmless;
- a production token change or implicit transport fallback;
- retaining both upstream and current traversal indefinitely without a
  measured product benefit.
