# Linux Topology Simulation Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Linux-only topology simulation suite that proves derphole transport behavior across NAT, relay fallback, direct promotion, changing links, address-family preference, many addresses, and portmap changes on GitHub Actions Ubuntu.

**Architecture:** Build a repo-native simulator using Linux network namespaces, veth pairs, `iptables`, and `tc netem`, with helper processes running `pkg/transport.Manager` inside endpoint namespaces. A Go coordinator owns scenario setup, relays manager control/data messages, drives topology changes, and asserts path transitions. This is inspired by iroh patchbay/netsim but uses Go and Linux tools already available on CI.

**Tech Stack:** Go, `pkg/transport`, Linux network namespaces, `iproute2`, `iptables`, `tc`, Bash, `mise`, GitHub Actions `ubuntu-latest`.

---

## Branch

Use GitButler branch `codex/linux-topology-sim-suite`.

Run before editing:

```bash
but status -fv
but pull --check
but branch new codex/linux-topology-sim-suite
mise run install-githooks
```

Expected: no active branch touches `pkg/toposim`, `scripts/toposim-linux.sh`, `.mise.toml`, or `.github/workflows/checks.yml`. This branch should not modify production `pkg/transport` unless a topology test exposes a confirmed bug; if that happens, stop and write a smaller transport fix plan.

## File Structure

- Create `pkg/toposim/scenario.go`: scenario catalog, node/link/NAT descriptors, expected transitions.
- Create `pkg/toposim/scenario_test.go`: non-root catalog coverage tests.
- Create `pkg/toposim/protocol.go` and `pkg/toposim/protocol_test.go`: line-delimited JSON command/event schema.
- Create `pkg/toposim/coordinator.go` and `pkg/toposim/coordinator_test.go`: helper process orchestration, control forwarding, relay forwarding, wait helpers.
- Create `pkg/toposim/lab_linux.go`: `//go:build linux` namespace/veth/router/NAT/tc primitives.
- Create `pkg/toposim/lab_linux_test.go`: `//go:build linux && toposim` namespace smoke tests.
- Create `pkg/toposim/scenarios_linux_test.go`: `//go:build linux && toposim` scenario tests.
- Create `tools/toposimnode/main.go` and `tools/toposimnode/main_test.go`: helper process running one manager.
- Create `scripts/toposim-linux.sh` and `scripts/toposim_script_test.go`: local/CI wrapper and script contract tests.
- Modify `.mise.toml`: add `toposim` task.
- Modify `.github/workflows/checks.yml`: install networking tools and run `mise run toposim`.

## Task 1: Scenario Catalog And Protocol

**Files:**
- Create: `pkg/toposim/scenario.go`
- Create: `pkg/toposim/scenario_test.go`
- Create: `pkg/toposim/protocol.go`
- Create: `pkg/toposim/protocol_test.go`

- [ ] **Step 1: Write failing catalog tests**

Add `TestScenarioCatalogCoversBacklogItemOne` requiring these exact scenario names:

```text
nat-to-nat-direct
relay-fallback
faster-path-appears
link-outage-replug
many-local-addresses
dual-stack-preference
portmap-change
```

Add `TestCatalogScenariosHaveConcreteAssertions`, asserting each scenario has two nodes, a positive timeout under 90s, and at least one expected relay/direct transition.

- [ ] **Step 2: Write failing protocol tests**

Add JSON round-trip tests for `NodeCommand` and `NodeEvent`, including a peer-control candidate message and a direct path event.

- [ ] **Step 3: Verify red**

Run:

```bash
mise exec -- go test ./pkg/toposim -run 'TestScenarioCatalog|TestCatalogScenarios|TestNode(Command|Event)' -count=1
```

Expected: FAIL because `pkg/toposim` does not exist.

- [ ] **Step 4: Implement catalog/protocol**

Define:

```go
type Scenario struct { Name string; Nodes []NodeSpec; Links []LinkSpec; Actions []ScenarioAction; Expect []ExpectedTransition; Timeout time.Duration; Description string }
type NodeSpec struct { Name string; Namespace string; DirectPort int; InitialCandidates []string; PortmapCandidates []string; ManyAddressCount int }
type LinkSpec struct { Name string; From string; To string; IPv4CIDR string; IPv6CIDR string; Latency time.Duration; LossPercent int; NAT NATKind }
type ExpectedTransition struct { Node string; Path string; Direct string; Within time.Duration }
```

Define constants `PathRelayName`, `PathDirectName`, `NATNone`, `NATPortMapped`, `NATSymmetric`, and a concrete `Catalog() []Scenario` covering all names above.

Define JSON `NodeCommand` and `NodeEvent` with types for peer control, relay delivery, send peer datagram, set candidates, set portmap, stop, ready, path, peer-control, relay-send, peer-datagram, and error.

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/toposim/scenario.go pkg/toposim/scenario_test.go pkg/toposim/protocol.go pkg/toposim/protocol_test.go
mise exec -- go test ./pkg/toposim -run 'TestScenarioCatalog|TestCatalogScenarios|TestNode(Command|Event)' -count=1
but status -fv
but commit -m "toposim: add scenario catalog and protocol"
```

Expected: PASS.

## Task 2: Linux Lab And Wrapper

**Files:**
- Create: `pkg/toposim/lab_linux.go`
- Create: `pkg/toposim/lab_linux_test.go`
- Create: `scripts/toposim-linux.sh`
- Create: `scripts/toposim_script_test.go`

- [ ] **Step 1: Write failing script contract test**

Add `TestToposimLinuxScriptRunsTaggedLinuxSuite`. It must assert the script contains:

```text
uname -s
require_tool ip
require_tool iptables
require_tool tc
go build -o .tmp/toposim/toposimnode ./tools/toposimnode
go test -tags=toposim ./pkg/toposim
--run
```

It must also reject references to `xcodebuild`, `simctl`, or private `ssh` hosts.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./scripts -run TestToposimLinuxScriptRunsTaggedLinuxSuite -count=1
```

Expected: FAIL because `scripts/toposim-linux.sh` does not exist.

- [ ] **Step 3: Create wrapper**

Create `scripts/toposim-linux.sh`. It must:

- exit 77 with a clear message when `uname -s` is not `Linux`
- require `ip`, `iptables`, `tc`, and `sudo`
- build `.tmp/toposim/toposimnode`
- accept `--run PATTERN` and `--quick`
- run `go test -tags=toposim ./pkg/toposim -run "$pattern" -count=1 -timeout=180s`

- [ ] **Step 4: Write failing namespace smoke test**

Add `TestLinuxLabCreatesAndCleansNamespaces` behind `//go:build linux && toposim`. It must create two namespaces, connect them with veth, run `ip netns list`, clean up, and assert both names are gone.

- [ ] **Step 5: Verify red**

Run:

```bash
scripts/toposim-linux.sh --run TestLinuxLabCreatesAndCleansNamespaces
```

Expected: on Linux, FAIL because lab primitives do not exist; on macOS, exit 77 with the Linux-only message.

- [ ] **Step 6: Implement lab primitives**

Create `LinuxLab`, `LinuxNamespace`, `NewLinuxLab`, `AddNamespace`, `AddVeth`, `SetLink`, `AddNAT`, `SetNetem`, and `Cleanup`. Namespace names must be prefix-scoped to `derphole-ts-$PID-*`. Cleanup must delete only matching namespaces.

- [ ] **Step 7: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/toposim/lab_linux.go pkg/toposim/lab_linux_test.go scripts/toposim_script_test.go
mise exec -- go test ./scripts -run TestToposimLinuxScriptRunsTaggedLinuxSuite -count=1
scripts/toposim-linux.sh --run TestLinuxLabCreatesAndCleansNamespaces
but status -fv
but commit -m "toposim: add linux lab wrapper"
```

Expected: PASS on Linux; on non-Linux, script exits 77 and the Linux smoke must be verified on Ubuntu before landing.

## Task 3: Node Helper And Coordinator

**Files:**
- Create: `tools/toposimnode/main.go`
- Create: `tools/toposimnode/main_test.go`
- Create: `pkg/toposim/coordinator.go`
- Create: `pkg/toposim/coordinator_test.go`

- [ ] **Step 1: Write failing coordinator tests**

Add tests proving the coordinator forwards peer controls, forwards relay payloads, records path transitions, and times out with the scenario name in the error.

- [ ] **Step 2: Write failing node tests**

Add tests for command JSON parsing and path-name mapping from `transport.PathRelay`/`PathDirect` to `relay`/`direct`.

- [ ] **Step 3: Verify red**

Run:

```bash
mise exec -- go test ./pkg/toposim ./tools/toposimnode -run 'TestCoordinator|TestParseNodeCommand|TestPathName' -count=1
```

Expected: FAIL because coordinator and helper do not exist.

- [ ] **Step 4: Implement helper**

`tools/toposimnode` must accept node name, direct UDP port, and comma-separated initial candidates. It starts `transport.NewManager`, emits ready/path/control events as JSON lines, accepts JSON commands on stdin, and supports changing candidates/portmap candidates.

- [ ] **Step 5: Implement coordinator**

Add `nodeEndpoint`, `Coordinator`, `NewCoordinatorForTest`, `Run`, `WaitForPath`, relay/control forwarding, and process-node support through commands shaped like `sudo ip netns exec left .tmp/toposim/toposimnode -name left -direct-port 40000`.

- [ ] **Step 6: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/toposim/coordinator.go pkg/toposim/coordinator_test.go tools/toposimnode/main.go tools/toposimnode/main_test.go
mise exec -- go test ./pkg/toposim ./tools/toposimnode -run 'TestCoordinator|TestParseNodeCommand|TestPathName' -count=1
but status -fv
but commit -m "toposim: add coordinator and node helper"
```

Expected: PASS.

## Task 4: Core Topology Scenarios

**Files:**
- Create: `pkg/toposim/scenarios_linux_test.go`
- Modify: `pkg/toposim/scenario.go`
- Modify: `pkg/toposim/coordinator.go`
- Modify: `pkg/toposim/lab_linux.go`

- [ ] **Step 1: Write failing scenario tests**

Add Linux/tagged tests:

```go
func TestTopologyNATToNATPromotesDirect(t *testing.T)
func TestTopologyRelayFallbackWhenNoStableMapping(t *testing.T)
func TestTopologyFasterPathAppears(t *testing.T)
func TestTopologyLinkOutageFallsBackThenReplugPromotes(t *testing.T)
```

Each calls `runCatalogScenario`.

- [ ] **Step 2: Add result helpers**

Add `FindScenario`, `Result`, and `Result.Saw(ExpectedTransition)` to `scenario.go`.

- [ ] **Step 3: Verify red**

Run:

```bash
scripts/toposim-linux.sh --run 'TestTopology(NATToNAT|RelayFallback|FasterPath|LinkOutage)'
```

Expected: FAIL because `RunLinuxScenario` is missing.

- [ ] **Step 4: Implement core scenarios**

Implement `RunLinuxScenario(ctx, scenario) (Result, error)` and `LinuxLab.BuildScenario`. Core cases must set up:

- stable port-mapped NAT on both sides for NAT-to-NAT direct
- unusable/private-only candidates for relay fallback
- slow initial direct link plus later fast candidate for faster path
- direct link down/up for outage/replug

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/toposim/scenarios_linux_test.go pkg/toposim/scenario.go pkg/toposim/coordinator.go pkg/toposim/lab_linux.go
scripts/toposim-linux.sh --run 'TestTopology(NATToNAT|RelayFallback|FasterPath|LinkOutage)'
but status -fv
but commit -m "toposim: cover core topology scenarios"
```

Expected: PASS on Linux in under 90s.

## Task 5: Candidate Stress, Dual Stack, Portmap Change

**Files:**
- Modify: `pkg/toposim/scenarios_linux_test.go`
- Modify: `pkg/toposim/lab_linux.go`
- Modify: `pkg/toposim/coordinator.go`
- Modify: `tools/toposimnode/main.go`

- [ ] **Step 1: Write failing scenario tests**

Add:

```go
func TestTopologyManyLocalAddressesCapsCandidatesAndPromotes(t *testing.T)
func TestTopologyDualStackPrefersReachableLowerLatencyFamily(t *testing.T)
func TestTopologyPortmapChangeRefreshesCandidates(t *testing.T)
```

- [ ] **Step 2: Verify red**

Run:

```bash
scripts/toposim-linux.sh --run 'TestTopology(ManyLocal|DualStack|Portmap)'
```

Expected: FAIL until scenario branches are implemented.

- [ ] **Step 3: Extend helper/coordinator**

Ensure peer-control events include actual manager candidates. Add a coordinator assertion for candidate cap (`<= candidate.MaxCount`). Add node support for command-driven peer datagrams and portmap candidate changes.

- [ ] **Step 4: Implement scenarios**

Implement:

- many local address aliases, capped candidate emission, still promotes direct
- IPv4 and IPv6 paths with lower latency IPv6 selected, fallback to IPv4 when IPv6 broken if included in test variant
- mapped UDP port change from `:40000` to `:41000`, old mapping dropped, direct regained on new candidate

- [ ] **Step 5: Verify and checkpoint**

Run:

```bash
gofmt -w pkg/toposim/scenarios_linux_test.go pkg/toposim/lab_linux.go pkg/toposim/coordinator.go tools/toposimnode/main.go
scripts/toposim-linux.sh --run 'TestTopology(ManyLocal|DualStack|Portmap)'
but status -fv
but commit -m "toposim: add address and portmap scenarios"
```

Expected: PASS on Linux in under 90s.

## Task 6: Mise And CI

**Files:**
- Modify: `.mise.toml`
- Modify: `.github/workflows/checks.yml`
- Modify: `scripts/toposim_script_test.go`

- [ ] **Step 1: Write failing wiring test**

Add `TestToposimIsWiredIntoMiseAndChecksWorkflow`. It must assert `.mise.toml` contains `[tasks.toposim]` and `bash ./scripts/toposim-linux.sh --quick`, and checks workflow contains `iproute2`, `iptables`, `iputils-ping`, and `mise run toposim`.

- [ ] **Step 2: Verify red**

Run:

```bash
mise exec -- go test ./scripts -run TestToposimIsWiredIntoMiseAndChecksWorkflow -count=1
```

Expected: FAIL.

- [ ] **Step 3: Add task/workflow**

Add:

```toml
[tasks.toposim]
description = "Run Linux-only local topology simulation tests"
run = "bash ./scripts/toposim-linux.sh --quick"
```

In `.github/workflows/checks.yml`, install tools and run `mise run toposim` after `mise run check`.

- [ ] **Step 4: Verify and checkpoint**

Run:

```bash
mise exec -- go test ./scripts -run 'TestToposimLinuxScript|TestToposimIsWired' -count=1
mise exec -- go test ./pkg/toposim ./tools/toposimnode ./scripts -count=1
scripts/toposim-linux.sh --quick
mise run test
mise run check:hooks
but status -fv
but commit -m "ci: run linux topology simulations"
```

Expected: PASS on Linux; on macOS the wrapper exits 77 and Linux verification must happen in Ubuntu CI before landing.

## Final Verification

Run:

```bash
mise exec -- go test ./pkg/toposim ./tools/toposimnode ./scripts -count=1
scripts/toposim-linux.sh --run 'TestTopology(NATToNAT|RelayFallback|FasterPath|LinkOutage|ManyLocal|DualStack|Portmap)'
mise run test
mise run check:hooks
but status -fv
```

Expected: all Go tests PASS; all topology scenarios PASS on Ubuntu; no generated `dist/` changes.

## Acceptance Criteria

- Linux-only local suite covers all seven topology scenarios.
- Suite needs no SSH/private hosts and can run on GitHub Actions Ubuntu.
- Namespace cleanup is prefix-scoped and aggressive.
- Production transport behavior is unchanged unless a separate bugfix branch is created.

## Self-Review Notes

- Spec coverage: all requested topology cases and CI integration are mapped to tasks.
- Red-flag scan: clean for unresolved markers, ellipses, and incomplete implementation steps.
- Type consistency: scenario/protocol/coordinator/result names are introduced before use.
