# Direct Connect Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reusable `derphole-probe` diagnostic that explains whether two SSH-connected hosts can form a direct UDP path and why not.

**Architecture:** Keep the harness in `cmd/derphole-probe` and `pkg/probe` beside the existing probe tooling. Put classification and report types in `pkg/probe` so tests can validate the important decisions without SSH. The CLI runner will gather DNS, local/remote interface and egress facts, UDP reachability, and simultaneous punch evidence, then print a JSON report plus concise classifications.

**Tech Stack:** Go, existing `cmd/derphole-probe` CLI pattern, SSH command execution, UDP sockets, JSON reports, focused Go tests.

---

### Task 1: Topology Report And Classifier

**Files:**
- Create: `pkg/probe/topology.go`
- Test: `pkg/probe/topology_test.go`

- [ ] **Step 1: Write failing tests**

Add tests that construct reports and assert classifications:

```go
func TestClassifyTopologyDetectsSSHFrontDoorMismatch(t *testing.T) {
	report := TopologyReport{
		DNSAddresses: []string{"161.210.92.1"},
		Remote: TopologyHost{
			EgressIP: "44.240.253.236",
			Interfaces: []TopologyInterface{{Name: "eth0", Addrs: []string{"10.42.0.64/16"}}},
		},
	}
	got := ClassifyTopology(report)
	if !slices.Contains(got, TopologyClassSSHFrontDoorMismatch) {
		t.Fatalf("ClassifyTopology() = %v, want %s", got, TopologyClassSSHFrontDoorMismatch)
	}
}

func TestClassifyTopologyDetectsUDPBlocked(t *testing.T) {
	report := TopologyReport{
		UDPReachability: []UDPReachabilityResult{
			{Target: "dns-a", Address: "161.210.92.1:47000", Received: false},
			{Target: "egress", Address: "44.240.253.236:47000", Received: false},
		},
	}
	got := ClassifyTopology(report)
	if !slices.Contains(got, TopologyClassRemoteUDPUnreachable) {
		t.Fatalf("ClassifyTopology() = %v, want %s", got, TopologyClassRemoteUDPUnreachable)
	}
}
```

- [ ] **Step 2: Run red test**

Run: `go test ./pkg/probe -run 'TestClassifyTopology' -count=1`

Expected: FAIL because `TopologyReport` and `ClassifyTopology` do not exist.

- [ ] **Step 3: Implement minimal report types and classifier**

Add exported JSON-friendly types and constants:

```go
const (
	TopologyClassSSHFrontDoorMismatch = "ssh-front-door-mismatch"
	TopologyClassRemoteUDPUnreachable = "remote-udp-unreachable"
	TopologyClassDirectUDPPossible    = "direct-udp-possible"
)
```

`ClassifyTopology` should detect:

- DNS addresses are present and do not include remote egress IP.
- remote interface addresses are private while egress IP is public.
- all UDP reachability tests failed.
- at least one UDP reachability or punch test succeeded.

- [ ] **Step 4: Run green test**

Run: `go test ./pkg/probe -run 'TestClassifyTopology' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```bash
git add pkg/probe/topology.go pkg/probe/topology_test.go
git commit -m "probe: add topology classification model"
git push origin main
```

### Task 2: Diagnostic Runner

**Files:**
- Modify: `pkg/probe/topology.go`
- Test: `pkg/probe/topology_test.go`

- [ ] **Step 1: Write failing tests for command generation and UDP result parsing**

Add tests for:

- SSH target formatting from `{User, Host}`.
- remote fact JSON decode into `TopologyHost`.
- UDP reachability result recording success and failure.

- [ ] **Step 2: Run red test**

Run: `go test ./pkg/probe -run 'TestTopologyRunner|TestDecodeRemoteTopology' -count=1`

Expected: FAIL because runner helpers do not exist.

- [ ] **Step 3: Implement runner with injectable dependencies**

Add `TopologyConfig`, `TopologyRunner`, and `RunTopologyDiagnostics(ctx, cfg)` with injectable hooks for tests:

- DNS lookup.
- local egress IP lookup.
- SSH command execution.
- UDP packet send/read.

The production runner should:

- resolve DNS for the target host
- gather local hostname, interface addresses, and egress IP
- gather remote hostname, interface addresses, egress IP, firewall summaries, and UDP listener state through SSH
- start a temporary remote UDP echo server and send local UDP probes to DNS and remote egress addresses
- run a simultaneous UDP punch attempt using local and remote bound UDP sockets
- classify the final report

- [ ] **Step 4: Run green test**

Run: `go test ./pkg/probe -run 'TestTopologyRunner|TestDecodeRemoteTopology|TestClassifyTopology' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```bash
git add pkg/probe/topology.go pkg/probe/topology_test.go
git commit -m "probe: add direct topology diagnostic runner"
git push origin main
```

### Task 3: CLI Subcommand

**Files:**
- Modify: `cmd/derphole-probe/root.go`
- Create: `cmd/derphole-probe/topology.go`
- Test: `cmd/derphole-probe/root_test.go`
- Test: `cmd/derphole-probe/topology_test.go`

- [ ] **Step 1: Write failing CLI tests**

Add tests that verify:

- `derphole-probe topology --host example.com --user user` calls the runner.
- the subcommand rejects empty host.
- JSON report includes `classifications`.

- [ ] **Step 2: Run red test**

Run: `go test ./cmd/derphole-probe -run 'TestRunTopology|TestRunHelpCommandShowsSubcommandHelp' -count=1`

Expected: FAIL because the subcommand is not wired.

- [ ] **Step 3: Implement CLI wiring**

Add `topology` to the registry and `run` switch. Add flags:

- `--host`
- `--user`, default `root`
- `--udp-port`, default `47000`
- `--timeout`, default `5s`

Print indented JSON to stdout. Print validation errors to stderr and exit `2`.

- [ ] **Step 4: Run green test**

Run: `go test ./cmd/derphole-probe -run 'TestRunTopology|TestRunHelpCommandShowsSubcommandHelp' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```bash
git add cmd/derphole-probe/root.go cmd/derphole-probe/topology.go cmd/derphole-probe/topology_test.go
git commit -m "probe: expose direct topology diagnostics"
git push origin main
```

### Task 4: Verification And Live Report

**Files:**
- Uncommitted: host-specific report file requested by the user

- [ ] **Step 1: Run focused tests**

Run: `go test ./cmd/derphole-probe ./pkg/probe`

Expected: PASS.

- [ ] **Step 2: Run full suite**

Run: `mise run test`

Expected: PASS.

- [ ] **Step 3: Build binaries**

Run: `mise run build`

Expected: PASS and `dist/derphole` exists.

- [ ] **Step 4: Run live topology diagnostic**

Run the new harness against the target host named in the uncommitted report. Append the JSON summary and interpretation to the report.

- [ ] **Step 5: Commit any verification fixes and push**

If code changes are needed, commit and push them with a scoped imperative subject.
