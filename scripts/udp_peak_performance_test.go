// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUDPPeakPerformancePreliminaryContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "udp-peak-performance.sh"))
	if err != nil {
		t.Fatalf("read udp-peak-performance.sh: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		`preliminary`,
		`--root`,
		`--registry`,
		`--registry-sha256`,
		`--remote`,
		`--remote-public`,
		`--local-public`,
		`--tcp-port`,
		`size_bytes=1073741824`,
		`sequence=(frozen-control combined-gso3 combined-gso3 frozen-control combined-gso3 frozen-control)`,
		`directions=(forward reverse)`,
		`-t 20`,
		`-P 8`,
		`capacity_attempts=3`,
		`2050`,
		`DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`,
		`env -i`,
		`health-snapshot`,
		`health-watch`,
		`health-compare`,
		`capacity-check`,
		`-expected-payload-bytes`,
		`-require-file-payload-engine`,
		`-require-engine-telemetry`,
		`-expected-selected-public-ipv4`,
		`-peer-expected-selected-public-ipv4`,
		`-forbid-relay-payload`,
		`bulk_candidate_id`,
		`benchmark-source-sha256`,
		`benchmark-sink-sha256`,
		`benchmark-sink-size-bytes`,
		`benchmark-cleanup-success`,
		`results.csv`,
		`comparison.csv`,
		`/tmp/derphole-udp-peak-v1.`,
		`ssh -o BatchMode=yes --`,
		`bash -se --`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("udp-peak-performance.sh missing %q", want)
		}
	}
	if strings.Contains(body, `remote_clean "`) {
		t.Fatal("udp-peak-performance.sh interpolates a remote script instead of passing positional arguments")
	}

	for _, reject := range []string{
		"direct-tcp",
		"apt-get",
		"apt install",
		"brew install",
		"mise install",
		"sysctl",
		"sudo ",
		"fleet",
		"eric",
		"3221225472",
		"ceiling",
		"RETAIN_REMOTE_RESULT",
	} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(reject)) {
			t.Errorf("udp-peak-performance.sh contains out-of-scope behavior %q", reject)
		}
	}
}

func TestUDPPeakPerformanceRequiresExplicitInputs(t *testing.T) {
	t.Parallel()

	command := exec.Command("bash", "./udp-peak-performance.sh", "preliminary")
	if err := command.Run(); err == nil {
		t.Fatal("preliminary harness accepted missing explicit inputs")
	}
}

func TestUDPPeakPerformanceUsesLinuxSafeRemoteHelperName(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	setup := scriptSection(t, string(data), "setup_tools_and_remote() {", "\nrun_capacity_control() {")
	const prefix = `remote_udppeak="${remote_root}/`
	start := strings.Index(setup, prefix)
	if start < 0 {
		t.Fatal("remote udppeak assignment is missing")
	}
	remainder := setup[start+len(prefix):]
	end := strings.IndexByte(remainder, '"')
	if end < 0 {
		t.Fatal("remote udppeak assignment is unterminated")
	}
	name := remainder[:end]
	if name != "udppeak" {
		t.Fatalf("remote udppeak name = %q, want Linux-safe scoped name %q", name, "udppeak")
	}
	if len(name) > 15 {
		t.Fatalf("remote udppeak name %q exceeds Linux's 15-byte task-name limit", name)
	}
	if !strings.Contains(setup, `install -m 0755`) {
		t.Fatal("remote helper is not installed executable")
	}
}

func TestUDPPeakPerformanceUsesHostSafeHealthWatchInterval(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	startHealth := scriptSection(t, string(data), "start_health() {", "\nstop_health() {")
	if got := strings.Count(startHealth, `-interval 2s`); got != 2 {
		t.Fatalf("2s health-watch interval count = %d, want local and remote watchers", got)
	}
	if strings.Contains(startHealth, `-interval 1s`) {
		t.Fatal("health watcher uses a deadline below the measured Darwin capture time")
	}
}

func TestUDPPeakPerformanceLowCapacityCannotStartUDP(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "udp-peak-performance.sh"))
	if err != nil {
		t.Fatalf("read udp-peak-performance.sh: %v", err)
	}
	body := string(data)
	capacity := scriptSection(t, body, "run_capacity_control() {", "\nrun_transfer() {")
	main := scriptSection(t, body, "run_preliminary() {", "\nmain() {")
	assertScriptOrder(t, capacity, `for attempt in $(seq 1 "${capacity_attempts}")`, `if capacity_passes`, `return 0`, `return 1`)
	assertScriptOrder(t, main, "run_capacity_control", "write_postponed_result", "return 1")
	if strings.Index(main, "run_capacity_control") > strings.Index(main, "run_transfer") {
		t.Fatal("preliminary harness can start UDP before its capacity gate")
	}
}

func TestUDPPeakPerformanceIdentityPublicationHasNoTrackerGap(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	body := string(data)
	if got := strings.Count(body, `publish_local_process_ref "`); got != 4 {
		t.Fatalf("identity publication transitions = %d, want 4 shared gap-free transitions", got)
	}
	definition := scriptSection(t, body, "publish_local_process_ref() {", "\nlocal_pid_running() {")
	script := definition + "\n" + `
set -euo pipefail
local_process_refs=()
unidentified_local_pids=(123)
expected_ref="$1"
remove_unidentified_local_pid() {
  [[ " ${local_process_refs[*]} " == *" ${expected_ref} "* ]]
  unidentified_local_pids=()
}
publish_local_process_ref 123 "${expected_ref}"
[[ "${local_process_refs[0]}" == "${expected_ref}" ]]
[[ "${#unidentified_local_pids[@]}" == 0 ]]
`
	cmd := exec.Command("bash", "-c", script, "probe", filepath.Join(t.TempDir(), "child.ref.json"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("identity publication exposed a zero-tracker interruption: %v\n%s", err, output)
	}
}

type udpPeakPerformanceHarness struct {
	registry    string
	registrySHA string
	outputRoot  string
	fakeBin     string
	stateDir    string
	promotion   string
}

func newUDPPeakPerformanceHarness(t *testing.T, capacity float64, failAt int) udpPeakPerformanceHarness {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, info.Mode()|0o700)
			}
			return nil
		})
	})
	fakeBin := filepath.Join(root, "bin")
	stateDir := filepath.Join(root, "state")
	candidateRoot := filepath.Join(root, "candidates")
	for _, dir := range []string{fakeBin, stateDir, candidateRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	registryPath := writeUDPPeakPerformanceRegistry(t, candidateRoot)
	udppeakHelper := filepath.Join(stateDir, "udppeak-helper")
	writeExecutable(t, udppeakHelper, strings.ReplaceAll(`#!/usr/bin/env bash
set -euo pipefail
command_name="${1:?missing command}"
shift
printf '%s\n' "${command_name}" >>'__STATE__/timeline'
out=""
stop=""
name=""
pid=""
scope=""
while (( $# > 0 )); do
  case "$1" in
    -out) out="$2"; shift 2 ;;
    -stop-file) stop="$2"; shift 2 ;;
    -name) name="$2"; shift 2 ;;
    -pid) pid="$2"; shift 2 ;;
    -scope) scope="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "${out}" ]]
printf '%s\t%s\n' "${command_name}" "${out}" >>'__STATE__/udppeak-calls'
write_snapshot() {
  local output="$1" side="ordinary" mode="healthy"
  if [[ "$(basename "${scope}")" == local-child-scope.json ]]; then
    side=local
  elif [[ "$(basename "${scope}")" == *.child-scope.json ]]; then
    side=remote
  fi
  [[ -f '__STATE__/post-cleanup-mode' ]] && mode="$(tr -d '[:space:]' <'__STATE__/post-cleanup-mode')"
  if [[ "${command_name}" == health-snapshot && "${side}" == ordinary && -f '__STATE__/baseline-health-fail' ]]; then
    return 93
  fi
  if [[ "${side}" == local && "${mode}" == local-helper-error ]] || [[ "${side}" == remote && "${mode}" == remote-helper-error ]]; then
    return 94
  fi
  python3 - "${scope}" "${output}" "${side}" "${mode}" <<'PY'
import json, sys
scope_path, output_path, side, mode = sys.argv[1:]
with open(scope_path, encoding="utf-8") as source:
    scope = json.load(source)
processes = []
sockets = []
if side == "local" and mode == "local-process":
    processes = scope["processes"][:1]
if side == "remote" and mode == "remote-socket":
    process = scope["processes"][0]
    sockets = [{
        "executable_identity": process["executable_identity"],
        "local": "1.1.1.1:12345",
        "network": "udp4",
        "pid": process["pid"],
        "remote": "8.8.8.8:54321",
        "start_identity": process["start_identity"],
    }]
snapshot = {
    "available_memory_bytes": 90000000000,
    "boot_id": "boot-a",
    "cgroup_oom_kills": 0,
    "cgroups": [],
    "cleanup_scope": scope,
    "counter_families": ["uptime", "online-cpus", "global-oom", "cgroup-oom", "memory", "swap", "disk", "kernel", "interface", "udp", "softnet", "process", "socket"],
    "disk_free_bytes": 90000000000,
    "global_oom_kills": 0,
    "interface_counters": [],
    "interface_drops": 0,
    "kernel_errors": [],
    "online_cpus": 2,
    "platform": "linux" if side == "remote" else "darwin",
    "processes": processes,
    "sockets": sockets,
    "softnet_counters": [],
    "softnet_drops": 0,
    "swap_used_bytes": 0,
    "udp_counters": [],
    "udp_errors": 0,
    "uptime_seconds": 100,
}
with open(output_path, "x", encoding="utf-8") as output:
    json.dump(snapshot, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
}
case "${command_name}" in
  process-identify)
    if [[ -f '__STATE__/fail-local-watch-identify' && "$(basename "${out}")" == local-watch.ref.json ]]; then
      exit 95
    fi
    if [[ -f '__STATE__/fail-iperf-identify' && "$(basename "${out}")" == iperf-server-*.ref.json ]]; then
      exit 96
    fi
    if [[ -f '__STATE__/fail-promotion-identify' && "$(basename "${out}")" == promotion.ref.json ]]; then
      exit 97
    fi
    if [[ -f '__STATE__/fail-promotion-reidentify' && "$(basename "${out}")" == promotion.ref.json.recheck.* ]]; then
      exit 98
    fi
    kill -0 "${pid}" 2>/dev/null
    printf '{"executable_identity":"/fake/%s","name":"%s","pid":%s,"start_identity":"start-%s"}\n' "${name}" "${name}" "${pid}" "${pid}" >"${out}"
    ;;
  health-snapshot)
    write_snapshot "${out}"
    ;;
  health-watch)
    write_snapshot "${out}"
    if [[ -f '__STATE__/local-ready-health-fail' && "$(basename "${out}")" == local-watch.jsonl ]]; then
      python3 - "${out}" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
value["udp_errors"] = 1
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(value, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
    fi
    case "${FAKE_HEALTH_WATCH_MODE:-healthy}" in
      malformed) printf '{not-json\n' >>"${out}" ;;
      counter) python3 - "${out}" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
value["udp_errors"] = 1
with open(sys.argv[1], "a", encoding="utf-8") as output:
    json.dump(value, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
      ;;
    esac
    while [[ ! -e "${stop}" ]]; do sleep 0.01; done
    ;;
  health-compare|capacity-check)
    printf '%s\n' '{}' >"${out}"
    ;;
  *) exit 91 ;;
esac
shasum -a 256 "${out}" | awk '{print $1}'
`, "__STATE__", stateDir))
	traceHelper := filepath.Join(stateDir, "trace-helper")
	writeExecutable(t, traceHelper, strings.ReplaceAll(`#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>'__STATE__/trace-events'
printf 'trace-ok\n'
`, "__STATE__", stateDir))
	writeExecutable(t, filepath.Join(fakeBin, "mise"), strings.NewReplacer(
		"__UDPPEAK__", udppeakHelper,
		"__TRACE__", traceHelper,
	).Replace(`#!/usr/bin/env bash
set -euo pipefail
out=""
previous=""
for argument in "$@"; do
  if [[ "${previous}" == "-o" ]]; then out="${argument}"; fi
  previous="${argument}"
done
[[ -n "${out}" ]]
if [[ "$*" == *"./tools/udppeak"* ]]; then source='__UDPPEAK__'; else source='__TRACE__'; fi
mkdir -p "$(dirname "${out}")"
cp "${source}" "${out}"
chmod 0755 "${out}"
`))
	writeExecutable(t, filepath.Join(fakeBin, "ssh"), `#!/usr/bin/env bash
set -euo pipefail
while (( $# > 0 )); do
  case "$1" in
    -o) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
shift
/bin/bash -c "$*"
`)
	writeExecutable(t, filepath.Join(fakeBin, "scp"), strings.ReplaceAll(`#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == -- ]] && shift
source_path="$1"
destination_path="$2"
[[ "${source_path}" == *:* ]] && source_path="${source_path#*:}"
[[ "${destination_path}" == *:* ]] && destination_path="${destination_path#*:}"
if [[ -f '__STATE__/fail-remote-child-ref-scp' && "${source_path}" == *.child.ref.json ]]; then
  exit 97
fi
mkdir -p "$(dirname "${destination_path}")"
cp "${source_path}" "${destination_path}"
`, "__STATE__", stateDir))
	writeExecutable(t, filepath.Join(fakeBin, "iperf3"), fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" -s "* ]]; then printf '%%s\n' "$$" >>%q; sleep 0.25; exit 0; fi
printf 'client\n' >>%q
python3 - <<'PY'
import json
print(json.dumps({"end":{"sum_received":{"bits_per_second":%f * 1000000.0}}}))
PY
`, filepath.Join(stateDir, "iperf-server-pids"), filepath.Join(stateDir, "iperf-events"), capacity))
	writeExecutable(t, filepath.Join(fakeBin, "df"), "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\nfake 100000000 1 99999999 1%% /\\n'\n")
	writeExecutable(t, filepath.Join(fakeBin, "route"), "#!/bin/sh\nprintf ' interface: en0\\n'\n")
	writeExecutable(t, filepath.Join(fakeBin, "ip"), "#!/bin/sh\nprintf '8.8.8.8 via 1.1.1.1 dev eth0 src 1.1.1.2\\n'\n")
	writeExecutable(t, filepath.Join(fakeBin, "ss"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "ps"), strings.ReplaceAll(`#!/usr/bin/env bash
set -euo pipefail
pid=""
for argument in "$@"; do pid="${argument}"; done
if [[ -f '__STATE__/promotion-ps-indeterminate' && -f '__STATE__/promotion-pids' ]] && grep -Fxq -- "${pid}" '__STATE__/promotion-pids'; then
  exit 99
fi
exec /bin/ps "$@"
`, "__STATE__", stateDir))
	writeExecutable(t, filepath.Join(fakeBin, "sha256sum"), "#!/bin/sh\nexec shasum -a 256 \"$@\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "getconf"), "#!/bin/sh\nprintf '2\\n'\n")
	writeExecutable(t, filepath.Join(fakeBin, "dd"), `#!/usr/bin/env bash
set -euo pipefail
out=""
for argument in "$@"; do [[ "${argument}" == of=* ]] && out="${argument#of=}"; done
[[ -n "${out}" ]]
printf 'payload-allocation\n' >>'`+stateDir+`/timeline'
printf 'stub-payload\n' >"${out}"
`)

	promotion := filepath.Join(root, "promotion")
	promotionBody := strings.NewReplacer(
		"__STATE__", stateDir,
		"__FAIL_AT__", fmt.Sprintf("%d", failAt),
	).Replace(`#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$$" >>'__STATE__/promotion-pids'
events='__STATE__/promotion-events'
if [[ -f '__STATE__/promotion-no-ready' ]]; then
  for _ in $(seq 1 3000); do sleep 0.01; done
  exit 98
fi
if [[ -n "${DERPHOLE_BENCH_READY_FILE:-}" ]]; then
  printf 'ready\n' >"${DERPHOLE_BENCH_READY_FILE}"
  for _ in $(seq 1 1000); do
    [[ -f "${DERPHOLE_BENCH_START_FILE}" ]] && break
    sleep 0.01
  done
  [[ -f "${DERPHOLE_BENCH_START_FILE}" ]]
fi
candidate="$(basename "$(dirname "${DERPHOLE_BENCH_LOCAL_BIN}")")"
printf '%s %s\n' "${DERPHOLE_BENCH_DIRECTION}" "${candidate}" >>"${events}"
printf '%s %s\n' "${candidate}" "${DERPHOLE_BENCH_REVISION_LABEL}" >>'__STATE__/revision-events'
count="$(wc -l <"${events}" | tr -d '[:space:]')"
mkdir -p "${DERPHOLE_BENCH_LOG_DIR}"
if [[ "${candidate}" == combined-gso3 ]]; then
  printf '%s\n' \
    'bulk_candidate_id,bulk_native_send_attempts,bulk_native_send_syscalls,bulk_gso_messages,bulk_logical_datagrams,bulk_accepted_payload_bytes,bulk_gso_segments_per_message' \
    'combined-gso3,10,9,8,30,1073741824,3' >"${DERPHOLE_BENCH_LOG_DIR}/run-sender.trace.csv"
  cp "${DERPHOLE_BENCH_LOG_DIR}/run-sender.trace.csv" "${DERPHOLE_BENCH_LOG_DIR}/run-receiver.trace.csv"
else
  printf 'app_bytes\n1073741824\n' >"${DERPHOLE_BENCH_LOG_DIR}/run-sender.trace.csv"
  cp "${DERPHOLE_BENCH_LOG_DIR}/run-sender.trace.csv" "${DERPHOLE_BENCH_LOG_DIR}/run-receiver.trace.csv"
fi
if [[ "${DERPHOLE_BENCH_DIRECTION}" == forward ]]; then payload="${DERPHOLE_BENCH_LOCAL_PAYLOAD}"; else payload="${DERPHOLE_BENCH_REMOTE_PAYLOAD}"; fi
digest="$(shasum -a 256 "${payload}" | awk '{print $1}')"
mkdir -p "${DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR}"
roles=(local-runstats local-derphole wrapper runstats derphole)
role_pid=120
for role in "${roles[@]}"; do
  role_pid=$((role_pid + 1))
  printf '{"executable_identity":"/fake/%s","name":"%s","pid":%d,"start_identity":"start-%s"}\n' "${role}" "${role}" "${role_pid}" "${role}" >"${DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR}/${role}.ref.json"
  shasum -a 256 "${DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR}/${role}.ref.json" | awk '{print $1}' >"${DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR}/${role}.ref.json.sha256"
done
python3 - "${DERPHOLE_BENCH_CHILD_CLEANUP_OUT}" "${DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR}" "${FAKE_CHILD_CLEANUP_INVALID:-0}" <<'PY'
import hashlib, json, os, sys
path, root, invalid = sys.argv[1:]
refs = []
if invalid != "1":
    for role in ("local-runstats", "local-derphole", "wrapper", "runstats", "derphole"):
        data = open(os.path.join(root, role + ".ref.json"), "rb").read()
        refs.append({"role": role, "sha256": hashlib.sha256(data).hexdigest()})
with open(path, "x", encoding="utf-8") as output:
    json.dump({"identity_cleanup_complete": True, "references": refs, "schema_version": 1, "success": True}, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
cleanup_digest="$(shasum -a 256 "${DERPHOLE_BENCH_CHILD_CLEANUP_OUT}" | awk '{print $1}')"
status=0
success=true
if [[ '__FAIL_AT__' != 0 && "${count}" == '__FAIL_AT__' ]]; then status=23; success=false; fi
printf '%s\n' \
  "benchmark-source-sha256=${digest}" \
  "benchmark-sink-sha256=${digest}" \
  'benchmark-sink-size-bytes=1073741824' \
  'benchmark-goodput-mbps=2100.000' \
  'benchmark-wall-goodput-mbps=2080.000' \
  'benchmark-sender-user-cpu-seconds=1.25' \
  'benchmark-sender-system-cpu-seconds=0.25' \
  'benchmark-sender-max-rss-bytes=134217728' \
  "benchmark-sender-resource-stats-available=$([[ \"${FAKE_PROMOTION_RESOURCE_UNAVAILABLE:-0}\" == 1 ]] && echo false || echo true)" \
  'benchmark-receiver-user-cpu-seconds=1.5' \
  'benchmark-receiver-system-cpu-seconds=0.5' \
  'benchmark-receiver-max-rss-bytes=167772160' \
  "benchmark-receiver-resource-stats-available=$([[ \"${FAKE_PROMOTION_RESOURCE_UNAVAILABLE:-0}\" == 1 ]] && echo false || echo true)" \
  "benchmark-remote-linux-bin-sha256=${DERPHOLE_BENCH_LINUX_BIN_SHA256}" \
  'benchmark-cleanup-success=true' \
  'benchmark-child-cleanup-success=true' \
  "benchmark-child-cleanup-sha256=${cleanup_digest}" \
  "benchmark-success=${success}"
exit "${status}"
`)
	writeExecutable(t, promotion, promotionBody)

	return udpPeakPerformanceHarness{
		registry: registryPath, registrySHA: testFileSHA256(t, registryPath), outputRoot: filepath.Join(root, "output"), fakeBin: fakeBin, stateDir: stateDir, promotion: promotion,
	}
}

func writeUDPPeakPerformanceRegistry(t *testing.T, root string) string {
	t.Helper()
	candidates := []string{"frozen-control", "coalesced-gso3", "connected-gso3", "combined-gso1", "combined-gso2", "combined-gso3", "combined-gso4", "combined-gso6", "combined-gso8", "combined-gso12", "quic-control"}
	entries := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		commit := strings.Repeat("b", 40)
		if candidate == "frozen-control" {
			commit = strings.Repeat("a", 40)
		}
		candidateDir := filepath.Join(root, "bin", candidate)
		if err := os.MkdirAll(candidateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		binaries := map[string]map[string]any{}
		for _, platform := range []struct{ key, name, platform string }{{"darwin", "derphole-darwin-arm64", "darwin-arm64"}, {"linux", "derphole-linux-amd64", "linux-amd64"}} {
			path := filepath.Join(candidateDir, platform.name)
			writeExecutable(t, path, "#!/bin/sh\nexit 0\n")
			digest := sha256.Sum256([]byte("#!/bin/sh\nexit 0\n"))
			binary := map[string]any{
				"path": filepath.ToSlash(filepath.Join("bin", candidate, platform.name)), "platform": platform.platform,
				"sha256": hex.EncodeToString(digest[:]), "vcs_revision": commit, "vcs_modified": false,
				"build_info_sha256": strings.Repeat("c", 64), "command_path": "github.com/shayne/derphole/cmd/derphole",
				"go_version": "go1.test", "module_path": "github.com/shayne/derphole", "module_version": "(devel)",
			}
			if platform.key == "darwin" {
				binary["goos"], binary["goarch"] = "darwin", "arm64"
			} else {
				binary["goos"], binary["goarch"] = "linux", "amd64"
			}
			if candidate == "combined-gso3" {
				binary["configured_linker_value"] = candidate
			}
			if candidate == "frozen-control" {
				binary["configured_linker_value"], binary["selector_state"] = "", "absent"
			} else {
				binary["configured_linker_value"], binary["selector_state"] = candidate, "linked"
			}
			binaries[platform.key] = binary
		}
		gsoSegments := 3
		engine := "bulk-packets-v1"
		if strings.HasPrefix(candidate, "combined-gso") {
			_, _ = fmt.Sscanf(candidate, "combined-gso%d", &gsoSegments)
		}
		if candidate == "quic-control" {
			engine = "quic-blocks-v1"
			gsoSegments = 0
		}
		entry := map[string]any{
			"commit": commit, "config": map[string]string{"candidate": candidate}, "darwin": binaries["darwin"],
			"engine": engine, "gso_segments_per_message": gsoSegments, "id": candidate, "linux": binaries["linux"],
		}
		if candidate == "combined-gso3" {
			entry["linker_value"] = candidate
			entry["configuration_profile"] = "benchmark-linker"
		} else if candidate == "frozen-control" {
			entry["linker_value"] = ""
			entry["configuration_profile"] = "frozen-bulk-gso3"
		} else {
			entry["linker_value"] = candidate
			entry["configuration_profile"] = "benchmark-linker"
		}
		entries = append(entries, entry)
	}
	registry := map[string]any{"candidates": entries, "control_id": "frozen-control", "schema_version": 1, "source_revision": strings.Repeat("b", 40)}
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "candidates.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (h udpPeakPerformanceHarness) command() *exec.Cmd {
	return h.commandForRemote("stub@example")
}

func (h udpPeakPerformanceHarness) commandForRemote(remote string) *exec.Cmd {
	command := exec.Command("bash", "./scripts/udp-peak-performance.sh", "preliminary",
		"--root", h.outputRoot,
		"--registry", h.registry,
		"--registry-sha256", h.registrySHA,
		"--remote", remote,
		"--remote-public", "8.8.8.8",
		"--local-public", "1.1.1.1",
		"--tcp-port", "8123",
	)
	command.Dir = ".."
	command.Env = append(os.Environ(),
		"PATH="+h.fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DERPHOLE_UDP_PEAK_PROMOTION_DRIVER="+h.promotion,
	)
	return command
}

func TestUDPPeakPerformanceRejectsUnsafeRemoteRegistryMutationAndExistingRoot(t *testing.T) {
	t.Run("unsafe remote", func(t *testing.T) {
		harness := newUDPPeakPerformanceHarness(t, 2200, 0)
		output, err := harness.commandForRemote("-oProxyCommand=bad").CombinedOutput()
		if err == nil || !strings.Contains(string(output), "remote must be a safe SSH target") {
			t.Fatalf("unsafe remote result: err=%v\n%s", err, output)
		}
	})
	t.Run("registry mutation", func(t *testing.T) {
		harness := newUDPPeakPerformanceHarness(t, 2200, 0)
		file, err := os.OpenFile(harness.registry, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.WriteString(" \n")
		_ = file.Close()
		output, err := harness.command().CombinedOutput()
		if err == nil || !strings.Contains(string(output), "registry SHA-256") {
			t.Fatalf("mutated registry result: err=%v\n%s", err, output)
		}
	})
	t.Run("existing root", func(t *testing.T) {
		harness := newUDPPeakPerformanceHarness(t, 2200, 0)
		if err := os.MkdirAll(harness.outputRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		output, err := harness.command().CombinedOutput()
		if err == nil || !strings.Contains(string(output), "campaign root must not exist") {
			t.Fatalf("existing root result: err=%v\n%s", err, output)
		}
	})
}

func TestUDPPeakPerformanceRejectsInvalidUnselectedCandidateMetadata(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 1900, 0)
	data := mustReadUDPArtifact(t, harness.registry)
	var registry map[string]any
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	for _, raw := range registry["candidates"].([]any) {
		candidate := raw.(map[string]any)
		if candidate["id"] == "coalesced-gso3" {
			candidate["engine"] = "wrong-engine"
		}
	}
	updated, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness.registry, append(updated, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	harness.registrySHA = testFileSHA256(t, harness.registry)
	output, err := harness.command().CombinedOutput()
	if err == nil || !strings.Contains(string(output), "coalesced-gso3") {
		t.Fatalf("invalid unselected candidate was not rejected precisely: err=%v\n%s", err, output)
	}
}

func TestUDPPeakPerformanceValidatesEveryHealthWatchSample(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "validate_health_watch() {", "\nfooter_value() {")
	root := t.TempDir()
	before := filepath.Join(root, "before.json")
	snapshot := `{"available_memory_bytes":90000000000,"boot_id":"boot-a","cgroup_oom_kills":0,"cgroups":[],"cleanup_scope":{"cgroups":[],"declared":true,"processes":[]},"counter_families":["uptime","online-cpus","global-oom","cgroup-oom","memory","swap","disk","kernel","interface","udp","softnet","process","socket"],"disk_free_bytes":90000000000,"global_oom_kills":0,"interface_counters":[],"interface_drops":0,"kernel_errors":[],"online_cpus":2,"platform":"darwin","processes":[],"sockets":[],"softnet_counters":[],"softnet_drops":0,"swap_used_bytes":0,"udp_counters":[],"udp_errors":0,"uptime_seconds":100}`
	if err := os.WriteFile(before, []byte(snapshot+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, content string }{
		{name: "empty", content: ""},
		{name: "malformed", content: snapshot + "\n{bad\n"},
		{name: "counter increase", content: snapshot + "\n" + strings.Replace(snapshot, `"udp_errors":0`, `"udp_errors":1`, 1) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := filepath.Join(root, strings.ReplaceAll(tc.name, " ", "-")+".jsonl")
			verdict := watch + ".verdict"
			if err := os.WriteFile(watch, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", definitions+"\n"+`validate_health_watch "$1" "$2" "$3"`, "probe", before, watch, verdict)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("invalid health watch accepted; output=%s verdict=%s", output, mustReadUDPArtifact(t, verdict))
			}
		})
	}
}

func TestUDPPeakPerformanceScopeBytesAreAcceptedByRealHelper(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "write_cleanup_scope() {", "\nwait_promotion_ready() {")
	root := t.TempDir()
	helper := filepath.Join(root, "udppeak")
	build := exec.Command("go", "build", "-trimpath", "-o", helper, "../tools/udppeak")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real udppeak helper: %v\n%s", err, output)
	}
	reference := filepath.Join(root, "process.ref.json")
	referenceBytes := []byte(`{"name":"derphole","pid":999999,"start_identity":"test-start","executable_identity":"/fake/derphole"}` + "\n")
	if err := os.WriteFile(reference, referenceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	scope := filepath.Join(root, "scope.json")
	write := exec.Command("bash", "-c", definitions+"\n"+`write_process_scope "$1" "$2"`, "probe", reference, scope)
	if output, err := write.CombinedOutput(); err != nil {
		t.Fatalf("write cleanup scope: %v\n%s", err, output)
	}
	command := exec.Command(helper, "health-snapshot", "-workdir", root, "-interface", "test0", "-scope", scope)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "health-snapshot requires -out") || strings.Contains(string(output), "load cleanup scope") {
		t.Fatalf("real helper rejected generated cleanup scope before normal flag validation: err=%v\n%s\nscope=%s", err, output, mustReadUDPArtifact(t, scope))
	}
	emptyScope := filepath.Join(root, "empty-scope.json")
	write = exec.Command("bash", "-c", definitions+"\n"+`write_cleanup_scope "$1"`, "probe", emptyScope)
	if output, err := write.CombinedOutput(); err != nil {
		t.Fatalf("write empty cleanup scope: %v\n%s", err, output)
	}
	command = exec.Command(helper, "health-snapshot", "-workdir", root, "-interface", "test0", "-scope", emptyScope)
	output, err = command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "health-snapshot requires -out") || strings.Contains(string(output), "load cleanup scope") {
		t.Fatalf("real helper rejected generated empty cleanup scope: err=%v\n%s\nscope=%s", err, output, mustReadUDPArtifact(t, emptyScope))
	}
}

func assertUDPPeakPerformancePreStartFailure(t *testing.T, harness udpPeakPerformanceHarness) {
	t.Helper()
	runDir := filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control")
	if _, statErr := os.Stat(filepath.Join(runDir, "promotion.ready")); statErr != nil {
		t.Fatalf("pre-start failure did not reach the promotion ready gate: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(runDir, "promotion.start")); !os.IsNotExist(statErr) {
		t.Fatalf("pre-start failure published the transfer start gate: %v", statErr)
	}
	resultPath := filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json")
	var result map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, resultPath), &result); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if result["started"] != false || result["sink_size_bytes"] != float64(0) || result["goodput_mbps"] != float64(0) || result["wall_goodput_mbps"] != float64(0) {
		t.Fatalf("pre-start failure result contains transfer activity: %#v", result)
	}
	if result["source_sha256"] != "" || result["sink_sha256"] != "" {
		t.Fatalf("pre-start failure result contains payload digests: %#v", result)
	}
	assertSealedArtifact(t, resultPath)
	cleanupPath := filepath.Join(harness.outputRoot, "cleanup", "01-forward-frozen-control.json")
	var cleanup map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, cleanupPath), &cleanup); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if cleanup["driver_cleanup_success"] != false || cleanup["health_cleanup_success"] != false || cleanup["independent_cleanup_success"] != false {
		t.Fatalf("pre-start failure cleanup evidence claimed success: %#v", cleanup)
	}
	var campaign map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, filepath.Join(harness.outputRoot, "campaign-cleanup.json")), &campaign); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if campaign["local_process_cleanup_success"] != true || campaign["remote_cleanup_success"] != true {
		t.Fatalf("bounded campaign cleanup evidence = %#v", campaign)
	}
}

func assertUDPPeakPerformanceNoStartedTransfer(t *testing.T, harness udpPeakPerformanceHarness) {
	t.Helper()
	runDir := filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control")
	if _, statErr := os.Stat(filepath.Join(runDir, "promotion.start")); !os.IsNotExist(statErr) {
		t.Fatalf("identity failure published the transfer start gate: %v", statErr)
	}
	resultPath := filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json")
	var result map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, resultPath), &result); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if result["started"] != false || result["sink_size_bytes"] != float64(0) || result["goodput_mbps"] != float64(0) || result["wall_goodput_mbps"] != float64(0) {
		t.Fatalf("identity failure result contains transfer activity: %#v", result)
	}
	assertSealedArtifact(t, resultPath)
	campaignPath := filepath.Join(harness.outputRoot, "campaign-cleanup.json")
	var campaign map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, campaignPath), &campaign); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if campaign["local_process_cleanup_success"] != true || campaign["remote_cleanup_success"] != true {
		t.Fatalf("identity failure cleanup was not bounded: %#v", campaign)
	}
	assertSealedArtifact(t, campaignPath)
}

func assertRecordedPIDsAbsent(t *testing.T, path string) {
	t.Helper()
	for _, field := range strings.Fields(string(mustReadUDPArtifact(t, path))) {
		pid, err := strconv.Atoi(field)
		if err != nil {
			t.Fatalf("invalid recorded PID %q: %v", field, err)
		}
		if err := syscall.Kill(pid, 0); err == nil {
			t.Fatalf("recorded child PID %d is still present", pid)
		}
	}
}

func TestUDPPeakPerformanceBaselineHealthFailureIsBoundedAndSealed(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	if err := os.WriteFile(filepath.Join(harness.stateDir, "baseline-health-fail"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("baseline health failure published success:\n%s", output)
	}
	for _, noisy := range []string{"No such file or directory", "File exists", "Traceback"} {
		if strings.Contains(string(output), noisy) {
			t.Fatalf("baseline health failure cascaded into %q:\n%s", noisy, output)
		}
	}
	assertUDPPeakPerformancePreStartFailure(t, harness)
}

func TestUDPPeakPerformanceUnhealthyLocalReadySampleCannotStart(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	if err := os.WriteFile(filepath.Join(harness.stateDir, "local-ready-health-fail"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("unhealthy local ready sample published success:\n%s", output)
	}
	assertUDPPeakPerformancePreStartFailure(t, harness)
}

func TestUDPPeakPerformanceRemoteReferenceCopyFailureCannotStart(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	if err := os.WriteFile(filepath.Join(harness.stateDir, "fail-remote-child-ref-scp"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("failed remote reference copy published success:\n%s", output)
	}
	assertUDPPeakPerformancePreStartFailure(t, harness)
}

func TestUDPPeakPerformanceLocalWatcherIdentityFailureIsBounded(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	if err := os.WriteFile(filepath.Join(harness.stateDir, "fail-local-watch-identify"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("failed local watcher identity published success:\n%s", output)
	}
	assertUDPPeakPerformancePreStartFailure(t, harness)
}

func TestUDPPeakPerformanceIperfIdentityFailureIsBounded(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	if err := os.WriteFile(filepath.Join(harness.stateDir, "fail-iperf-identify"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("failed iperf identity published success:\n%s", output)
	}
	assertUDPPeakPerformanceNoStartedTransfer(t, harness)
	refPath := filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control", "iperf-server-1.ref.json")
	if _, statErr := os.Stat(refPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed iperf identity left a published reference: %v", statErr)
	}
	assertRecordedPIDsAbsent(t, filepath.Join(harness.stateDir, "iperf-server-pids"))
}

func TestUDPPeakPerformancePromotionIdentityFailureIsBounded(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	if err := os.WriteFile(filepath.Join(harness.stateDir, "fail-promotion-identify"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("failed promotion identity published success:\n%s", output)
	}
	assertUDPPeakPerformanceNoStartedTransfer(t, harness)
	refPath := filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control", "promotion.ref.json")
	if _, statErr := os.Stat(refPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed promotion identity left a published reference: %v", statErr)
	}
	assertRecordedPIDsAbsent(t, filepath.Join(harness.stateDir, "promotion-pids"))
}

func runUDPPeakPerformanceWithContext(t *testing.T, harness udpPeakPerformanceHarness, timeout time.Duration) ([]byte, error, error) {
	t.Helper()
	base := harness.command()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	command.Dir = base.Dir
	command.Env = base.Env
	output, err := command.CombinedOutput()
	return output, err, ctx.Err()
}

func assertUDPPeakPerformanceIndeterminatePromotionCleanup(t *testing.T, harness udpPeakPerformanceHarness, output []byte, commandErr, contextErr error) {
	t.Helper()
	if contextErr != nil {
		t.Fatalf("indeterminate promotion cleanup exceeded its bound: %v\n%s", contextErr, output)
	}
	if commandErr == nil {
		t.Fatalf("indeterminate promotion cleanup published success:\n%s", output)
	}
	runDir := filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control")
	if _, statErr := os.Stat(filepath.Join(runDir, "promotion.start")); !os.IsNotExist(statErr) {
		t.Fatalf("indeterminate promotion cleanup published start: %v", statErr)
	}
	refPath := filepath.Join(runDir, "promotion.ref.json")
	if _, statErr := os.Stat(refPath); statErr != nil {
		t.Fatalf("indeterminate promotion cleanup discarded its exact ref: %v", statErr)
	}
	resultPath := filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json")
	var result map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, resultPath), &result); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if result["started"] != false || result["sink_size_bytes"] != float64(0) || result["goodput_mbps"] != float64(0) {
		t.Fatalf("indeterminate promotion cleanup result = %#v", result)
	}
	assertSealedArtifact(t, resultPath)
	campaignPath := filepath.Join(harness.outputRoot, "campaign-cleanup.json")
	var campaign map[string]any
	if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, campaignPath), &campaign); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if cleanupSuccess, ok := campaign["local_process_cleanup_success"].(bool); !ok {
		t.Fatalf("promotion cleanup omitted its bounded outcome: %#v", campaign)
	} else if cleanupSuccess {
		assertRecordedPIDsAbsent(t, filepath.Join(harness.stateDir, "promotion-pids"))
	}
	assertSealedArtifact(t, campaignPath)
}

func TestUDPPeakPerformancePromotionReadinessCleanupIsBounded(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	for _, name := range []string{"promotion-no-ready", "promotion-ps-indeterminate", "fail-promotion-reidentify"} {
		if err := os.WriteFile(filepath.Join(harness.stateDir, name), []byte("1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, commandErr, contextErr := runUDPPeakPerformanceWithContext(t, harness, 18*time.Second)
	assertUDPPeakPerformanceIndeterminatePromotionCleanup(t, harness, output, commandErr, contextErr)
}

func TestUDPPeakPerformanceStartHealthCleanupIsBounded(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 0)
	for _, name := range []string{"local-ready-health-fail", "promotion-ps-indeterminate", "fail-promotion-reidentify"} {
		if err := os.WriteFile(filepath.Join(harness.stateDir, name), []byte("1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, commandErr, contextErr := runUDPPeakPerformanceWithContext(t, harness, 25*time.Second)
	assertUDPPeakPerformanceIndeterminatePromotionCleanup(t, harness, output, commandErr, contextErr)
}

func TestUDPPeakPerformancePersistentIndeterminatePublishedChildRetainsTracker(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definition := scriptSection(t, string(data), "stop_published_local_child_bounded() {", "\nwait_local_pid_bounded() {")
	ref := filepath.Join(t.TempDir(), "promotion.ref.json")
	script := definition + "\n" + `
set -euo pipefail
promotion_pid=123
promotion_ref="$1"
local_process_refs=("${promotion_ref}")
removed=0
terminate_local_process_ref() { return 1; }
stop_unidentified_local_child() { return 1; }
remove_local_process_ref() { removed=$((removed + 1)); local_process_refs=(); }
if stop_published_local_child_bounded "${promotion_pid}" "${promotion_ref}"; then
  remove_local_process_ref "${promotion_ref}"
  promotion_pid=""
  promotion_ref=""
fi
[[ "${promotion_pid}" == 123 ]]
[[ "${promotion_ref}" == "$1" ]]
[[ "${local_process_refs[0]}" == "$1" ]]
[[ "${removed}" == 0 ]]
`
	cmd := exec.Command("bash", "-c", script, "probe", ref)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("persistent indeterminate child discarded its exact tracker: %v\n%s", err, output)
	}
}

func TestUDPPeakPerformanceStartsRemoteSSHAsDirectTrackedChild(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "build_remote_clean_command() {", "\nremove_local_process_ref() {")
	root := t.TempDir()
	fakeBin := filepath.Join(root, "bin")
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "ssh"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$$" >"${FAKE_SSH_STATE}/pid"
printf '%s\n' "${PPID}" >"${FAKE_SSH_STATE}/ppid"
printf '%s\n' "$@" >"${FAKE_SSH_STATE}/argv"
cat >"${FAKE_SSH_STATE}/stdin"
: >"${FAKE_SSH_STATE}/ready"
for _ in $(seq 1 500); do
  [[ -e "${FAKE_SSH_STATE}/stop" ]] && exit 0
  sleep 0.01
done
exit 99
`)

	probe := definitions + "\n" + `
set -euo pipefail
remote_target=stub@example
unidentified_local_pids=()
remote_watch_pid=""
cleanup_fake_ssh() {
  : >"${FAKE_SSH_STATE}/stop"
  if [[ -n "${remote_watch_pid}" ]]; then
    kill -TERM -- "${remote_watch_pid}" 2>/dev/null || true
    wait "${remote_watch_pid}" 2>/dev/null || true
  fi
}
trap cleanup_fake_ssh EXIT
start_remote_clean_child remote_watch_pid 'printf "%s\n" "$1"' safe/argument
for _ in $(seq 1 200); do [[ -e "${FAKE_SSH_STATE}/ready" ]] && break; sleep 0.01; done
[[ -e "${FAKE_SSH_STATE}/ready" ]]
[[ "$(cat "${FAKE_SSH_STATE}/pid")" == "${remote_watch_pid}" ]]
[[ "$(cat "${FAKE_SSH_STATE}/ppid")" == "$$" ]]
[[ "${#unidentified_local_pids[@]}" == 1 ]]
[[ "${unidentified_local_pids[0]}" == "${remote_watch_pid}" ]]
cat >"${FAKE_SSH_STATE}/expected.argv" <<'EOF'
-o
BatchMode=yes
--
stub@example
env -i HOME=$HOME PATH=$PATH TMPDIR=${TMPDIR:-/tmp} bash -se -- safe/argument
EOF
cmp "${FAKE_SSH_STATE}/expected.argv" "${FAKE_SSH_STATE}/argv"
printf 'printf "%%s\\n" "$1"\n' >"${FAKE_SSH_STATE}/expected.stdin"
cmp "${FAKE_SSH_STATE}/expected.stdin" "${FAKE_SSH_STATE}/stdin"
: >"${FAKE_SSH_STATE}/stop"
wait "${remote_watch_pid}"
remote_watch_pid=""
trap - EXIT
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", "-c", probe, "probe")
	command.Env = append(os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_SSH_STATE="+state,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("remote SSH was not the directly tracked child: %v\n%s", err, output)
	}

	unsafeState := filepath.Join(root, "unsafe-state")
	if err := os.MkdirAll(unsafeState, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeProbe := definitions + "\n" + `
set -euo pipefail
remote_target=stub@example
unidentified_local_pids=()
unsafe_pid=""
cleanup_fake_ssh() {
  : >"${FAKE_SSH_STATE}/stop"
  if [[ -n "${unsafe_pid}" ]]; then
    kill -TERM -- "${unsafe_pid}" 2>/dev/null || true
    wait "${unsafe_pid}" 2>/dev/null || true
  elif [[ -s "${FAKE_SSH_STATE}/pid" ]]; then
    kill -TERM -- "$(cat "${FAKE_SSH_STATE}/pid")" 2>/dev/null || true
  fi
}
trap cleanup_fake_ssh EXIT
if start_remote_clean_child unsafe_pid ':' 'unsafe argument'; then exit 90; fi
[[ -z "${unsafe_pid}" ]]
[[ "${#unidentified_local_pids[@]}" == 0 ]]
[[ ! -e "${FAKE_SSH_STATE}/pid" ]]
trap - EXIT
`
	unsafeCtx, unsafeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer unsafeCancel()
	command = exec.CommandContext(unsafeCtx, "bash", "-c", unsafeProbe, "probe")
	command.Env = append(os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_SSH_STATE="+unsafeState,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unsafe remote argument launched SSH: %v\n%s", err, output)
	}
}

func TestUDPPeakPerformanceRemoteWatcherCleanupIsIdempotent(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "cleanup_remote_watch() {", "\ncleanup_campaign() {")
	root := t.TempDir()
	base := filepath.Join(root, "health")
	cleanup := base + ".cleanup.json"
	contents := []byte(`{"exact_processes_absent":false,"schema_version":1}` + "\n")
	if err := os.WriteFile(cleanup, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "helper")
	writeExecutable(t, helper, "#!/bin/sh\nexit 1\n")
	script := definitions + "\n" + `
remote_udppeak="$1"
remote_clean() {
  local source="$1"
  shift
  bash -se -- "$@" <<<"${source}"
}
cleanup_remote_watch "$2"
`
	cmd := exec.Command("bash", "-c", script, "probe", helper, base)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("previous failed watcher cleanup became successful:\n%s", output)
	}
	if strings.Contains(string(output), "File exists") || strings.Contains(string(output), "Traceback") {
		t.Fatalf("idempotent watcher cleanup re-created immutable evidence:\n%s", output)
	}
	if got := mustReadUDPArtifact(t, cleanup); !reflect.DeepEqual(got, contents) {
		t.Fatalf("watcher cleanup evidence mutated:\n%s", got)
	}
}

func TestUDPPeakPerformanceChildCleanupRequiresExactRoleDigests(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "sha256_file() {", "\nwrite_cleanup_evidence() {")
	roles := []string{"local-runstats", "local-derphole", "wrapper", "runstats", "derphole"}
	build := func(t *testing.T, corrupt bool) (string, string) {
		t.Helper()
		root := t.TempDir()
		refsRoot := filepath.Join(root, "process-refs")
		if err := os.Mkdir(refsRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		references := make([]map[string]string, 0, len(roles))
		for index, role := range roles {
			path := filepath.Join(refsRoot, role+".ref.json")
			contents := fmt.Sprintf(`{"executable_identity":"/fake/%s","name":"%s","pid":%d,"start_identity":"start-%s"}`+"\n", role, role, 100+index, role)
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			digest := testFileSHA256(t, path)
			if err := os.WriteFile(path+".sha256", []byte(digest+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			references = append(references, map[string]string{"role": role, "sha256": digest})
		}
		if corrupt {
			references[2]["sha256"] = strings.Repeat("0", 64)
		}
		cleanup := map[string]any{"identity_cleanup_complete": true, "references": references, "schema_version": 1, "success": true}
		contents, err := json.Marshal(cleanup)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "child-cleanup.json")
		if err := os.WriteFile(path, append(contents, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return root, testFileSHA256(t, path)
	}
	t.Run("accepts exact role and digest binding", func(t *testing.T) {
		root, digest := build(t, false)
		cmd := exec.Command("bash", "-c", definitions+"\n"+`validate_child_cleanup_evidence "$1" "$2"`, "probe", root, digest)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("exact cleanup binding rejected: %v\n%s", err, output)
		}
	})
	t.Run("rejects digest substitution", func(t *testing.T) {
		root, digest := build(t, true)
		cmd := exec.Command("bash", "-c", definitions+"\n"+`validate_child_cleanup_evidence "$1" "$2"`, "probe", root, digest)
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("substituted cleanup digest accepted: %s", output)
		}
	})
}

func TestUDPPeakPerformanceRequiresRemoteResourceTelemetry(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "validate_remote_resource_footer() {", "\nwrite_result() {")
	cmd := exec.Command("bash", "-c", definitions+"\n"+`validate_remote_resource_footer forward false 1.0 1.0 1 false 1.0 1.0 1`, "probe")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("unavailable remote resource telemetry accepted: %s", output)
	}
}

func TestUDPPeakPerformancePostCleanupSnapshotsRejectErrorProcessAndSocket(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "validate_post_cleanup_snapshot() {", "\nverify_child_cleanup_absence() {")
	root := t.TempDir()
	scope := filepath.Join(root, "scope.json")
	scopeJSON := `{"cgroups":[],"declared":true,"processes":[{"executable_identity":"/fake/derphole","name":"derphole","pid":123,"start_identity":"start-123"}]}`
	if err := os.WriteFile(scope, []byte(scopeJSON+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := `{"cleanup_scope":` + scopeJSON + `,"processes":%s,"sockets":%s}`
	cases := []struct {
		name     string
		contents *string
	}{
		{name: "helper error", contents: nil},
		{name: "exact process", contents: stringPointer(fmt.Sprintf(base, `[ {"executable_identity":"/fake/derphole","name":"derphole","pid":123,"start_identity":"start-123"} ]`, `[]`))},
		{name: "exact socket", contents: stringPointer(fmt.Sprintf(base, `[]`, `[{"pid":123}]`))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := filepath.Join(root, strings.ReplaceAll(tc.name, " ", "-")+".json")
			if tc.contents != nil {
				if err := os.WriteFile(snapshot, []byte(*tc.contents+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", definitions+"\n"+`validate_post_cleanup_snapshot "$1" "$2"`, "probe", scope, snapshot)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("unsafe post-cleanup snapshot accepted: %s", output)
			}
		})
	}
}

func stringPointer(value string) *string { return &value }

func TestUDPPeakPerformanceIndeterminateIperfCleanupRetainsReference(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "run_capacity_control() {", "\nensure_payloads() {")
	root := t.TempDir()
	script := definitions + "\n" + `
set -euo pipefail
capacity_attempts=1
tcp_port=8123
local_public=1.1.1.1
last_capacity=""
local_process_refs=()
unidentified_local_pids=()
removed=0
iperf3() { return 0; }
sleep() { :; }
identify_local_process() {
  printf '{"executable_identity":"/fake/iperf3","name":"iperf3","pid":%s,"start_identity":"start-%s"}\n' "$2" "$2" >"$3"
}
remote_clean() { return 1; }
remove_unidentified_local_pid() { :; }
publish_local_process_ref() { local_process_refs+=("$2"); remove_unidentified_local_pid "$1"; }
stop_unidentified_local_child() { return 0; }
terminate_local_process_ref() { return 1; }
remove_local_process_ref() { removed=$((removed + 1)); }
set +e
run_capacity_control forward "$1"
run_status=$?
set -e
[[ "${run_status}" == 1 ]]
[[ "${#local_process_refs[@]}" == 1 ]]
[[ "${local_process_refs[0]}" == "$1/iperf-server-1.ref.json" ]]
[[ "${removed}" == 0 ]]
`
	cmd := exec.Command("bash", "-c", script, "probe", root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("indeterminate iperf cleanup was discarded: %v\n%s", err, output)
	}
}

func TestUDPPeakPerformanceBoundedWaitPropagatesIndeterminateIdentity(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "wait_local_pid_bounded() {", "\ncleanup_remote_watch() {")
	script := definitions + "\n" + `
set -euo pipefail
local_pid_running() { return 0; }
sleep() { :; }
terminate_calls=0
terminate_local_process_ref() { terminate_calls=$((terminate_calls + 1)); return 1; }
set +e
wait_local_pid_bounded 123 "$1"
wait_status=$?
set -e
[[ "${wait_status}" == 2 ]]
[[ "${terminate_calls}" == 1 ]]
`
	cmd := exec.Command("bash", "-c", script, "probe", filepath.Join(t.TempDir(), "watch.ref.json"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bounded wait discarded indeterminate identity: %v\n%s", err, output)
	}
}

func TestUDPPeakPerformanceUnidentifiedChildInspectionFailureIsBounded(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "local_pid_running() {", "\nprocess_ref_field() {")
	script := definitions + "\n" + `
set -euo pipefail
kill_calls=0
sleep_calls=0
wait_calls=0
kill() { kill_calls=$((kill_calls + 1)); return 0; }
ps() { return 1; }
sleep() { sleep_calls=$((sleep_calls + 1)); }
wait() { wait_calls=$((wait_calls + 1)); return 0; }
set +e
stop_unidentified_local_child 123
stop_status=$?
set -e
[[ "${stop_status}" == 1 ]]
[[ "${wait_calls}" == 0 ]]
[[ "${sleep_calls}" == 160 ]]
[[ "${kill_calls}" == 162 ]]
`
	cmd := exec.Command("bash", "-c", script, "probe")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("indeterminate direct-child inspection was not bounded: %v\n%s", err, output)
	}
}

func TestUDPPeakPerformanceIndeterminateWatcherCleanupRetainsReference(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "stop_health() {", "\nvalidate_health_watch() {")
	for _, role := range []string{"local-watcher", "remote-ssh-watcher"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			localRef := filepath.Join(root, "local-watch.ref.json")
			remoteRef := filepath.Join(root, "remote-ssh-watch.ref.json")
			indeterminateRef := localRef
			if role == "remote-ssh-watcher" {
				indeterminateRef = remoteRef
			}
			script := definitions + "\n" + `
set -euo pipefail
root="$1"
run_dir="$1/run"
mkdir -p "${run_dir}"
local_scope="${run_dir}/local-scope.json"
remote_scope="${run_dir}/remote-scope.json"
printf '%s\n' '{"cgroups":[],"declared":true,"processes":[]}' >"${local_scope}"
printf '%s\n' '{"cgroups":[],"declared":true,"processes":[]}' >"${remote_scope}"
local_watch_pid=101
remote_watch_pid=102
local_watch_ref="$2"
remote_watch_ref="$3"
indeterminate_ref="$4"
local_process_refs=("${local_watch_ref}" "${remote_watch_ref}")
health_remote_base="${run_dir}/remote-health"
remote_root="${root}/remote"
remote_udppeak=/usr/bin/false
remote_interface=eth0
local_udppeak=/usr/bin/false
local_interface=en0
remote_target=fake@example
size_bytes=1073741824
removed=""
wait_local_pid_bounded() { [[ "$2" == "${indeterminate_ref}" ]] && return 2; return 0; }
remove_local_process_ref() {
  removed="${removed}$1\n"
  local remove="$1" reference kept=()
  for reference in "${local_process_refs[@]}"; do [[ "${reference}" == "${remove}" ]] || kept+=("${reference}"); done
  local_process_refs=("${kept[@]}")
}
remote_clean() { return 0; }
cleanup_remote_watch() { return 0; }
scp() { return 1; }
sha256_file() { printf 'missing\n'; }
validate_health_watch() { return 1; }
stop_health "${run_dir}" "${local_scope}" "${remote_scope}" || true
[[ " ${local_process_refs[*]} " == *" ${indeterminate_ref} "* ]]
[[ "${removed}" != *"${indeterminate_ref}"* ]]
[[ "${health_status}" == 1 ]]
`
			cmd := exec.Command("bash", "-c", script, "probe", root, localRef, remoteRef, indeterminateRef)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("indeterminate %s reference was discarded: %v\n%s", role, err, output)
			}
		})
	}
}

func TestUDPPeakPerformanceCampaignEvidenceRejectsIndeterminateLocalCleanup(t *testing.T) {
	data := mustReadUDPArtifact(t, filepath.Join(".", "udp-peak-performance.sh"))
	definitions := scriptSection(t, string(data), "cleanup_campaign() {", "\ntrap cleanup_campaign EXIT INT TERM")
	root := t.TempDir()
	ref := filepath.Join(root, "iperf.ref.json")
	script := definitions + "\n" + `
root="$1"
remote_root=""
health_remote_base=""
local_process_refs=("$2")
unidentified_local_pids=()
terminate_local_process_ref() { return 1; }
seal_artifact() { return 0; }
cleanup_campaign
`
	cmd := exec.Command("bash", "-c", script, "probe", root, ref)
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("campaign with indeterminate cleanup succeeded:\n%s", output)
	}
	var evidence map[string]any
	if err := json.Unmarshal(mustReadUDPArtifact(t, filepath.Join(root, "campaign-cleanup.json")), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["local_process_cleanup_success"] != false {
		t.Fatalf("campaign evidence claimed or omitted indeterminate local cleanup: %#v", evidence)
	}
}

func TestUDPPeakPerformanceNeverPublishesSuccessWithoutIndependentCleanupAbsence(t *testing.T) {
	for _, mode := range []string{"local-helper-error", "remote-helper-error", "local-process", "remote-socket"} {
		t.Run(mode, func(t *testing.T) {
			harness := newUDPPeakPerformanceHarness(t, 2200, 0)
			if err := os.WriteFile(filepath.Join(harness.stateDir, "post-cleanup-mode"), []byte(mode+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := harness.command().CombinedOutput()
			if err == nil {
				t.Fatalf("unsafe post-cleanup observation published success:\n%s", output)
			}
			resultPath := filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json")
			var result map[string]any
			if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, resultPath), &result); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			if result["success"] == true {
				t.Fatalf("unsafe post-cleanup result marked successful: %#v", result)
			}
			cleanupPath := filepath.Join(harness.outputRoot, "cleanup", "01-forward-frozen-control.json")
			var cleanup map[string]any
			if unmarshalErr := json.Unmarshal(mustReadUDPArtifact(t, cleanupPath), &cleanup); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			if cleanup["independent_cleanup_success"] != false {
				t.Fatalf("unsafe post-cleanup evidence was accepted: %#v", cleanup)
			}
		})
	}
}

func TestUDPPeakPerformanceThreeLowControlsPostponeWithoutUDP(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 1900, 0)
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("low-capacity preliminary comparison succeeded:\n%s", output)
	}
	if data, readErr := os.ReadFile(filepath.Join(harness.stateDir, "promotion-events")); !os.IsNotExist(readErr) {
		t.Fatalf("low capacity started UDP: error=%v events=%q", readErr, data)
	}
	data, err := os.ReadFile(filepath.Join(harness.stateDir, "iperf-events"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(string(data))); got != 3 {
		t.Fatalf("capacity attempts = %d, want 3", got)
	}
	resultData, err := os.ReadFile(filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(resultData, &result); err != nil {
		t.Fatal(err)
	}
	if result["started"] != false || result["status"] != float64(75) {
		t.Fatalf("postponed result = %#v", result)
	}
	if result["registry_sha256"] != harness.registrySHA {
		t.Fatalf("postponed registry digest = %#v, want %s", result["registry_sha256"], harness.registrySHA)
	}
	for _, path := range []string{
		filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json"),
		filepath.Join(harness.outputRoot, "results.csv"),
		filepath.Join(harness.outputRoot, "comparison.csv"),
		filepath.Join(harness.outputRoot, "campaign-cleanup.json"),
	} {
		assertSealedArtifact(t, path)
	}
	registryCopy := filepath.Join(harness.outputRoot, "registry.json")
	if got := strings.TrimSpace(string(mustReadUDPArtifact(t, filepath.Join(harness.outputRoot, "registry.sha256")))); got != testFileSHA256(t, registryCopy) || got != harness.registrySHA {
		t.Fatalf("sealed registry digest = %q, want %s", got, harness.registrySHA)
	}
	assertReadOnly(t, registryCopy)
	assertReadOnly(t, filepath.Join(harness.outputRoot, "registry.sha256"))
}

func TestUDPPeakPerformanceRunsFixedRotationAndRetainsStartedFailure(t *testing.T) {
	harness := newUDPPeakPerformanceHarness(t, 2200, 2)
	output, err := harness.command().CombinedOutput()
	if err == nil {
		t.Fatalf("comparison with a started failure succeeded:\n%s", output)
	}
	events, err := os.ReadFile(filepath.Join(harness.stateDir, "promotion-events"))
	if err != nil {
		t.Fatalf("read promotion events: %v\n%s", err, output)
	}
	wantBlock := []string{
		"forward frozen-control", "forward combined-gso3", "forward combined-gso3", "forward frozen-control", "forward combined-gso3", "forward frozen-control",
		"reverse frozen-control", "reverse combined-gso3", "reverse combined-gso3", "reverse frozen-control", "reverse combined-gso3", "reverse frozen-control",
	}
	gotBlock := strings.FieldsFunc(strings.TrimSpace(string(events)), func(r rune) bool { return r == '\n' })
	if !reflect.DeepEqual(gotBlock, wantBlock) {
		promotionError, _ := os.ReadFile(filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control", "promotion.err"))
		resultError, _ := os.ReadFile(filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json"))
		cleanupError, _ := os.ReadFile(filepath.Join(harness.outputRoot, "cleanup", "01-forward-frozen-control.json"))
		localWatchError, _ := os.ReadFile(filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control", "local-watch.err"))
		remoteWatchError, _ := os.ReadFile(filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control", "remote-watch.err"))
		healthStatus, _ := os.ReadFile(filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control", "health-status.json"))
		var evidencePaths []string
		_ = filepath.Walk(filepath.Join(harness.outputRoot, "runs", "01-forward-frozen-control"), func(path string, _ os.FileInfo, _ error) error {
			evidencePaths = append(evidencePaths, path)
			return nil
		})
		t.Fatalf("promotion order = %#v, want %#v\noutput=%s\npromotion=%s\nresult=%s\ncleanup=%s\nlocal-watch=%s\nremote-watch=%s\nhealth=%s\npaths=%v", gotBlock, wantBlock, output, promotionError, resultError, cleanupError, localWatchError, remoteWatchError, healthStatus, evidencePaths)
	}
	udppeakCalls := strings.Split(strings.TrimSpace(string(mustReadUDPArtifact(t, filepath.Join(harness.stateDir, "udppeak-calls")))), "\n")
	for runIndex, event := range wantBlock {
		fields := strings.Fields(event)
		runID := fmt.Sprintf("%02d-%s-%s", runIndex+1, fields[0], fields[1])
		wantCall := "health-snapshot\t" + filepath.Join(harness.outputRoot, "runs", runID, "local-after.json")
		count := 0
		for _, call := range udppeakCalls {
			if call == wantCall {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s local-after snapshot attempts = %d, want exactly one\nall calls=%q", runID, count, udppeakCalls)
		}
	}
	timeline := strings.Split(strings.TrimSpace(string(mustReadUDPArtifact(t, filepath.Join(harness.stateDir, "timeline")))), "\n")
	allocationIndex := -1
	for index, event := range timeline {
		if event == "payload-allocation" {
			allocationIndex = index
			break
		}
	}
	if allocationIndex < 2 || timeline[0] != "capacity-check" || timeline[1] != "capacity-check" {
		t.Fatalf("pre-allocation disk capacity timeline = %#v", timeline)
	}
	revisionData, err := os.ReadFile(filepath.Join(harness.stateDir, "revision-events"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(revisionData)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("candidate revision label = %q, want candidate and revision", line)
		}
		wantRevision := strings.Repeat("b", 40)
		if fields[0] == "frozen-control" {
			wantRevision = strings.Repeat("a", 40)
		}
		if fields[1] != wantRevision {
			t.Fatalf("candidate revision label = %q, want %s", line, wantRevision)
		}
	}
	traceData, err := os.ReadFile(filepath.Join(harness.stateDir, "trace-events"))
	if err != nil {
		t.Fatal(err)
	}
	traceLines := strings.Split(strings.TrimSpace(string(traceData)), "\n")
	if len(traceLines) != 22 {
		t.Fatalf("trace validations = %d, want 22", len(traceLines))
	}
	traceIndex := 0
	for runIndex, event := range wantBlock {
		if runIndex == 1 { // The deliberately failed started transfer is retained without trace validation.
			continue
		}
		candidate := strings.Fields(event)[1]
		for _, traceLine := range traceLines[traceIndex : traceIndex+2] {
			hasEfficiencyGate := strings.Contains(traceLine, "-require-engine-telemetry")
			if candidate == "frozen-control" && hasEfficiencyGate {
				t.Fatalf("frozen control required unavailable efficiency telemetry: %s", traceLine)
			}
			if candidate == "combined-gso3" && !hasEfficiencyGate {
				t.Fatalf("combined-gso3 omitted efficiency telemetry gate: %s", traceLine)
			}
		}
		traceIndex += 2
	}
	resultData, err := os.ReadFile(filepath.Join(harness.outputRoot, "results", "02-forward-combined-gso3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(resultData, &result); err != nil {
		t.Fatal(err)
	}
	if result["started"] != true || result["status"] != float64(23) || result["cleanup_success"] != true {
		t.Fatalf("started failure result = %#v", result)
	}
	controlData, err := os.ReadFile(filepath.Join(harness.outputRoot, "results", "01-forward-frozen-control.json"))
	if err != nil {
		t.Fatal(err)
	}
	var control map[string]any
	if err := json.Unmarshal(controlData, &control); err != nil {
		t.Fatal(err)
	}
	if control["efficiency_telemetry_status"] != "unavailable" {
		t.Fatalf("control efficiency status = %#v, want unavailable", control["efficiency_telemetry_status"])
	}
	if control["hetz_cpu_seconds_per_gib"] != float64(2) || control["hetz_max_rss_bytes"] != float64(167772160) || control["resource_telemetry_status"] != "available" {
		t.Fatalf("forward Hetz efficiency = %#v", control)
	}
	for _, field := range []string{"bulk_native_send_attempts", "bulk_native_send_syscalls", "bulk_gso_messages", "bulk_logical_datagrams", "bulk_accepted_payload_bytes", "bulk_gso_segments_per_message"} {
		if value, exists := control[field]; !exists || value != nil {
			t.Fatalf("control %s = %#v exists=%v, want explicit null", field, value, exists)
		}
	}
	candidateData, err := os.ReadFile(filepath.Join(harness.outputRoot, "results", "03-forward-combined-gso3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var candidate map[string]any
	if err := json.Unmarshal(candidateData, &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate["efficiency_telemetry_status"] != "available" || candidate["bulk_native_send_attempts"] != float64(10) {
		t.Fatalf("candidate efficiency evidence = %#v", candidate)
	}
	if candidate["registry_sha256"] != harness.registrySHA {
		t.Fatalf("candidate registry digest = %#v, want %s", candidate["registry_sha256"], harness.registrySHA)
	}
	assertSealedArtifact(t, filepath.Join(harness.outputRoot, "results", "03-forward-combined-gso3.json"))
	assertSealedArtifact(t, filepath.Join(harness.outputRoot, "cleanup", "03-forward-combined-gso3.json"))
	assertSealedArtifact(t, filepath.Join(harness.outputRoot, "runs", "03-forward-combined-gso3", "child-cleanup.json"))
	var cleanup map[string]any
	if err := json.Unmarshal(mustReadUDPArtifact(t, filepath.Join(harness.outputRoot, "cleanup", "03-forward-combined-gso3.json")), &cleanup); err != nil {
		t.Fatal(err)
	}
	if cleanup["child_cleanup_success"] != true || cleanup["child_cleanup_sha256"] != testFileSHA256(t, filepath.Join(harness.outputRoot, "runs", "03-forward-combined-gso3", "child-cleanup.json")) {
		t.Fatalf("bound child cleanup evidence = %#v", cleanup)
	}
	resultsCSV, err := os.ReadFile(filepath.Join(harness.outputRoot, "results.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(resultsCSV)), "\n")); got != 13 {
		t.Fatalf("results.csv lines = %d, want 13", got)
	}
	comparison, err := os.ReadFile(filepath.Join(harness.outputRoot, "comparison.csv"))
	if err != nil || !strings.Contains(string(comparison), "forward,combined-gso3,3,2") {
		t.Fatalf("comparison.csv does not retain started failure: error=%v\n%s", err, comparison)
	}
	comparisonRows, err := csv.NewReader(strings.NewReader(string(comparison))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]int{}
	for index, name := range comparisonRows[0] {
		header[name] = index
	}
	for _, row := range comparisonRows[1:] {
		status := row[header["efficiency_telemetry_status"]]
		attempts := row[header["median_bulk_native_send_attempts"]]
		switch row[header["candidate_id"]] {
		case "frozen-control":
			if status != "unavailable" || attempts != "" {
				t.Fatalf("control comparison efficiency = status %q attempts %q", status, attempts)
			}
		case "combined-gso3":
			if status != "available" || attempts != "10.000" {
				t.Fatalf("candidate comparison efficiency = status %q attempts %q", status, attempts)
			}
		}
		if row[header["resource_telemetry_status"]] != "available" || row[header["median_hetz_cpu_seconds_per_gib"]] == "" || row[header["median_hetz_max_rss_bytes"]] == "" {
			t.Fatalf("comparison omitted Hetz CPU/RSS efficiency: %#v", row)
		}
	}
}

func assertSealedArtifact(t *testing.T, path string) {
	t.Helper()
	digest := strings.TrimSpace(string(mustReadUDPArtifact(t, path+".sha256")))
	if want := testFileSHA256(t, path); digest != want {
		t.Fatalf("artifact digest for %s = %q, want %s", path, digest, want)
	}
	assertReadOnly(t, path)
	assertReadOnly(t, path+".sha256")
}

func assertReadOnly(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("artifact %s mode = %o, want read-only", path, info.Mode().Perm())
	}
}

func mustReadUDPArtifact(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
