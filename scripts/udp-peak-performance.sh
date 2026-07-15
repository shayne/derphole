#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

size_bytes=1073741824
size_mib=1024
capacity_attempts=3
capacity_minimum_mbps=2050
sequence=(frozen-control combined-gso3 combined-gso3 frozen-control combined-gso3 frozen-control)
directions=(forward reverse)

usage() {
  cat >&2 <<'EOF'
usage: udp-peak-performance.sh preliminary --root ROOT --registry REGISTRY --registry-sha256 SHA256 --remote SSH_TARGET --remote-public IPV4 --local-public IPV4 --tcp-port PORT
EOF
}

validate_public_ipv4() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if address.version != 4 or not address.is_global or address.is_multicast:
    raise SystemExit(1)
if address in ipaddress.ip_network("100.64.0.0/10"):
    raise SystemExit(1)
PY
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required locally" >&2
    exit 1
  }
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

seal_artifact() {
  local path="$1" digest_path="${2:-$1.sha256}" digest
  [[ -f "${path}" && ! -L "${path}" && ! -e "${digest_path}" && ! -L "${digest_path}" ]] || return 1
  digest="$(sha256_file "${path}")"
  python3 - "${digest_path}" "${digest}" <<'PY'
import sys

with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(sys.argv[2] + "\n")
PY
  chmod a-w "${path}" "${digest_path}"
}

root=""
registry=""
registry_sha256=""
remote_target=""
remote_public=""
local_public=""
tcp_port=""
remote_root=""
local_udppeak=""
remote_udppeak=""
local_tracecheck=""
local_interface=""
remote_interface=""
source_file=""
remote_source=""
source_sha256=""
payloads_ready=0
campaign_cleanup_complete=0
health_remote_base=""
health_status=1
child_post_cleanup_status=1
local_watch_pid=""
local_watch_ref=""
remote_watch_pid=""
remote_watch_ref=""
promotion_pid=""
promotion_ref=""
transfer_started=false
process_recheck_sequence=0
local_process_refs=()
unidentified_local_pids=()
result_paths=()
candidate_rows=""
promotion_driver="${DERPHOLE_UDP_PEAK_PROMOTION_DRIVER:-./scripts/promotion-benchmark-driver.sh}"
preliminary_failed=0

build_remote_clean_command() {
  local output_variable="$1" argument built_command='env -i HOME=$HOME PATH=$PATH TMPDIR=${TMPDIR:-/tmp} bash -se --'
  shift
  for argument in "$@"; do
    [[ "${argument}" =~ ^[A-Za-z0-9_./:@+-]+$ ]] || { echo "unsafe remote positional argument" >&2; return 2; }
    built_command+=" ${argument}"
  done
  printf -v "${output_variable}" '%s' "${built_command}"
}

remote_clean() {
  local script="$1" remote_command=""
  shift
  build_remote_clean_command remote_command "$@" || return
  command ssh -o BatchMode=yes -- "${remote_target}" "${remote_command}" <<<"${script}"
}

start_remote_clean_child() {
  local output_variable="$1" script="$2" remote_command="" child_pid
  shift 2
  [[ "${output_variable}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 2
  build_remote_clean_command remote_command "$@" || return
  command ssh -o BatchMode=yes -- "${remote_target}" "${remote_command}" <<<"${script}" &
  child_pid="$!"
  unidentified_local_pids+=("${child_pid}")
  printf -v "${output_variable}" '%s' "${child_pid}"
}

remove_local_process_ref() {
  local remove="$1" reference kept=()
  for reference in "${local_process_refs[@]}"; do
    [[ "${reference}" == "${remove}" ]] || kept+=("${reference}")
  done
  local_process_refs=("${kept[@]}")
}

remove_unidentified_local_pid() {
  local remove="$1" pid kept=()
  for pid in "${unidentified_local_pids[@]}"; do
    [[ "${pid}" == "${remove}" ]] || kept+=("${pid}")
  done
  unidentified_local_pids=("${kept[@]}")
}

publish_local_process_ref() {
  local pid="$1" reference="$2"
  # Publish the exact reference before retiring the provisional PID tracker so
  # an asynchronous signal always observes at least one cleanup identity.
  local_process_refs+=("${reference}")
  remove_unidentified_local_pid "${pid}"
}

local_pid_running() {
  local pid="$1" state
  kill -0 "${pid}" 2>/dev/null || return 1
  state="$(ps -o stat= -p "${pid}" 2>/dev/null | tr -d '[:space:]')" || return 2
  [[ -n "${state}" ]] || return 2
  [[ "${state}" != Z* ]] || return 1
  return 0
}

stop_unidentified_local_child() {
  local pid="$1" state
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  # The unreaped PID is a child launched by this shell, so it cannot be reused
  # while this bounded stop sequence owns it. Failed or empty ps inspection is
  # indeterminate: only kill -0 failure or an observed zombie permits wait.
  for _ in $(seq 1 80); do
    if local_pid_running "${pid}"; then
      :
    else
      state=$?
      if ((state == 1)); then
        wait "${pid}" 2>/dev/null || true
        return 0
      fi
      ((state == 2)) || return 1
    fi
    sleep 0.05 || return 1
  done
  kill -TERM -- "${pid}" 2>/dev/null || return 1
  for _ in $(seq 1 40); do
    if local_pid_running "${pid}"; then
      :
    else
      state=$?
      if ((state == 1)); then
        wait "${pid}" 2>/dev/null || true
        return 0
      fi
      ((state == 2)) || return 1
    fi
    sleep 0.05 || return 1
  done
  kill -KILL -- "${pid}" 2>/dev/null || return 1
  for _ in $(seq 1 40); do
    if local_pid_running "${pid}"; then
      :
    else
      state=$?
      if ((state == 1)); then
        wait "${pid}" 2>/dev/null || true
        return 0
      fi
      ((state == 2)) || return 1
    fi
    sleep 0.05 || return 1
  done
  return 1
}

process_ref_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
print(value[sys.argv[2]])
PY
}

identify_local_process() {
  local name="$1" pid="$2" output="$3"
  "$local_udppeak" process-identify -name "$name" -pid "$pid" -timeout 5s -out "$output" >"${output}.sha256"
}

reidentify_local_process() {
  local reference="$1" name pid fresh
  name="$(process_ref_field "$reference" name)"
  pid="$(process_ref_field "$reference" pid)"
  process_recheck_sequence=$((process_recheck_sequence + 1))
  fresh="${reference}.recheck.${process_recheck_sequence}"
  if identify_local_process "$name" "$pid" "$fresh" 2>"${fresh}.err"; then
    cmp -s "$reference" "$fresh" && return 0
    return 1
  fi
  return 2
}

terminate_local_process_ref() {
  local reference="$1" pid state
  pid="$(process_ref_field "$reference" pid)"
  if reidentify_local_process "$reference"; then
    kill -TERM -- "$pid"
  else
    state=$?
    ((state == 1)) && return 0
    return 1
  fi
  for _ in $(seq 1 40); do
    if reidentify_local_process "$reference"; then
      :
    else
      state=$?
      ((state == 1)) && { wait "$pid" 2>/dev/null || true; return 0; }
      return 1
    fi
    sleep 0.05
  done
  if reidentify_local_process "$reference"; then
    kill -KILL -- "$pid"
  else
    state=$?
    ((state == 1)) && return 0
    return 1
  fi
  for _ in $(seq 1 40); do
    if reidentify_local_process "$reference"; then
      :
    else
      state=$?
      ((state == 1)) && { wait "$pid" 2>/dev/null || true; return 0; }
      return 1
    fi
    sleep 0.05
  done
  return 1
}

stop_published_local_child_bounded() {
  local pid="$1" reference="$2"
  # Prefer exact identity termination. The unreaped direct-child PID remains
  # safe for the bounded tri-state fallback if re-identification is unavailable.
  terminate_local_process_ref "${reference}" && return 0
  stop_unidentified_local_child "${pid}"
}

wait_local_pid_bounded() {
  local pid="$1" reference="$2" process_status=0 state
  for _ in $(seq 1 80); do
    if local_pid_running "${pid}"; then
      :
    else
      state=$?
      if ((state == 1)); then
        wait "${pid}" || process_status=$?
        return "${process_status}"
      fi
      ((state == 2)) || return 2
    fi
    sleep 0.05
  done
  if terminate_local_process_ref "${reference}"; then
    return 1
  fi
  return 2
}

cleanup_remote_watch() {
  local base="$1"
  remote_clean 'set +e
helper=$1
base=$2
status=0
sequence=0
if [[ -e "${base}.cleanup.json" || -L "${base}.cleanup.json" ]]; then
  [[ -f "${base}.cleanup.json" && ! -L "${base}.cleanup.json" ]] || exit 1
  python3 - "${base}.cleanup.json" <<"PY"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
complete = value.get("exact_processes_absent") is True or value.get("completed_and_waited") is True
raise SystemExit(0 if value.get("schema_version") == 1 and complete else 1)
PY
  exit $?
fi
same_process() {
  reference=$1
  name=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"name\"])" "${reference}") || return 2
  pid=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"pid\"])" "${reference}") || return 2
  sequence=$((sequence + 1))
  fresh="${reference}.cleanup-recheck.${sequence}"
  if "${helper}" process-identify -name "${name}" -pid "${pid}" -timeout 5s -out "${fresh}" >"${fresh}.sha256" 2>"${fresh}.err"; then
    cmp -s -- "${reference}" "${fresh}" && return 0
    return 1
  fi
  return 2
}
terminate_exact() {
  reference=$1
  [[ -f "${reference}" && ! -L "${reference}" ]] || return 1
  pid=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"pid\"])" "${reference}") || return 1
  if same_process "${reference}"; then
    kill -TERM -- "${pid}" || return 1
  else
    state=$?
    [[ "${state}" == 1 ]] && return 0
    return 1
  fi
  for _ in $(seq 1 40); do
    if same_process "${reference}"; then :; else state=$?; [[ "${state}" == 1 ]] && return 0; return 1; fi
    sleep 0.05
  done
  if same_process "${reference}"; then
    kill -KILL -- "${pid}" || return 1
  else
    state=$?
    [[ "${state}" == 1 ]] && return 0
    return 1
  fi
  for _ in $(seq 1 40); do
    if same_process "${reference}"; then :; else state=$?; [[ "${state}" == 1 ]] && return 0; return 1; fi
    sleep 0.05
  done
  return 1
}
terminate_exact "${base}.child.ref.json" || status=1
terminate_exact "${base}.wrapper.ref.json" || status=1
python3 - "${base}.cleanup.json" "${status}" <<"PY"
import json
import sys
with open(sys.argv[1], "x", encoding="utf-8") as output:
    json.dump({"exact_processes_absent": sys.argv[2] == "0", "schema_version": 1}, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
exit "${status}"' "${remote_udppeak}" "${base}"
}

cleanup_campaign() {
  local status="$?" pid reference local_status=0 remote_status=0 watch_status=0
  trap - EXIT INT TERM
  set +e
  for pid in "${unidentified_local_pids[@]}"; do
    if stop_unidentified_local_child "${pid}"; then
      remove_unidentified_local_pid "${pid}"
    else
      local_status=1
      status=1
    fi
  done
  for reference in "${local_process_refs[@]}"; do
    if terminate_local_process_ref "${reference}"; then
      remove_local_process_ref "${reference}"
    else
      local_status=1
      status=1
    fi
  done
  if [[ -n "${remote_root}" ]]; then
    if [[ -n "${health_remote_base}" ]] && ! cleanup_remote_watch "${health_remote_base}"; then
      watch_status=1
      status=1
    fi
    if ! remote_clean 'root=$1
case "${root}" in
  /tmp/derphole-udp-peak-v1.[A-Za-z0-9]*) rm -rf -- "${root}" && [[ ! -e "${root}" ]] ;;
  *) exit 1 ;;
esac' "${remote_root}"; then
      remote_status=1
      status=1
    fi
  fi
  if [[ -n "${root}" && -d "${root}" && ! -e "${root}/campaign-cleanup.json" ]]; then
    python3 - "${root}/campaign-cleanup.json" "${local_status}" "${remote_status}" "${watch_status}" <<'PY'
import json
import sys

path, local_status, remote_status, watch_status = sys.argv[1:]
with open(path, "x", encoding="utf-8") as output:
    json.dump({"local_process_cleanup_success": local_status == "0", "remote_cleanup_success": remote_status == "0", "remote_watcher_cleanup_success": watch_status == "0", "schema_version": 1}, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
    seal_artifact "${root}/campaign-cleanup.json" || status=1
  fi
  campaign_cleanup_complete=1
  exit "${status}"
}
trap cleanup_campaign EXIT INT TERM

parse_args() {
  [[ "${1:-}" == "preliminary" ]] || { usage; exit 2; }
  shift
  while (( $# > 0 )); do
    case "$1" in
      --root) [[ $# -ge 2 && -z "${root}" ]] || { usage; exit 2; }; root="$2"; shift 2 ;;
      --registry) [[ $# -ge 2 && -z "${registry}" ]] || { usage; exit 2; }; registry="$2"; shift 2 ;;
      --registry-sha256) [[ $# -ge 2 && -z "${registry_sha256}" ]] || { usage; exit 2; }; registry_sha256="$2"; shift 2 ;;
      --remote) [[ $# -ge 2 && -z "${remote_target}" ]] || { usage; exit 2; }; remote_target="$2"; shift 2 ;;
      --remote-public) [[ $# -ge 2 && -z "${remote_public}" ]] || { usage; exit 2; }; remote_public="$2"; shift 2 ;;
      --local-public) [[ $# -ge 2 && -z "${local_public}" ]] || { usage; exit 2; }; local_public="$2"; shift 2 ;;
      --tcp-port) [[ $# -ge 2 && -z "${tcp_port}" ]] || { usage; exit 2; }; tcp_port="$2"; shift 2 ;;
      *) usage; exit 2 ;;
    esac
  done
  if [[ -z "${root}" || -z "${registry}" || -z "${registry_sha256}" || -z "${remote_target}" || -z "${remote_public}" || -z "${local_public}" || -z "${tcp_port}" ]]; then
    usage
    exit 2
  fi
  [[ "${remote_target}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*(@[A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] || { echo "remote must be a safe SSH target" >&2; exit 2; }
  validate_public_ipv4 "${remote_public}" || { echo "remote-public must be a public IPv4 address" >&2; exit 2; }
  validate_public_ipv4 "${local_public}" || { echo "local-public must be a public IPv4 address" >&2; exit 2; }
  [[ "${tcp_port}" =~ ^[0-9]+$ ]] && ((tcp_port >= 1024 && tcp_port <= 65535)) || { echo "tcp-port must be from 1024 through 65535" >&2; exit 2; }
  [[ "${registry_sha256}" =~ ^[0-9a-f]{64}$ ]] || { echo "registry SHA-256 must be lowercase hexadecimal" >&2; exit 2; }
  [[ -f "${registry}" && ! -L "${registry}" ]] || { echo "registry is not a non-symlink regular file" >&2; exit 2; }
  [[ "$(sha256_file "${registry}")" == "${registry_sha256}" ]] || { echo "registry SHA-256 does not match exact bytes" >&2; exit 1; }
  [[ "${root}" == /* ]] || { echo "campaign root must be absolute" >&2; exit 2; }
  [[ ! -e "${root}" && ! -L "${root}" ]] || { echo "campaign root must not exist" >&2; exit 1; }
  [[ -d "$(dirname "${root}")" && ! -L "$(dirname "${root}")" ]] || { echo "campaign root parent must be a non-symlink directory" >&2; exit 2; }
}

load_candidates() {
  candidate_rows="$(python3 - "${registry}" <<'PY'
import json
import hashlib
import os
import re
import stat
import sys

registry_path = os.path.realpath(sys.argv[1])
registry_root = os.path.dirname(registry_path)
with open(registry_path, encoding="utf-8") as source:
    registry = json.load(source)
required_ids = {
    "frozen-control", "coalesced-gso3", "connected-gso3", "combined-gso1",
    "combined-gso2", "combined-gso3", "combined-gso4", "combined-gso6",
    "combined-gso8", "combined-gso12", "quic-control",
}
if registry.get("schema_version") != 1 or registry.get("control_id") != "frozen-control":
    raise SystemExit("registry schema or control identity is invalid")
source_revision = registry.get("source_revision", "")
if len(source_revision) != 40 or any(ch not in "0123456789abcdef" for ch in source_revision):
    raise SystemExit("registry source revision is invalid")
candidate_entries = registry.get("candidates", [])
candidate_ids = [entry.get("id") for entry in candidate_entries if isinstance(entry, dict)]
if len(candidate_ids) != len(required_ids) or len(set(candidate_ids)) != len(candidate_ids) or set(candidate_ids) != required_ids:
    raise SystemExit("registry must contain exactly the frozen control and ten candidates")
entries = {entry["id"]: entry for entry in candidate_entries}
expected_gso = {
    "frozen-control": 3, "coalesced-gso3": 3, "connected-gso3": 3,
    "combined-gso1": 1, "combined-gso2": 2, "combined-gso3": 3,
    "combined-gso4": 4, "combined-gso6": 6, "combined-gso8": 8,
    "combined-gso12": 12, "quic-control": 0,
}
for candidate_id in sorted(required_ids):
    entry = entries[candidate_id]
    commit = entry.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(f"registry {candidate_id} commit is invalid")
    if candidate_id != "frozen-control" and commit != source_revision:
        raise SystemExit(f"registry {candidate_id} revision does not match registry source")
    if entry.get("config") != {"candidate": candidate_id}:
        raise SystemExit(f"registry {candidate_id} config is invalid")
    want_engine = "quic-blocks-v1" if candidate_id == "quic-control" else "bulk-packets-v1"
    if entry.get("engine") != want_engine:
        raise SystemExit(f"registry {candidate_id} engine is invalid")
    if entry.get("gso_segments_per_message") != expected_gso[candidate_id]:
        raise SystemExit(f"registry {candidate_id} GSO metadata is invalid")
    is_control = candidate_id == "frozen-control"
    want_linker = "" if is_control else candidate_id
    want_profile = "frozen-bulk-gso3" if is_control else "benchmark-linker"
    if entry.get("linker_value", "") != want_linker or entry.get("configuration_profile") != want_profile:
        raise SystemExit(f"registry {candidate_id} linker metadata is invalid")
    binaries = []
    for key, platform, goos, goarch, filename in (
        ("darwin", "darwin-arm64", "darwin", "arm64", "derphole-darwin-arm64"),
        ("linux", "linux-amd64", "linux", "amd64", "derphole-linux-amd64"),
    ):
        binary = entry.get(key)
        if not isinstance(binary, dict) or binary.get("platform") != platform:
            raise SystemExit(f"registry {candidate_id} {key} identity is invalid")
        relative_path = binary.get("path", "")
        if relative_path != f"bin/{candidate_id}/{filename}":
            raise SystemExit(f"registry {candidate_id} {key} path is invalid")
        path = os.path.realpath(os.path.join(registry_root, relative_path))
        if os.path.commonpath((registry_root, path)) != registry_root or os.path.islink(os.path.join(registry_root, relative_path)):
            raise SystemExit(f"registry {candidate_id} {key} path escapes or is a symlink")
        try:
            path_status = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise SystemExit(f"registry {candidate_id} {key} path is unreadable: {error}")
        if not stat.S_ISREG(path_status.st_mode) or not path_status.st_mode & 0o111:
            raise SystemExit(f"registry {candidate_id} {key} path is not an executable regular file")
        digest = binary.get("sha256", "")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise SystemExit(f"registry {candidate_id} {key} digest is invalid")
        with open(path, "rb") as source:
            actual_digest = hashlib.sha256(source.read()).hexdigest()
        if actual_digest != digest:
            raise SystemExit(f"registry {candidate_id} {key} digest does not match bytes")
        if binary.get("vcs_revision") != commit or binary.get("vcs_modified") is not False:
            raise SystemExit(f"registry {candidate_id} {key} revision metadata is invalid")
        build_info_digest = binary.get("build_info_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", build_info_digest):
            raise SystemExit(f"registry {candidate_id} {key} build metadata digest is invalid")
        if binary.get("goos") != goos or binary.get("goarch") != goarch:
            raise SystemExit(f"registry {candidate_id} {key} Go platform metadata is invalid")
        if not isinstance(binary.get("go_version"), str) or not binary["go_version"]:
            raise SystemExit(f"registry {candidate_id} {key} Go version is invalid")
        if binary.get("module_path") != "github.com/shayne/derphole" or binary.get("command_path") != "github.com/shayne/derphole/cmd/derphole":
            raise SystemExit(f"registry {candidate_id} {key} Go module metadata is invalid")
        if not isinstance(binary.get("module_version"), str) or not binary["module_version"]:
            raise SystemExit(f"registry {candidate_id} {key} module version is invalid")
        configured_linker_value = binary.get("configured_linker_value", "")
        selector_state = binary.get("selector_state", "absent")
        if configured_linker_value != want_linker:
            raise SystemExit(f"registry {candidate_id} {key} binary selector is wrong")
        if (is_control and selector_state not in ("absent", "empty")) or (not is_control and selector_state != "linked"):
            raise SystemExit(f"registry {candidate_id} {key} selector state is wrong")
        binaries.extend((path, digest))
    if candidate_id in ("frozen-control", "combined-gso3"):
        trace_candidate = candidate_id if want_linker else "unavailable"
        print("\t".join((candidate_id, commit, entry["engine"], trace_candidate, *binaries)))
PY
)"
  [[ "$(wc -l <<<"${candidate_rows}" | tr -d '[:space:]')" == 2 ]] || { echo "candidate registry selection failed" >&2; exit 1; }
  local row id commit engine trace_candidate local_bin local_sha linux_bin linux_sha
  while IFS=$'\t' read -r id commit engine trace_candidate local_bin local_sha linux_bin linux_sha; do
    [[ -x "${local_bin}" && -x "${linux_bin}" ]] || { echo "candidate binary is missing or not executable" >&2; exit 1; }
    [[ "$(sha256_file "${local_bin}")" == "${local_sha}" ]] || { echo "${id} Darwin binary hash mismatch" >&2; exit 1; }
    [[ "$(sha256_file "${linux_bin}")" == "${linux_sha}" ]] || { echo "${id} Linux binary hash mismatch" >&2; exit 1; }
  done <<<"${candidate_rows}"
}

candidate_field() {
  local wanted="$1" field="$2"
  python3 - "${wanted}" "${field}" "${candidate_rows}" <<'PY'
import sys

wanted, field, rows = sys.argv[1:]
fields = {"commit": 1, "engine": 2, "trace_candidate": 3, "local_bin": 4, "local_sha": 5, "linux_bin": 6, "linux_sha": 7}
for line in rows.splitlines():
    values = line.split("\t")
    if values[0] == wanted:
        print(values[fields[field]])
        raise SystemExit(0)
raise SystemExit(1)
PY
}

setup_tools_and_remote() {
  for command_name in awk cmp dd df iperf3 mise ps python3 scp shasum ssh; do require_command "${command_name}"; done
  remote_clean 'for command_name in awk cat cmp df getconf ip iperf3 mktemp python3 sha256sum ss; do command -v "${command_name}" >/dev/null || { echo "${command_name} is required remotely" >&2; exit 1; }; done'
  mkdir -m 0700 "${root}"
  mkdir -p "${root}/tools" "${root}/runs" "${root}/results" "${root}/cleanup"
  cp "${registry}" "${root}/registry.json"
  [[ "$(sha256_file "${root}/registry.json")" == "${registry_sha256}" ]] || { echo "copied registry SHA-256 changed" >&2; exit 1; }
  printf '%s\n' "${registry_sha256}" >"${root}/registry.sha256"
  chmod a-w "${root}/registry.json" "${root}/registry.sha256"
  local_udppeak="${root}/tools/udppeak-darwin-arm64"
  remote_udppeak=""
  local_tracecheck="${root}/tools/transfertracecheck-darwin-arm64"
  mise exec -- go build -trimpath -o "${local_udppeak}" ./tools/udppeak
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -trimpath -o "${root}/tools/udppeak-linux-amd64" ./tools/udppeak
  mise exec -- go build -trimpath -o "${local_tracecheck}" ./tools/transfertracecheck
  remote_root="$(remote_clean 'mktemp -d /tmp/derphole-udp-peak-v1.XXXXXXXX')"
  [[ "${remote_root}" =~ ^/tmp/derphole-udp-peak-v1\.[A-Za-z0-9]+$ ]] || { echo "remote scoped root is invalid" >&2; exit 1; }
  remote_udppeak="${remote_root}/udppeak"
  scp -- "${root}/tools/udppeak-linux-amd64" "${remote_target}:${remote_udppeak}.upload" >/dev/null
  remote_clean 'upload=$1
destination=$2
install -m 0755 -- "${upload}" "${destination}"
rm -f -- "${upload}"' "${remote_udppeak}.upload" "${remote_udppeak}"
  [[ "$(remote_clean 'sha256sum -- "$1" | awk "{print \$1}"' "${remote_udppeak}")" == "$(sha256_file "${root}/tools/udppeak-linux-amd64")" ]] || { echo "remote udppeak helper hash mismatch" >&2; exit 1; }
  local_interface="$(route -n get "${remote_public}" 2>/dev/null | awk '/interface:/{print $2; exit}')"
  remote_interface="$(remote_clean 'route=$(ip route get "$1")
set -- ${route}
while (( $# > 1 )); do
  if [[ "$1" == dev ]]; then printf "%s\n" "$2"; exit 0; fi
  shift
done
exit 1' "${local_public}")"
  [[ -n "${local_interface}" && -n "${remote_interface}" ]] || { echo "failed to resolve benchmark interfaces" >&2; exit 1; }
  remote_source="${remote_root}/source.bin"
}

parse_iperf_mbps() {
  python3 - "$1" <<'PY'
import json
import math
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
rate = float(value["end"]["sum_received"]["bits_per_second"]) / 1_000_000.0
if not math.isfinite(rate) or rate < 0:
    raise SystemExit(1)
print(f"{rate:.3f}")
PY
}

capacity_passes() {
  python3 - "$1" "${capacity_minimum_mbps}" <<'PY'
import sys
raise SystemExit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)
PY
}

run_capacity_control() {
  local direction="$1" run_dir="$2" attempt server_pid server_ref output capacity reverse_args=()
  [[ "${direction}" == "forward" ]] && reverse_args=(-R)
  last_capacity=""
  for attempt in $(seq 1 "${capacity_attempts}"); do
    output="${run_dir}/iperf-attempt-${attempt}.json"
    iperf3 -s -4 -p "${tcp_port}" --one-off --forceflush >"${run_dir}/iperf-server-${attempt}.log" 2>&1 &
    server_pid="$!"
    unidentified_local_pids+=("${server_pid}")
    server_ref="${run_dir}/iperf-server-${attempt}.ref.json"
    if identify_local_process iperf3 "${server_pid}" "${server_ref}"; then
      publish_local_process_ref "${server_pid}" "${server_ref}"
    else
      if stop_unidentified_local_child "${server_pid}"; then
        remove_unidentified_local_pid "${server_pid}"
      fi
      return 1
    fi
    sleep 0.2
    if remote_clean 'direction=$1
local_public=$2
tcp_port=$3
reverse=()
[[ "${direction}" == forward ]] && reverse=(-R)
iperf3 -4 -J -c "${local_public}" -p "${tcp_port}" -t 20 -P 8 "${reverse[@]}"' "${direction}" "${local_public}" "${tcp_port}" >"${output}"; then
      wait "${server_pid}" || true
      remove_local_process_ref "${server_ref}"
      if capacity="$(parse_iperf_mbps "${output}")"; then
        last_capacity="${capacity}"
        if capacity_passes "${capacity}"; then
          return 0
        fi
      fi
    else
      if terminate_local_process_ref "${server_ref}"; then
        remove_local_process_ref "${server_ref}"
      else
        return 1
      fi
    fi
  done
  return 1
}

ensure_payloads() {
  ((payloads_ready == 0)) || return 0
  source_file="${root}/source.bin"
  dd if=/dev/urandom of="${source_file}" bs=1048576 count="${size_mib}" 2>/dev/null
  source_sha256="$(sha256_file "${source_file}")"
  scp -- "${source_file}" "${remote_target}:${remote_source}.upload" >/dev/null
  remote_clean 'mv -- "$1" "$2"' "${remote_source}.upload" "${remote_source}"
  [[ "$(remote_clean 'sha256sum -- "$1" | awk "{print \$1}"' "${remote_source}")" == "${source_sha256}" ]] || { echo "remote source hash mismatch" >&2; exit 1; }
  payloads_ready=1
}

check_disk_capacity() {
  local run_id="$1" candidate="$2" run_dir="$3" local_free remote_free binary_bytes
  binary_bytes="$(( $(wc -c <"$(candidate_field "${candidate}" local_bin)") + $(wc -c <"$(candidate_field "${candidate}" linux_bin)") ))"
  local_free="$(( $(df -Pk "${root}" | awk 'NR==2 {print $4}') * 1024 ))"
  remote_free="$(( $(remote_clean 'df -Pk "$1" | awk "NR==2 {print \$4}"' "${remote_root}") * 1024 ))"
  "${local_udppeak}" capacity-check -free-bytes "${local_free}" -payload-bytes "${size_bytes}" -binary-bytes "${binary_bytes}" -evidence-reserve-bytes 536870912 -additional-payload-copies 1 -out "${run_dir}/local-capacity.json" >/dev/null
  remote_clean '"$1" capacity-check -free-bytes "$2" -payload-bytes "$3" -binary-bytes "$4" -evidence-reserve-bytes 536870912 -additional-payload-copies 1 -out "$5"' "${remote_udppeak}" "${remote_free}" "${size_bytes}" "${binary_bytes}" "${remote_root}/${run_id}.capacity.json" >/dev/null
  scp -- "${remote_target}:${remote_root}/${run_id}.capacity.json" "${run_dir}/remote-capacity.json" >/dev/null
}

check_preallocation_capacity() {
  local local_free remote_free binary_bytes
  mkdir "${root}/preallocation"
  binary_bytes="$(( $(wc -c <"$(candidate_field frozen-control local_bin)") + $(wc -c <"$(candidate_field frozen-control linux_bin)") + $(wc -c <"$(candidate_field combined-gso3 local_bin)") + $(wc -c <"$(candidate_field combined-gso3 linux_bin)") ))"
  local_free="$(( $(df -Pk "${root}" | awk 'NR==2 {print $4}') * 1024 ))"
  remote_free="$(( $(remote_clean 'df -Pk "$1" | awk "NR==2 {print \$4}"' "${remote_root}") * 1024 ))"
  "${local_udppeak}" capacity-check -free-bytes "${local_free}" -payload-bytes "${size_bytes}" -binary-bytes "${binary_bytes}" -evidence-reserve-bytes 536870912 -additional-payload-copies 2 -out "${root}/preallocation/local-capacity.json" >/dev/null
  remote_clean '"$1" capacity-check -free-bytes "$2" -payload-bytes "$3" -binary-bytes "$4" -evidence-reserve-bytes 536870912 -additional-payload-copies 2 -out "$5"' "${remote_udppeak}" "${remote_free}" "${size_bytes}" "${binary_bytes}" "${remote_root}/preallocation-capacity.json" >/dev/null
  scp -- "${remote_target}:${remote_root}/preallocation-capacity.json" "${root}/preallocation/remote-capacity.json" >/dev/null
  seal_artifact "${root}/preallocation/local-capacity.json"
  seal_artifact "${root}/preallocation/remote-capacity.json"
}

write_intermediate_health_verdict() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

before_path, sample_path, output_path = sys.argv[1:]
with open(before_path, encoding="utf-8") as source:
    before = json.load(source)
with open(sample_path, encoding="utf-8") as source:
    sample = json.load(source)
reasons = []
if sample.get("boot_id") != before.get("boot_id"):
    reasons.append("boot ID changed before transfer")
if sample.get("online_cpus") != before.get("online_cpus"):
    reasons.append("online CPU count changed before transfer")
for field, label in (("global_oom_kills", "global OOM kills"), ("cgroup_oom_kills", "cgroup OOM kills")):
    if sample.get(field) != before.get(field):
        reasons.append(label + " changed before transfer")
if int(sample.get("available_memory_bytes", -1)) < 268435456:
    reasons.append("available memory is below policy before transfer")
if int(sample.get("disk_free_bytes", -1)) < int(before.get("disk_free_bytes", 0)) - 1073741824:
    reasons.append("disk free bytes fell before transfer")
if int(sample.get("swap_used_bytes", -1)) > int(before.get("swap_used_bytes", 0)) + 67108864:
    reasons.append("swap grew before transfer")
if set(sample.get("kernel_errors", ())) - set(before.get("kernel_errors", ())):
    reasons.append("new kernel error before transfer")
for field in ("interface_drops", "udp_errors", "softnet_drops"):
    if int(sample.get(field, -1)) > int(before.get(field, 0)):
        reasons.append(field + " increased before transfer")
with open(output_path, "x", encoding="utf-8") as output:
    json.dump({"healthy": not reasons, "reasons": reasons, "schema_version": 1}, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
raise SystemExit(0 if not reasons else 1)
PY
}

wait_health_ready() {
  local run_dir="$1" remote_base="$2"
  for _ in $(seq 1 400); do
    [[ -s "${run_dir}/local-watch.jsonl" ]] && remote_clean 'test -s "$1"' "${remote_base}.watch.jsonl" && break
    sleep 0.05 || return 1
  done
  [[ -s "${run_dir}/local-watch.jsonl" ]] || { echo "local health watcher did not produce its first sample" >&2; return 1; }
  remote_clean 'test -s "$1"' "${remote_base}.watch.jsonl" || { echo "remote health watcher did not produce its first sample" >&2; return 1; }
  head -n 1 "${run_dir}/local-watch.jsonl" >"${run_dir}/local-ready.json" || return 1
  remote_clean 'head -n 1 -- "$1"' "${remote_base}.watch.jsonl" >"${run_dir}/remote-ready.json" || return 1
  write_intermediate_health_verdict "${run_dir}/local-before.json" "${run_dir}/local-ready.json" "${run_dir}/local-ready-verdict.json" || return 1
  write_intermediate_health_verdict "${run_dir}/remote-before.json" "${run_dir}/remote-ready.json" "${run_dir}/remote-ready-verdict.json" || return 1
}

start_health() {
  local run_id="$1" run_dir="$2" local_scope="$3" remote_scope="$4" remote_base="${remote_root}/${run_id}.health"
  local remote_cpus
  remote_cpus="$(remote_clean 'getconf _NPROCESSORS_ONLN')" || return 1
  [[ "${remote_cpus}" == 2 ]] || { echo "remote endpoint must have exactly two online CPUs" >&2; return 1; }
  "${local_udppeak}" health-snapshot -workdir "${root}" -interface "${local_interface}" -scope "${local_scope}" -out "${run_dir}/local-before.json" >/dev/null || return 1
  remote_clean '"$1" health-snapshot -workdir "$2" -interface "$3" -scope "$4" -out "$5"' "${remote_udppeak}" "${remote_root}" "${remote_interface}" "${remote_scope}" "${remote_base}.before.json" >/dev/null || return 1
  scp -- "${remote_target}:${remote_base}.before.json" "${run_dir}/remote-before.json" >/dev/null || return 1
  "${local_udppeak}" health-watch -workdir "${root}" -interface "${local_interface}" -scope "${local_scope}" -interval 2s -stop-file "${run_dir}/local-watch.stop" -out "${run_dir}/local-watch.jsonl" >"${run_dir}/local-watch.digest" 2>"${run_dir}/local-watch.err" &
  local_watch_pid="$!"
  unidentified_local_pids+=("${local_watch_pid}")
  local_watch_ref="${run_dir}/local-watch.ref.json"
  if identify_local_process "$(basename "${local_udppeak}")" "${local_watch_pid}" "${local_watch_ref}"; then
    publish_local_process_ref "${local_watch_pid}" "${local_watch_ref}"
  else
    : >"${run_dir}/local-watch.stop" || true
    if stop_unidentified_local_child "${local_watch_pid}"; then
      remove_unidentified_local_pid "${local_watch_pid}"
    fi
    return 1
  fi
  health_remote_base="${remote_base}"
  start_remote_clean_child remote_watch_pid 'set -euo pipefail
remote_udppeak=$1
remote_root=$2
remote_interface=$3
scope=$4
remote_base=$5
printf "%s\n" "$$" >"${remote_base}.wrapper.pid"
"${remote_udppeak}" process-identify -name bash -pid "$$" -timeout 5s -out "${remote_base}.wrapper.ref.json" >"${remote_base}.wrapper.ref.sha256"
"${remote_udppeak}" health-watch -workdir "${remote_root}" -interface "${remote_interface}" -scope "${scope}" -interval 2s -stop-file "${remote_base}.stop" -out "${remote_base}.watch.jsonl" >"${remote_base}.watch.digest" 2>"${remote_base}.watch.err" &
child_pid=$!
printf "%s\n" "${child_pid}" >"${remote_base}.child.pid"
"${remote_udppeak}" process-identify -name "$(basename "${remote_udppeak}")" -pid "${child_pid}" -timeout 5s -out "${remote_base}.child.ref.json" >"${remote_base}.child.ref.sha256"
wait "${child_pid}"' "${remote_udppeak}" "${remote_root}" "${remote_interface}" "${remote_scope}" "${remote_base}" || return 1
  remote_watch_ref="${run_dir}/remote-ssh-watch.ref.json"
  if identify_local_process ssh "${remote_watch_pid}" "${remote_watch_ref}"; then
    publish_local_process_ref "${remote_watch_pid}" "${remote_watch_ref}"
  else
    remote_clean ': >"$1"' "${remote_base}.stop" || true
    if stop_unidentified_local_child "${remote_watch_pid}"; then
      remove_unidentified_local_pid "${remote_watch_pid}"
    fi
    return 1
  fi
  for _ in $(seq 1 400); do
    remote_clean 'test -s "$1" -a -s "$2"' "${remote_base}.wrapper.ref.json" "${remote_base}.child.ref.json" && break
    sleep 0.05 || return 1
  done
  remote_clean 'test -s "$1" -a -s "$2"' "${remote_base}.wrapper.ref.json" "${remote_base}.child.ref.json" || return 1
  scp -- "${remote_target}:${remote_base}.wrapper.ref.json" "${run_dir}/remote-wrapper.ref.json" >/dev/null || return 1
  scp -- "${remote_target}:${remote_base}.child.ref.json" "${run_dir}/remote-child.ref.json" >/dev/null || return 1
  wait_health_ready "${run_dir}" "${remote_base}" || return 1
}

stop_health() {
  local run_dir="$1" local_scope="$2" remote_scope="$3" local_status=0 remote_status=0 remote_watch_cleanup_status=0 remote_watch_waited=0
  local local_wait_status=0 remote_wait_status=0
  : >"${run_dir}/local-watch.stop"
  remote_clean ': >"$1"' "${health_remote_base}.stop" || remote_status=1
  wait_local_pid_bounded "${local_watch_pid}" "${local_watch_ref}" || local_wait_status=$?
  ((local_wait_status == 0)) || local_status=1
  if ((local_wait_status != 2)); then
    remove_local_process_ref "${local_watch_ref}"
  fi
  wait_local_pid_bounded "${remote_watch_pid}" "${remote_watch_ref}" || remote_wait_status=$?
  if ((remote_wait_status == 0)); then
    remote_watch_waited=1
  else
    remote_status=1
  fi
  if ((remote_wait_status != 2)); then
    remove_local_process_ref "${remote_watch_ref}"
  fi
  if ((remote_watch_waited == 1)); then
    remote_clean 'python3 - "$1" <<"PY"
import json
import sys
with open(sys.argv[1], "x", encoding="utf-8") as output:
    json.dump({"completed_and_waited": True, "schema_version": 1}, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY' "${health_remote_base}.cleanup.json" || { remote_status=1; remote_watch_cleanup_status=1; }
  else
    cleanup_remote_watch "${health_remote_base}" || { remote_status=1; remote_watch_cleanup_status=1; }
  fi
  "${local_udppeak}" health-snapshot -workdir "${root}" -interface "${local_interface}" -scope "${local_scope}" -out "${run_dir}/local-after.json" >/dev/null || local_status=1
  remote_clean '"$1" health-snapshot -workdir "$2" -interface "$3" -scope "$4" -out "$5"' "${remote_udppeak}" "${remote_root}" "${remote_interface}" "${remote_scope}" "${health_remote_base}.after.json" >/dev/null || remote_status=1
  for suffix in after.json watch.jsonl watch.digest watch.err wrapper.pid child.pid wrapper.ref.json child.ref.json cleanup.json; do
    if remote_clean 'test -f "$1" -a ! -L "$1"' "${health_remote_base}.${suffix}"; then
      scp -- "${remote_target}:${health_remote_base}.${suffix}" "${run_dir}/remote-${suffix}" >/dev/null || remote_status=1
    else
      remote_status=1
    fi
  done
  if [[ -f "${run_dir}/local-watch.jsonl" && -f "${run_dir}/local-watch.digest" ]]; then
    [[ "$(sha256_file "${run_dir}/local-watch.jsonl")" == "$(tr -d '[:space:]' <"${run_dir}/local-watch.digest")" ]] || local_status=1
    validate_health_watch "${run_dir}/local-before.json" "${run_dir}/local-watch.jsonl" "${run_dir}/local-watch-verdict.json" || local_status=1
  else
    local_status=1
  fi
  if [[ -f "${run_dir}/remote-watch.jsonl" && -f "${run_dir}/remote-watch.digest" ]]; then
    [[ "$(sha256_file "${run_dir}/remote-watch.jsonl")" == "$(tr -d '[:space:]' <"${run_dir}/remote-watch.digest")" ]] || remote_status=1
    validate_health_watch "${run_dir}/remote-before.json" "${run_dir}/remote-watch.jsonl" "${run_dir}/remote-watch-verdict.json" || remote_status=1
  else
    remote_status=1
  fi
  local local_cpus remote_cpus local_disk remote_disk local_swap remote_swap
  if [[ -s "${run_dir}/local-before.json" && -s "${run_dir}/local-after.json" ]]; then
    local_cpus="$(getconf _NPROCESSORS_ONLN)"
    local_disk="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["disk_free_bytes"])' "${run_dir}/local-before.json")"
    local_swap="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["swap_used_bytes"] + 67108864)' "${run_dir}/local-before.json")"
    "${local_udppeak}" health-compare -before "${run_dir}/local-before.json" -after "${run_dir}/local-after.json" -expected-online-cpus "${local_cpus}" -min-available-memory-bytes 268435456 -min-disk-available-bytes "$((local_disk - size_bytes))" -max-swap-used-bytes "${local_swap}" -max-swap-increase-bytes 67108864 -scope "${local_scope}" -out "${run_dir}/local-health-verdict.json" >/dev/null || local_status=1
  else
    local_status=1
  fi
  if [[ -s "${run_dir}/remote-before.json" && -s "${run_dir}/remote-after.json" ]]; then
    remote_cpus="$(remote_clean 'getconf _NPROCESSORS_ONLN')" || remote_status=1
    remote_disk="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["disk_free_bytes"])' "${run_dir}/remote-before.json")"
    remote_swap="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["swap_used_bytes"] + 67108864)' "${run_dir}/remote-before.json")"
    if [[ -n "${remote_cpus}" ]]; then
      "${local_udppeak}" health-compare -before "${run_dir}/remote-before.json" -after "${run_dir}/remote-after.json" -expected-online-cpus "${remote_cpus}" -min-available-memory-bytes 268435456 -min-disk-available-bytes "$((remote_disk - size_bytes))" -max-swap-used-bytes "${remote_swap}" -max-swap-increase-bytes 67108864 -scope "${remote_scope}" -out "${run_dir}/remote-health-verdict.json" >/dev/null || remote_status=1
    fi
  else
    remote_status=1
  fi
  printf '{"local_status":%d,"remote_status":%d}\n' "${local_status}" "${remote_status}" >"${run_dir}/health-status.json"
  health_status="$((local_status == 0 && remote_status == 0 ? 0 : 1))"
  if ((remote_watch_cleanup_status == 0)); then
    health_remote_base=""
  fi
}

validate_health_watch() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import math
import sys

before_path, watch_path, output_path = sys.argv[1:]
reasons = []

def integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0

def validate_snapshot(value, label):
    required_ints = (
        "online_cpus", "global_oom_kills", "cgroup_oom_kills", "available_memory_bytes",
        "swap_used_bytes", "disk_free_bytes", "interface_drops", "udp_errors", "softnet_drops",
    )
    if not isinstance(value, dict):
        reasons.append(label + " is not an object")
        return False
    if not isinstance(value.get("boot_id"), str) or not value["boot_id"]:
        reasons.append(label + " has invalid boot_id")
    uptime = value.get("uptime_seconds")
    if isinstance(uptime, bool) or not isinstance(uptime, (int, float)) or not math.isfinite(uptime) or uptime < 0:
        reasons.append(label + " has invalid uptime_seconds")
    for field in required_ints:
        if not integer(value.get(field)) or (field == "online_cpus" and value[field] == 0):
            reasons.append(label + " has invalid " + field)
    if not isinstance(value.get("kernel_errors"), list) or any(not isinstance(item, str) for item in value.get("kernel_errors", ())):
        reasons.append(label + " has invalid kernel_errors")
    for field in ("interface_counters", "udp_counters", "softnet_counters"):
        counters = value.get(field)
        if not isinstance(counters, list):
            reasons.append(label + " has invalid " + field)
            continue
        names = set()
        for counter in counters:
            if not isinstance(counter, dict) or not isinstance(counter.get("name"), str) or not counter["name"] or not integer(counter.get("value")) or counter["name"] in names:
                reasons.append(label + " has malformed " + field)
                break
            names.add(counter["name"])
    scope = value.get("cleanup_scope")
    if not isinstance(scope, dict) or scope.get("declared") is not True or not isinstance(scope.get("processes"), list) or not isinstance(scope.get("cgroups"), list):
        reasons.append(label + " has invalid cleanup_scope")
    for field in ("cgroups", "processes", "sockets", "counter_families"):
        if not isinstance(value.get(field), list):
            reasons.append(label + " has invalid " + field)
    return True

try:
    with open(before_path, encoding="utf-8") as source:
        before = json.load(source)
except (OSError, ValueError, json.JSONDecodeError) as error:
    before = {}
    reasons.append("before snapshot is unreadable: " + str(error))
validate_snapshot(before, "before snapshot")
samples = []
try:
    with open(watch_path, encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                reasons.append(f"sample {line_number} is empty")
                continue
            try:
                sample = json.loads(line)
            except json.JSONDecodeError as error:
                reasons.append(f"sample {line_number} is malformed: {error}")
                continue
            samples.append((line_number, sample))
except OSError as error:
    reasons.append("watch is unreadable: " + str(error))
if not samples:
    reasons.append("watch has no samples")

previous_uptime = before.get("uptime_seconds", 0)
before_kernel = set(before.get("kernel_errors", ()))
before_counters = {
    field: {counter["name"]: counter["value"] for counter in before.get(field, ()) if isinstance(counter, dict) and "name" in counter and "value" in counter}
    for field in ("interface_counters", "udp_counters", "softnet_counters")
}
for line_number, sample in samples:
    label = f"sample {line_number}"
    valid = validate_snapshot(sample, label)
    if not valid:
        continue
    if sample["boot_id"] != before.get("boot_id"):
        reasons.append(label + " boot ID changed")
    if sample["online_cpus"] != before.get("online_cpus"):
        reasons.append(label + " online CPU count changed")
    for field in ("global_oom_kills", "cgroup_oom_kills"):
        if sample[field] != before.get(field):
            reasons.append(label + " changed " + field)
    if sample["available_memory_bytes"] < 268435456:
        reasons.append(label + " available memory is below policy")
    if sample["disk_free_bytes"] < before.get("disk_free_bytes", 0) - 1073741824:
        reasons.append(label + " disk free bytes are below policy")
    if sample["swap_used_bytes"] > before.get("swap_used_bytes", 0) + 67108864:
        reasons.append(label + " swap grew beyond policy")
    if set(sample["kernel_errors"]) - before_kernel:
        reasons.append(label + " has a new kernel error")
    for field in ("interface_drops", "udp_errors", "softnet_drops"):
        if sample[field] > before.get(field, 0):
            reasons.append(label + " increased " + field)
    if sample.get("cleanup_scope") != before.get("cleanup_scope"):
        reasons.append(label + " cleanup scope changed")
    if sample.get("counter_families") != before.get("counter_families"):
        reasons.append(label + " counter families changed")
    if sample["uptime_seconds"] < previous_uptime:
        reasons.append(label + " uptime regressed")
    previous_uptime = sample["uptime_seconds"]
    for field, baseline in before_counters.items():
        observed = {counter["name"]: counter["value"] for counter in sample[field]}
        if observed.keys() != baseline.keys():
            reasons.append(label + " changed " + field + " names")
        elif any(observed[name] > baseline[name] for name in baseline):
            reasons.append(label + " increased " + field)

with open(output_path, "x", encoding="utf-8") as output:
    json.dump({"healthy": not reasons, "reasons": reasons, "sample_count": len(samples), "schema_version": 1}, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
raise SystemExit(0 if not reasons else 1)
PY
}

footer_value() {
  local run_dir="$1" key="$2" line matches=()
  while IFS= read -r line; do
    [[ -n "${line}" ]] && matches+=("${line}")
  done < <(grep -h "^${key}=" "${run_dir}/promotion.out" "${run_dir}/promotion.err" 2>/dev/null || true)
  [[ "${#matches[@]}" == 1 ]] || return 1
  printf '%s\n' "${matches[0]#*=}"
}

find_one_artifact() {
  local pattern="$1" matches=()
  while IFS= read -r path; do [[ -n "${path}" ]] && matches+=("${path}"); done < <(find "$(dirname "${pattern}")" -maxdepth 1 -type f -name "$(basename "${pattern}")" -print | sort)
  [[ "${#matches[@]}" == 1 ]] || return 1
  printf '%s\n' "${matches[0]}"
}

validate_traces() {
  local direction="$1" candidate="$2" run_dir="$3" sender_trace receiver_trace sender_peer receiver_peer trace_candidate
  local engine_telemetry_args=()
  sender_trace="$(find_one_artifact "${run_dir}/raw/*-sender.trace.csv")"
  receiver_trace="$(find_one_artifact "${run_dir}/raw/*-receiver.trace.csv")"
  if [[ "${direction}" == "forward" ]]; then sender_peer="${remote_public}"; receiver_peer="${local_public}"; else sender_peer="${local_public}"; receiver_peer="${remote_public}"; fi
  trace_candidate="$(candidate_field "${candidate}" trace_candidate)"
  if [[ "${trace_candidate}" != unavailable ]]; then
    engine_telemetry_args=(-require-engine-telemetry)
  fi
  "${local_tracecheck}" -role receive -expected-payload-bytes "${size_bytes}" -require-direct-transport udp -require-file-payload-engine bulk-packets-v1 "${engine_telemetry_args[@]}" -expected-selected-public-ipv4 "${receiver_peer}" -forbid-relay-payload "${receiver_trace}" >"${run_dir}/receiver-tracecheck.txt"
  "${local_tracecheck}" -role send -expected-payload-bytes "${size_bytes}" -require-direct-transport udp -require-file-payload-engine bulk-packets-v1 "${engine_telemetry_args[@]}" -expected-selected-public-ipv4 "${sender_peer}" -peer-expected-selected-public-ipv4 "${receiver_peer}" -forbid-relay-payload -peer-trace "${receiver_trace}" "${sender_trace}" >"${run_dir}/paired-transfertracecheck.txt"
  if [[ "${trace_candidate}" == unavailable ]]; then
    return 0
  fi
  python3 - "${trace_candidate}" "${sender_trace}" "${receiver_trace}" "${run_dir}/efficiency.json" <<'PY'
import csv
import json
import sys

expected, sender_path, receiver_path, output_path = sys.argv[1:]
final_rows = {}
for path in (sender_path, receiver_path):
    observed = []
    with open(path, newline="") as source:
        for row in csv.DictReader(source):
            value = (row.get("bulk_candidate_id") or "").strip()
            if value:
                observed.append(value)
                final_rows[path] = row
    if not observed or any(value != expected for value in observed):
        raise SystemExit(f"{path}: bulk_candidate_id does not match {expected}")
fields = (
    "bulk_native_send_attempts",
    "bulk_native_send_syscalls",
    "bulk_gso_messages",
    "bulk_logical_datagrams",
    "bulk_accepted_payload_bytes",
    "bulk_gso_segments_per_message",
)
sender = final_rows[sender_path]
efficiency = {"efficiency_telemetry_status": "available"}
for field in fields:
    raw = (sender.get(field) or "").strip()
    if not raw:
        raise SystemExit(f"{sender_path}: missing {field}")
    value = int(raw)
    if value < 0:
        raise SystemExit(f"{sender_path}: negative {field}")
    efficiency[field] = value
with open(output_path, "x", encoding="utf-8") as output:
    json.dump(efficiency, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
}

validate_child_cleanup_evidence() {
  local run_dir="$1" expected_digest="$2"
  [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ -f "${run_dir}/child-cleanup.json" && ! -L "${run_dir}/child-cleanup.json" ]] || return 1
  [[ "$(sha256_file "${run_dir}/child-cleanup.json")" == "${expected_digest}" ]] || return 1
  python3 - "${run_dir}/child-cleanup.json" "${run_dir}/process-refs" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

cleanup_path, references_root = sys.argv[1:]
expected_roles = {"local-runstats", "local-derphole", "wrapper", "runstats", "derphole"}
with open(cleanup_path, encoding="utf-8") as source:
    value = json.load(source)
if set(value) != {"identity_cleanup_complete", "references", "schema_version", "success"}:
    raise SystemExit("child cleanup evidence has unexpected fields")
if value["schema_version"] != 1 or value["success"] is not True or value["identity_cleanup_complete"] is not True:
    raise SystemExit("child cleanup evidence is not successful")
references = value["references"]
if not isinstance(references, list) or len(references) != len(expected_roles):
    raise SystemExit("child cleanup evidence does not contain exactly five references")
observed_roles = []
for reference in references:
    if not isinstance(reference, dict) or set(reference) != {"role", "sha256"}:
        raise SystemExit("child cleanup reference is malformed")
    role, expected_digest = reference["role"], reference["sha256"]
    if role not in expected_roles or not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise SystemExit("child cleanup reference identity is invalid")
    observed_roles.append(role)
    reference_path = os.path.join(references_root, role + ".ref.json")
    digest_path = reference_path + ".sha256"
    for path in (reference_path, digest_path):
        if os.path.islink(path) or not os.path.isfile(path) or not stat.S_ISREG(os.stat(path).st_mode):
            raise SystemExit(role + " reference artifact is missing or unsafe")
    with open(reference_path, "rb") as source:
        actual_digest = hashlib.sha256(source.read()).hexdigest()
    with open(digest_path, encoding="ascii") as source:
        helper_digest = source.read().strip()
    if actual_digest != expected_digest or helper_digest != expected_digest:
        raise SystemExit(role + " reference digest does not bind exact bytes")
    with open(reference_path, encoding="utf-8") as source:
        process = json.load(source)
    if set(process) != {"executable_identity", "name", "pid", "start_identity"}:
        raise SystemExit(role + " process reference is malformed")
    if not isinstance(process["pid"], int) or isinstance(process["pid"], bool) or process["pid"] <= 0:
        raise SystemExit(role + " process PID is invalid")
    if any(not isinstance(process[field], str) or not process[field] for field in ("executable_identity", "name", "start_identity")):
        raise SystemExit(role + " process identity is invalid")
if len(set(observed_roles)) != len(expected_roles) or set(observed_roles) != expected_roles:
    raise SystemExit("child cleanup roles are duplicated or incomplete")
base_references = {
    name for name in os.listdir(references_root)
    if name.endswith(".ref.json") and not name.startswith("recheck-")
}
if base_references != {role + ".ref.json" for role in expected_roles}:
    raise SystemExit("process reference directory has an unexpected base role set")
PY
  local validation_status=$?
  ((validation_status == 0)) || return 1
  local role
  for role in local-runstats local-derphole wrapper runstats derphole; do
    chmod a-w "${run_dir}/process-refs/${role}.ref.json" "${run_dir}/process-refs/${role}.ref.json.sha256"
  done
  seal_artifact "${run_dir}/child-cleanup.json"
  [[ "$(tr -d '[:space:]' <"${run_dir}/child-cleanup.json.sha256")" == "${expected_digest}" ]]
}

validate_post_cleanup_snapshot() {
  local scope="$1" snapshot="$2"
  [[ -f "${scope}" && ! -L "${scope}" && -f "${snapshot}" && ! -L "${snapshot}" ]] || return 1
  python3 - "${scope}" "${snapshot}" <<'PY'
import json
import sys

scope_path, snapshot_path = sys.argv[1:]
with open(scope_path, encoding="utf-8") as source:
    scope = json.load(source)
with open(snapshot_path, encoding="utf-8") as source:
    snapshot = json.load(source)
if not isinstance(snapshot, dict) or snapshot.get("cleanup_scope") != scope:
    raise SystemExit("post-cleanup snapshot is not bound to the exact declared scope")
if snapshot.get("processes") != []:
    raise SystemExit("an exact benchmark process remains after driver cleanup")
if snapshot.get("sockets") != []:
    raise SystemExit("an exact benchmark socket remains after driver cleanup")
PY
}

verify_child_cleanup_absence() {
  local run_id="$1" run_dir="$2"
  local references_root="${run_dir}/process-refs"
  local local_scope="${run_dir}/local-child-scope.json"
  local remote_scope="${run_dir}/remote-child-scope.json"
  local local_snapshot="${run_dir}/local-child-post.json"
  local remote_snapshot="${run_dir}/remote-child-post.json"
  local remote_scope_path="${remote_root}/${run_id}.child-scope.json"
  local remote_snapshot_path="${remote_root}/${run_id}.child-post.json"
  write_cleanup_scope "${local_scope}" "${references_root}/local-runstats.ref.json" "${references_root}/local-derphole.ref.json" || return 1
  write_cleanup_scope "${remote_scope}" "${references_root}/wrapper.ref.json" "${references_root}/runstats.ref.json" "${references_root}/derphole.ref.json" || return 1
  scp -- "${remote_scope}" "${remote_target}:${remote_scope_path}" >/dev/null || return 1
  "${local_udppeak}" health-snapshot -workdir "${root}" -interface "${local_interface}" -scope "${local_scope}" -out "${local_snapshot}" >/dev/null || return 1
  remote_clean '"$1" health-snapshot -workdir "$2" -interface "$3" -scope "$4" -out "$5"' "${remote_udppeak}" "${remote_root}" "${remote_interface}" "${remote_scope_path}" "${remote_snapshot_path}" >/dev/null || return 1
  scp -- "${remote_target}:${remote_snapshot_path}" "${remote_snapshot}" >/dev/null || return 1
  validate_post_cleanup_snapshot "${local_scope}" "${local_snapshot}" || return 1
  validate_post_cleanup_snapshot "${remote_scope}" "${remote_snapshot}" || return 1
  seal_artifact "${local_scope}" || return 1
  seal_artifact "${remote_scope}" || return 1
  seal_artifact "${local_snapshot}" || return 1
  seal_artifact "${remote_snapshot}" || return 1
}

write_cleanup_evidence() {
  local run_id="$1" cleanup_success="$2" health_success="$3" child_cleanup_success="$4" child_cleanup_sha256="$5" independent_cleanup_success="$6" run_dir="$7"
  mkdir -p "${root}/cleanup"
  [[ -d "${root}/cleanup" && ! -L "${root}/cleanup" ]] || return 1
  python3 - "${root}/cleanup/${run_id}.json" "${cleanup_success}" "${health_success}" "${child_cleanup_success}" "${child_cleanup_sha256}" "${independent_cleanup_success}" "${run_dir}" <<'PY'
import hashlib
import json
import os
import sys

path, cleanup, health, child_cleanup, child_cleanup_sha256, independent_cleanup, run_dir = sys.argv[1:]

def digest(name):
    artifact = os.path.join(run_dir, name)
    if os.path.islink(artifact) or not os.path.isfile(artifact):
        return None
    with open(artifact, "rb") as source:
        return hashlib.sha256(source.read()).hexdigest()

references = []
child_path = os.path.join(run_dir, "child-cleanup.json")
if os.path.isfile(child_path) and not os.path.islink(child_path):
    try:
        with open(child_path, encoding="utf-8") as source:
            references = json.load(source).get("references", [])
    except (OSError, ValueError, json.JSONDecodeError):
        references = []
with open(path, "x", encoding="utf-8") as output:
    json.dump({
        "child_cleanup_sha256": child_cleanup_sha256 if len(child_cleanup_sha256) == 64 else None,
        "child_cleanup_success": child_cleanup == "true",
        "driver_cleanup_success": cleanup == "true",
        "health_cleanup_success": health == "true",
        "independent_cleanup_success": independent_cleanup == "true",
        "local_child_scope_sha256": digest("local-child-scope.json"),
        "local_child_snapshot_sha256": digest("local-child-post.json"),
        "references": references,
        "remote_child_scope_sha256": digest("remote-child-scope.json"),
        "remote_child_snapshot_sha256": digest("remote-child-post.json"),
        "schema_version": 1,
    }, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
  seal_artifact "${root}/cleanup/${run_id}.json"
}

validate_remote_resource_footer() {
  python3 - "$@" <<'PY'
import math
import sys

direction, sender_available, sender_user, sender_system, sender_rss, receiver_available, receiver_user, receiver_system, receiver_rss = sys.argv[1:]
if direction == "forward":
    available, user, system, rss = receiver_available, receiver_user, receiver_system, receiver_rss
elif direction == "reverse":
    available, user, system, rss = sender_available, sender_user, sender_system, sender_rss
else:
    raise SystemExit(1)
try:
    user_value = float(user)
    system_value = float(system)
    rss_value = int(rss)
except (TypeError, ValueError):
    raise SystemExit(1)
if available != "true" or not math.isfinite(user_value) or not math.isfinite(system_value) or user_value < 0 or system_value < 0 or rss_value < 0:
    raise SystemExit(1)
print(f"{user_value + system_value:.9f}\t{rss_value}")
PY
}

write_result() {
  local run_id="$1" sequence_index="$2" direction="$3" candidate="$4" capacity="$5" started="$6" status="$7" run_dir="$8"
  local source_sha="" sink_sha="" sink_size="" goodput="" wall="" cleanup_success="false" success="false"
  local sender_user="" sender_system="" sender_rss="" sender_available="false" receiver_user="" receiver_system="" receiver_rss="" receiver_available="false"
  source_sha="$(footer_value "${run_dir}" benchmark-source-sha256 2>/dev/null || true)"
  sink_sha="$(footer_value "${run_dir}" benchmark-sink-sha256 2>/dev/null || true)"
  sink_size="$(footer_value "${run_dir}" benchmark-sink-size-bytes 2>/dev/null || true)"
  goodput="$(footer_value "${run_dir}" benchmark-goodput-mbps 2>/dev/null || true)"
  wall="$(footer_value "${run_dir}" benchmark-wall-goodput-mbps 2>/dev/null || true)"
  cleanup_success="$(footer_value "${run_dir}" benchmark-cleanup-success 2>/dev/null || true)"
  success="$(footer_value "${run_dir}" benchmark-success 2>/dev/null || true)"
  sender_user="$(footer_value "${run_dir}" benchmark-sender-user-cpu-seconds 2>/dev/null || true)"
  sender_system="$(footer_value "${run_dir}" benchmark-sender-system-cpu-seconds 2>/dev/null || true)"
  sender_rss="$(footer_value "${run_dir}" benchmark-sender-max-rss-bytes 2>/dev/null || true)"
  sender_available="$(footer_value "${run_dir}" benchmark-sender-resource-stats-available 2>/dev/null || true)"
  receiver_user="$(footer_value "${run_dir}" benchmark-receiver-user-cpu-seconds 2>/dev/null || true)"
  receiver_system="$(footer_value "${run_dir}" benchmark-receiver-system-cpu-seconds 2>/dev/null || true)"
  receiver_rss="$(footer_value "${run_dir}" benchmark-receiver-max-rss-bytes 2>/dev/null || true)"
  receiver_available="$(footer_value "${run_dir}" benchmark-receiver-resource-stats-available 2>/dev/null || true)"
  python3 - "${root}/results/${run_id}.json" "${run_id}" "${sequence_index}" "${direction}" "${candidate}" "${capacity}" "${started}" "${status}" "${source_sha}" "${sink_sha}" "${sink_size}" "${goodput}" "${wall}" "${cleanup_success}" "${success}" "${run_dir}/efficiency.json" "${registry_sha256}" "${sender_user}" "${sender_system}" "${sender_rss}" "${sender_available}" "${receiver_user}" "${receiver_system}" "${receiver_rss}" "${receiver_available}" <<'PY'
import json
import os
import sys

(path, run_id, sequence, direction, candidate, capacity, started, status, source_sha,
 sink_sha, sink_size, goodput, wall, cleanup, success, efficiency_path, registry_sha256,
 sender_user, sender_system, sender_rss, sender_available, receiver_user, receiver_system,
 receiver_rss, receiver_available) = sys.argv[1:]

def optional_float(raw):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None

def optional_int(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None
efficiency_fields = (
    "bulk_native_send_attempts",
    "bulk_native_send_syscalls",
    "bulk_gso_messages",
    "bulk_logical_datagrams",
    "bulk_accepted_payload_bytes",
    "bulk_gso_segments_per_message",
)
value = {
    "candidate_id": candidate,
    "capacity_mbps": float(capacity or 0),
    "cleanup_success": cleanup == "true",
    "direction": direction,
    "goodput_mbps": float(goodput or 0),
    "run_id": run_id,
    "registry_sha256": registry_sha256,
    "schema_version": 1,
    "sequence": int(sequence),
    "sink_sha256": sink_sha,
    "sink_size_bytes": int(sink_size or 0),
    "source_sha256": source_sha,
    "started": started == "true",
    "status": int(status),
    "success": success == "true" and int(status) == 0,
    "wall_goodput_mbps": float(wall or 0),
}
value["efficiency_telemetry_status"] = "unavailable" if candidate == "frozen-control" else "missing"
for field in efficiency_fields:
    value[field] = None
if os.path.exists(efficiency_path):
    with open(efficiency_path, encoding="utf-8") as source:
        efficiency = json.load(source)
    value["efficiency_telemetry_status"] = efficiency["efficiency_telemetry_status"]
    for field in efficiency_fields:
        value[field] = efficiency[field]
sender_user_value = optional_float(sender_user)
sender_system_value = optional_float(sender_system)
receiver_user_value = optional_float(receiver_user)
receiver_system_value = optional_float(receiver_system)
value.update({
    "sender_user_cpu_seconds": sender_user_value,
    "sender_system_cpu_seconds": sender_system_value,
    "sender_max_rss_bytes": optional_int(sender_rss),
    "sender_resource_stats_available": sender_available == "true",
    "receiver_user_cpu_seconds": receiver_user_value,
    "receiver_system_cpu_seconds": receiver_system_value,
    "receiver_max_rss_bytes": optional_int(receiver_rss),
    "receiver_resource_stats_available": receiver_available == "true",
})
if direction == "forward":
    remote_available = value["receiver_resource_stats_available"]
    remote_user, remote_system, remote_rss = receiver_user_value, receiver_system_value, value["receiver_max_rss_bytes"]
else:
    remote_available = value["sender_resource_stats_available"]
    remote_user, remote_system, remote_rss = sender_user_value, sender_system_value, value["sender_max_rss_bytes"]
if remote_available and remote_user is not None and remote_system is not None and remote_rss is not None:
    value["resource_telemetry_status"] = "available"
    value["hetz_cpu_seconds"] = remote_user + remote_system
    gibibytes = 1073741824 / 1073741824
    value["hetz_cpu_seconds_per_gib"] = value["hetz_cpu_seconds"] / gibibytes
    value["hetz_max_rss_bytes"] = remote_rss
else:
    value["resource_telemetry_status"] = "unavailable"
    value["hetz_cpu_seconds"] = None
    value["hetz_cpu_seconds_per_gib"] = None
    value["hetz_max_rss_bytes"] = None
with open(path, "x", encoding="utf-8") as output:
    json.dump(value, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
  seal_artifact "${root}/results/${run_id}.json"
  result_paths+=("${root}/results/${run_id}.json")
}

write_postponed_result() {
  local run_id="$1" sequence_index="$2" direction="$3" candidate="$4" capacity="$5" run_dir="$6"
  : >"${run_dir}/promotion.out"
  : >"${run_dir}/promotion.err"
  write_result "${run_id}" "${sequence_index}" "${direction}" "${candidate}" "${capacity}" false 75 "${run_dir}"
}

write_cleanup_scope() {
  local output_path="$1"
  shift
  python3 - "${output_path}" "$@" <<'PY'
import json
import sys

output_path, *reference_paths = sys.argv[1:]
processes = []
for reference_path in reference_paths:
    with open(reference_path, encoding="utf-8") as source:
        reference = json.load(source)
    processes.append({
        "name": reference["name"],
        "pid": reference["pid"],
        "start_identity": reference["start_identity"],
        "executable_identity": reference["executable_identity"],
    })
with open(output_path, "x", encoding="utf-8") as output:
    json.dump({"declared": True, "processes": processes, "cgroups": []}, output, separators=(",", ":"))
    output.write("\n")
PY
}

write_process_scope() {
  write_cleanup_scope "$2" "$1"
}

wait_promotion_ready() {
  local ready_file="$1" pid="$2"
  for _ in $(seq 1 600); do
    [[ -f "${ready_file}" && ! -L "${ready_file}" ]] && return 0
    local_pid_running "${pid}" || return 1
    sleep 0.05
  done
  return 1
}

run_transfer() {
  local run_id="$1" direction="$2" candidate="$3" run_dir="$4"
  local local_bin linux_bin local_sha linux_sha commit status=0 ready_file start_file local_scope remote_scope cleanup_success child_cleanup_success child_cleanup_sha256
  local sender_available sender_user sender_system sender_rss receiver_available receiver_user receiver_system receiver_rss resource_status=0
  child_post_cleanup_status=1
  health_status=1
  transfer_started=false
  local_bin="$(candidate_field "${candidate}" local_bin)"
  linux_bin="$(candidate_field "${candidate}" linux_bin)"
  local_sha="$(candidate_field "${candidate}" local_sha)"
  linux_sha="$(candidate_field "${candidate}" linux_sha)"
  commit="$(candidate_field "${candidate}" commit)"
  mkdir -p "${run_dir}/raw"
  check_disk_capacity "${run_id}" "${candidate}" "${run_dir}"
  ready_file="${run_dir}/promotion.ready"
  start_file="${run_dir}/promotion.start"
  local_scope="${run_dir}/local-scope.json"
  remote_scope="${remote_root}/${run_id}.remote-scope.json"
  clean_env=(env -i "HOME=${HOME}" "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}")
  [[ -n "${SSH_AUTH_SOCK:-}" ]] && clean_env+=("SSH_AUTH_SOCK=${SSH_AUTH_SOCK}")
  clean_env+=(
    "DERPHOLE_BENCH_TOOL=derphole"
    "DERPHOLE_BENCH_DIRECTION=${direction}"
    "DERPHOLE_BENCH_WORKLOAD=file"
    "DERPHOLE_BENCH_LOCAL_BIN=${local_bin}"
    "DERPHOLE_BENCH_LINUX_BIN=${linux_bin}"
    "DERPHOLE_BENCH_LOCAL_BIN_SHA256=${local_sha}"
    "DERPHOLE_BENCH_LINUX_BIN_SHA256=${linux_sha}"
    "DERPHOLE_BENCH_REVISION_LABEL=${commit}"
    "DERPHOLE_BENCH_LOCAL_TMP_ROOT=${run_dir}/tmp"
    "DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT=${remote_root}/runs/${run_id}"
    "DERPHOLE_REMOTE_BIN_DIR=${remote_root}/bin/${run_id}"
    "DERPHOLE_BENCH_LOG_DIR=${run_dir}/raw"
    "DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1"
    "DERPHOLE_BENCH_PROCESS_IDENTIFY_LOCAL=${local_udppeak}"
    "DERPHOLE_BENCH_PROCESS_IDENTIFY_REMOTE=${remote_udppeak}"
    "DERPHOLE_BENCH_PROCESS_EVIDENCE_DIR=${run_dir}/process-refs"
    "DERPHOLE_BENCH_CHILD_CLEANUP_OUT=${run_dir}/child-cleanup.json"
    "DERPHOLE_BENCH_READY_FILE=${ready_file}"
    "DERPHOLE_BENCH_START_FILE=${start_file}"
    "DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1"
  )
  if [[ "${direction}" == "forward" ]]; then clean_env+=("DERPHOLE_BENCH_LOCAL_PAYLOAD=${source_file}"); else clean_env+=("DERPHOLE_BENCH_REMOTE_PAYLOAD=${remote_source}"); fi
  "${clean_env[@]}" bash "${promotion_driver}" "${remote_target}" "${size_mib}" >"${run_dir}/promotion.out" 2>"${run_dir}/promotion.err" &
  promotion_pid="$!"
  unidentified_local_pids+=("${promotion_pid}")
  promotion_ref="${run_dir}/promotion.ref.json"
  if identify_local_process bash "${promotion_pid}" "${promotion_ref}"; then
    publish_local_process_ref "${promotion_pid}" "${promotion_ref}"
  else
    if stop_unidentified_local_child "${promotion_pid}"; then
      remove_unidentified_local_pid "${promotion_pid}"
    fi
    promotion_pid=""
    promotion_ref=""
    write_cleanup_evidence "${run_id}" false false false "" false "${run_dir}"
    transfer_status=1
    return 0
  fi
  if ! wait_promotion_ready "${ready_file}" "${promotion_pid}"; then
    echo "promotion driver did not reach its start gate" >&2
    if stop_published_local_child_bounded "${promotion_pid}" "${promotion_ref}"; then
      remove_local_process_ref "${promotion_ref}"
      promotion_pid=""
      promotion_ref=""
    fi
    write_cleanup_evidence "${run_id}" false false false "" false "${run_dir}"
    transfer_status=1
    return 0
  fi
  write_process_scope "${promotion_ref}" "${local_scope}"
  write_cleanup_scope "${run_dir}/remote-scope.json"
  scp -- "${run_dir}/remote-scope.json" "${remote_target}:${remote_scope}" >/dev/null
  if ! start_health "${run_id}" "${run_dir}" "${local_scope}" "${remote_scope}"; then
    echo "health watchers did not become ready before transfer" >&2
    if stop_published_local_child_bounded "${promotion_pid}" "${promotion_ref}"; then
      remove_local_process_ref "${promotion_ref}"
      promotion_pid=""
      promotion_ref=""
    fi
    if [[ -n "${health_remote_base}" ]]; then
      stop_health "${run_dir}" "${local_scope}" "${remote_scope}" || true
    fi
    write_cleanup_evidence "${run_id}" false false false "" false "${run_dir}"
    transfer_status=1
    return 0
  fi
  (set -o noclobber; printf 'start\n' >"${start_file}")
  transfer_started=true
  set +e
  wait "${promotion_pid}"
  status=$?
  set -e
  remove_local_process_ref "${promotion_ref}"
  promotion_pid=""
  promotion_ref=""
  stop_health "${run_dir}" "${local_scope}" "${remote_scope}"
  cleanup_success="$(footer_value "${run_dir}" benchmark-cleanup-success 2>/dev/null || true)"
  child_cleanup_success="$(footer_value "${run_dir}" benchmark-child-cleanup-success 2>/dev/null || true)"
  child_cleanup_sha256="$(footer_value "${run_dir}" benchmark-child-cleanup-sha256 2>/dev/null || true)"
  sender_available="$(footer_value "${run_dir}" benchmark-sender-resource-stats-available 2>/dev/null || true)"
  sender_user="$(footer_value "${run_dir}" benchmark-sender-user-cpu-seconds 2>/dev/null || true)"
  sender_system="$(footer_value "${run_dir}" benchmark-sender-system-cpu-seconds 2>/dev/null || true)"
  sender_rss="$(footer_value "${run_dir}" benchmark-sender-max-rss-bytes 2>/dev/null || true)"
  receiver_available="$(footer_value "${run_dir}" benchmark-receiver-resource-stats-available 2>/dev/null || true)"
  receiver_user="$(footer_value "${run_dir}" benchmark-receiver-user-cpu-seconds 2>/dev/null || true)"
  receiver_system="$(footer_value "${run_dir}" benchmark-receiver-system-cpu-seconds 2>/dev/null || true)"
  receiver_rss="$(footer_value "${run_dir}" benchmark-receiver-max-rss-bytes 2>/dev/null || true)"
  validate_remote_resource_footer "${direction}" "${sender_available}" "${sender_user}" "${sender_system}" "${sender_rss}" "${receiver_available}" "${receiver_user}" "${receiver_system}" "${receiver_rss}" >"${run_dir}/remote-resource-efficiency.tsv" || resource_status=1
  if [[ "${child_cleanup_success}" != true ]] || ! validate_child_cleanup_evidence "${run_dir}" "${child_cleanup_sha256}"; then
    child_cleanup_success=false
  elif verify_child_cleanup_absence "${run_id}" "${run_dir}"; then
    child_post_cleanup_status=0
  fi
  write_cleanup_evidence "${run_id}" "${cleanup_success}" "$([[ "${health_status}" == 0 ]] && echo true || echo false)" "${child_cleanup_success}" "${child_cleanup_sha256}" "$([[ "${child_post_cleanup_status}" == 0 ]] && echo true || echo false)" "${run_dir}"
  if ((status == 0)); then
    [[ "$(footer_value "${run_dir}" benchmark-source-sha256)" == "${source_sha256}" ]] || status=1
    [[ "$(footer_value "${run_dir}" benchmark-sink-sha256)" == "${source_sha256}" ]] || status=1
    [[ "$(footer_value "${run_dir}" benchmark-sink-size-bytes)" == "${size_bytes}" ]] || status=1
    [[ "$(footer_value "${run_dir}" benchmark-remote-linux-bin-sha256)" == "${linux_sha}" ]] || status=1
    [[ "${cleanup_success}" == true && "${child_cleanup_success}" == true && "${child_post_cleanup_status}" == 0 && "${health_status}" == 0 && "${resource_status}" == 0 ]] || status=1
    validate_traces "${direction}" "${candidate}" "${run_dir}" || status=1
  fi
  transfer_status="${status}"
}

publish_indexes() {
  python3 - "${root}" <<'PY'
import csv
import glob
import json
import statistics
import sys

root = sys.argv[1]
rows = []
for path in glob.glob(root + "/results/*.json"):
    with open(path, encoding="utf-8") as source:
        rows.append(json.load(source))
rows.sort(key=lambda row: row["sequence"])
efficiency_fields = ["bulk_native_send_attempts", "bulk_native_send_syscalls", "bulk_gso_messages", "bulk_logical_datagrams", "bulk_accepted_payload_bytes", "bulk_gso_segments_per_message"]
resource_fields = ["sender_user_cpu_seconds", "sender_system_cpu_seconds", "sender_max_rss_bytes", "sender_resource_stats_available", "receiver_user_cpu_seconds", "receiver_system_cpu_seconds", "receiver_max_rss_bytes", "receiver_resource_stats_available", "resource_telemetry_status", "hetz_cpu_seconds", "hetz_cpu_seconds_per_gib", "hetz_max_rss_bytes"]
fields = ["sequence", "run_id", "direction", "candidate_id", "capacity_mbps", "started", "status", "success", "cleanup_success", "goodput_mbps", "wall_goodput_mbps", "source_sha256", "sink_sha256", "sink_size_bytes", "efficiency_telemetry_status", *efficiency_fields, *resource_fields]
with open(root + "/results.csv", "x", encoding="utf-8", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
groups = {}
for row in rows:
    if row["started"]:
        groups.setdefault((row["direction"], row["candidate_id"]), []).append(row)
with open(root + "/comparison.csv", "x", encoding="utf-8", newline="") as output:
    fields = ["direction", "candidate_id", "started_runs", "successful_runs", "efficiency_telemetry_status", "efficiency_available_runs", "resource_telemetry_status", "resource_available_runs", "median_goodput_mbps", "median_wall_goodput_mbps", "median_hetz_cpu_seconds", "median_hetz_cpu_seconds_per_gib", "median_hetz_max_rss_bytes", *["median_" + field for field in efficiency_fields]]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for key in sorted(groups):
        values = groups[key]
        successful = [row for row in values if row["success"]]
        efficiency = [row for row in successful if row["efficiency_telemetry_status"] == "available"]
        resource = [row for row in successful if row["resource_telemetry_status"] == "available"]
        if key[1] == "frozen-control":
            efficiency_status = "unavailable"
        elif successful and len(efficiency) == len(successful):
            efficiency_status = "available"
        elif efficiency:
            efficiency_status = "incomplete"
        else:
            efficiency_status = "missing"
        result = {
            "direction": key[0],
            "candidate_id": key[1],
            "started_runs": len(values),
            "successful_runs": len(successful),
            "efficiency_telemetry_status": efficiency_status,
            "efficiency_available_runs": len(efficiency),
            "resource_telemetry_status": "available" if successful and len(resource) == len(successful) else ("incomplete" if resource else "unavailable"),
            "resource_available_runs": len(resource),
            "median_goodput_mbps": f"{statistics.median([row['goodput_mbps'] for row in successful]):.3f}" if successful else "0.000",
            "median_wall_goodput_mbps": f"{statistics.median([row['wall_goodput_mbps'] for row in successful]):.3f}" if successful else "0.000",
            "median_hetz_cpu_seconds": f"{statistics.median([row['hetz_cpu_seconds'] for row in resource]):.3f}" if resource else "",
            "median_hetz_cpu_seconds_per_gib": f"{statistics.median([row['hetz_cpu_seconds_per_gib'] for row in resource]):.3f}" if resource else "",
            "median_hetz_max_rss_bytes": f"{statistics.median([row['hetz_max_rss_bytes'] for row in resource]):.3f}" if resource else "",
        }
        for field in efficiency_fields:
            result["median_" + field] = f"{statistics.median([row[field] for row in efficiency]):.3f}" if efficiency else ""
        writer.writerow(result)
PY
  seal_artifact "${root}/results.csv"
  seal_artifact "${root}/comparison.csv"
}

run_preliminary() {
  local direction candidate run_id run_dir sequence_index=0
  for direction in "${directions[@]}"; do
    for candidate in "${sequence[@]}"; do
      sequence_index=$((sequence_index + 1))
      run_id="$(printf '%02d-%s-%s' "${sequence_index}" "${direction}" "${candidate}")"
      run_dir="${root}/runs/${run_id}"
      mkdir "${run_dir}"
      if ! run_capacity_control "${direction}" "${run_dir}"; then
        write_postponed_result "${run_id}" "${sequence_index}" "${direction}" "${candidate}" "${last_capacity:-0}" "${run_dir}"
        chmod -R a-w "${run_dir}" "${root}/results/${run_id}.json"
        publish_indexes
        return 1
      fi
      ensure_payloads
      run_transfer "${run_id}" "${direction}" "${candidate}" "${run_dir}"
      write_result "${run_id}" "${sequence_index}" "${direction}" "${candidate}" "${last_capacity}" "${transfer_started}" "${transfer_status}" "${run_dir}"
      [[ "${transfer_status}" == 0 ]] || preliminary_failed=1
      chmod -R a-w "${run_dir}" "${root}/results/${run_id}.json" "${root}/cleanup/${run_id}.json"
      if [[ "${health_status}" != 0 || "${child_post_cleanup_status}" != 0 || "$(footer_value "${run_dir}" benchmark-cleanup-success 2>/dev/null || true)" != true ]]; then
        publish_indexes
        return 1
      fi
    done
  done
  publish_indexes
  ((preliminary_failed == 0))
}

main() {
  parse_args "$@"
  load_candidates
  setup_tools_and_remote
  check_preallocation_capacity
  run_preliminary
}

main "$@"
