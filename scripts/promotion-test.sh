#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <target> [size-mib]}"
size_mib="${2:-1024}"
expected_size="$((size_mib * 1048576))"
tmp="$(mktemp -d)"
remote_base="/tmp/derpcat-promotion-$$"
remote_upload="/tmp/derpcat-promotion-bin-$$"

remote() {
  ssh "root@${target}" 'bash -se' <<<"$1"
}

dump_failure() {
  echo "--- local sender log" >&2
  sed -n '1,200p' "${tmp}/send.err" >&2 || true
  echo "--- remote listener log" >&2
  remote "sed -n '1,200p' '${remote_base}.err'" >&2 || true
  echo "--- remote listener size" >&2
  remote "wc -c < '${remote_base}.out'" >&2 || true
}

cleanup() {
  remote "if [[ -f '${remote_base}.pid' ]]; then kill \$(cat '${remote_base}.pid') 2>/dev/null || true; fi; rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err'" >/dev/null 2>&1 || true
  rm -rf "${tmp}"
}

trap 'status=$?; if [[ ${status} -ne 0 ]]; then dump_failure; fi; cleanup; exit ${status}' EXIT

mise run build
mise run build-linux-amd64
scp dist/derpcat-linux-amd64 "root@${target}:${remote_upload}" >/dev/null
remote "install -m 0755 '${remote_upload}' /usr/local/bin/derpcat && rm -f '${remote_upload}' && /usr/local/bin/derpcat --help >/dev/null 2>&1"

payload="${tmp}/payload.bin"
send_log="${tmp}/send.err"
listener_log="${tmp}/listener.err"

echo "generating ${size_mib} MiB random payload"
dd if=/dev/urandom of="${payload}" bs=1048576 count="${size_mib}" 2>/dev/null
local_sha="$(shasum -a 256 "${payload}" | awk '{print $1}')"

remote "rm -f '${remote_base}.pid' '${remote_base}.out' '${remote_base}.err'; nohup /usr/local/bin/derpcat listen >'${remote_base}.out' 2>'${remote_base}.err' </dev/null & echo \$! > '${remote_base}.pid'"

token=""
for _ in $(seq 1 200); do
  token="$(remote "grep -E '^[A-Za-z0-9_-]{20,}$' '${remote_base}.err' | head -n 1 || true")"
  if [[ -n "${token}" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "${token}" ]]; then
  echo "failed to capture listener token" >&2
  exit 1
fi

SECONDS=0
./dist/derpcat send "${token}" <"${payload}" >/dev/null 2>"${send_log}"
duration="${SECONDS}"

for _ in $(seq 1 400); do
  if ! remote "if [[ -f '${remote_base}.pid' ]]; then kill -0 \$(cat '${remote_base}.pid') 2>/dev/null; else false; fi" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

remote "sed -n '1,200p' '${remote_base}.err'" >"${listener_log}"
remote_sha="$(remote "sha256sum '${remote_base}.out' | awk '{print \$1}'")"
remote_size="$(remote "wc -c < '${remote_base}.out'")"

[[ "${local_sha}" == "${remote_sha}" ]]
[[ "${remote_size}" == "${expected_size}" ]]
grep -q 'connected-direct' "${send_log}"
grep -q 'connected-direct' "${listener_log}"

echo "target=${target}"
echo "size_mib=${size_mib}"
echo "duration_seconds=${duration}"
echo "sha256=${local_sha}"
echo "--- sender log"
cat "${send_log}"
echo "--- listener log"
cat "${listener_log}"
