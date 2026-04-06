#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: $0 <target> [size-bytes]}"
size_bytes="${2:-1073741824}"
remote_user="${DERPCAT_REMOTE_USER:-root}"
probe_mode="${DERPCAT_PROBE_MODE:-raw}"
probe_transport="${DERPCAT_PROBE_TRANSPORT:-}"
probe_parallel="${DERPCAT_PROBE_PARALLEL:-1}"
if [[ -z "${probe_transport}" ]]; then
	if [[ "${probe_mode}" == "raw" || "${probe_mode}" == "blast" || "${probe_mode}" == "wg" || "${probe_mode}" == "wgos" || "${probe_mode}" == "wgiperf" ]]; then
		probe_transport="batched"
	else
		probe_transport="legacy"
	fi
fi
probe_local_bin="dist/derpcat-probe"
probe_remote_bin="dist/derpcat-probe-linux-amd64"
remote_probe="/tmp/derpcat-probe"

mkdir -p dist
go build -o "${probe_local_bin}" ./cmd/derpcat-probe
GOOS=linux GOARCH=amd64 go build -o "${probe_remote_bin}" ./cmd/derpcat-probe
ssh "${remote_user}@${target}" "rm -f '${remote_probe}'" >/dev/null
scp "${probe_remote_bin}" "${remote_user}@${target}:${remote_probe}" >/dev/null
ssh "${remote_user}@${target}" "chmod 0755 '${remote_probe}'"

if [[ "${probe_mode}" == "wgos" || "${probe_mode}" == "wgiperf" ]]; then
	sudo -n env "HOME=${HOME}" "SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-}" "./${probe_local_bin}" orchestrate --host "${target}" --user "${remote_user}" --size-bytes "${size_bytes}" --mode "${probe_mode}" --transport "${probe_transport}" --parallel "${probe_parallel}"
else
	"./${probe_local_bin}" orchestrate --host "${target}" --user "${remote_user}" --size-bytes "${size_bytes}" --mode "${probe_mode}" --transport "${probe_transport}" --parallel "${probe_parallel}"
fi
