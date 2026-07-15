#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: udp-peak-candidates.sh --root ROOT --control-local DARWIN_BIN --control-linux LINUX_BIN --revision REVISION
EOF
}

root=""
control_local=""
control_linux=""
revision=""

while (( $# > 0 )); do
  case "$1" in
    --root)
      [[ $# -ge 2 && -z "$root" ]] || { usage; exit 2; }
      root="$2"
      shift 2
      ;;
    --control-local)
      [[ $# -ge 2 && -z "$control_local" ]] || { usage; exit 2; }
      control_local="$2"
      shift 2
      ;;
    --control-linux)
      [[ $# -ge 2 && -z "$control_linux" ]] || { usage; exit 2; }
      control_linux="$2"
      shift 2
      ;;
    --revision)
      [[ $# -ge 2 && -z "$revision" ]] || { usage; exit 2; }
      revision="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$root" || -z "$control_local" || -z "$control_linux" || -z "$revision" ]]; then
  usage
  exit 2
fi
if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "revision must be an exact lowercase 40-character commit" >&2
  exit 2
fi

for variable in GOFLAGS GOEXPERIMENT GOOS GOARCH CGO_ENABLED GOAMD64 GOARM64 GOTOOLCHAIN GOWORK GOFIPS140; do
  if [[ -n "${!variable-}" ]]; then
    echo "${variable} must be unset to prevent ambient build drift" >&2
    exit 2
  fi
done

if [[ -L "$control_local" || ! -f "$control_local" || ! -x "$control_local" ]]; then
  echo "control-local must be a non-symlink executable file" >&2
  exit 2
fi
if [[ -L "$control_linux" || ! -f "$control_linux" || ! -x "$control_linux" ]]; then
  echo "control-linux must be a non-symlink executable file" >&2
  exit 2
fi
command -v go >/dev/null
command -v python3 >/dev/null

candidates=(coalesced-gso3 connected-gso3 combined-gso1 combined-gso2 combined-gso3 combined-gso4 combined-gso6 combined-gso8 combined-gso12 quic-control)

IFS=$'\t' read -r root root_parent root_name parent_device parent_inode < <(python3 - "$root" <<'PY'
import os
import pathlib
import stat
import sys

requested_root = os.path.abspath(sys.argv[1])
requested_parent, root_name = os.path.split(requested_root)
try:
    parent = os.path.realpath(requested_parent, strict=True)
except OSError as error:
    raise SystemExit(f"candidate output parent cannot be resolved: {error}")
root = os.path.join(parent, root_name)
current = pathlib.Path(parent).anchor
for component in pathlib.Path(parent).parts[1:]:
    current = os.path.join(current, component)
    try:
        status = os.lstat(current)
    except FileNotFoundError:
        raise SystemExit("candidate output parent must already exist")
    if stat.S_ISLNK(status.st_mode):
        raise SystemExit("candidate output ancestor must not be a symlink")
    if not stat.S_ISDIR(status.st_mode):
        raise SystemExit("candidate output ancestor must be a directory")
try:
    os.lstat(root)
except FileNotFoundError:
    pass
else:
    raise SystemExit("candidate output root already exists")
parent_status = os.stat(parent, follow_symlinks=False)
values = (root, parent, root_name, str(parent_status.st_dev), str(parent_status.st_ino))
if any("\t" in value or "\n" in value for value in values):
    raise SystemExit("candidate output path contains unsupported control characters")
print("\t".join(values))
PY
)
[[ -n "$root" && -n "$root_parent" && -n "$root_name" ]] || exit 2

staging="$(mktemp -d "${root}.tmp.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
mkdir -p "${staging}/bin"
scratch="${staging}/.scratch"
mkdir -p "$scratch"
rows="${scratch}/registry.tsv"
: >"$rows"

sha256_file() {
  python3 - "$1" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
}

inspect_binary() {
  local binary="$1" expected_goos="$2" expected_goarch="$3" expected_revision="$4"
  local expected_linker="$5" label="$6" output="$7"
  local build_info="${output}.build-info" symbols="${output}.symbols"
  if ! go version -m "$binary" >"$build_info"; then
    echo "${label} is not a readable Go binary" >&2
    return 1
  fi
  if ! go tool nm -size "$binary" >"$symbols"; then
    echo "${label} has no readable Go symbol table" >&2
    return 1
  fi
  python3 - "$binary" "$build_info" "$symbols" "$expected_goos" "$expected_goarch" "$expected_revision" "$expected_linker" "$label" "$output" <<'PY'
import hashlib
import json
import pathlib
import re
import struct
import sys

binary_path, build_info_path, symbols_path, want_goos, want_goarch, want_revision, want_linker, label, output_path = sys.argv[1:]
lines = pathlib.Path(build_info_path).read_text(encoding="utf-8").splitlines()
if not lines or ": " not in lines[0]:
    raise SystemExit(f"{label} has malformed go version metadata")
go_version = lines[0].rsplit(": ", 1)[1]
command_paths = []
modules = []
settings = {}
for line in lines[1:]:
    fields = line.lstrip("\t").split("\t")
    if not fields or fields == [""]:
        continue
    if fields[0] == "path" and len(fields) == 2:
        command_paths.append(fields[1])
    elif fields[0] == "mod" and len(fields) >= 2:
        modules.append(fields[1:])
    elif fields[0] == "build" and len(fields) == 2 and "=" in fields[1]:
        key, value = fields[1].split("=", 1)
        if key in settings:
            raise SystemExit(f"{label} has duplicate build setting {key}")
        settings[key] = value.strip('"')
    elif fields[0] == "=>":
        raise SystemExit(f"{label} uses a replaced module")

want_command = "github.com/shayne/derphole/cmd/derphole"
want_module = "github.com/shayne/derphole"
if command_paths != [want_command]:
    raise SystemExit(f"{label} command path is {command_paths}, want {want_command}")
if len(modules) != 1 or not modules[0] or modules[0][0] != want_module:
    raise SystemExit(f"{label} module is {modules}, want {want_module}")
module_version = modules[0][1] if len(modules[0]) > 1 else "(devel)"

required = {
    "-buildmode": "exe",
    "-compiler": "gc",
    "-trimpath": "true",
    "CGO_ENABLED": "0",
    "GOOS": want_goos,
    "GOARCH": want_goarch,
    "vcs": "git",
    "vcs.modified": "false",
}
if want_goos == "darwin":
    required["GOARM64"] = "v8.0"
else:
    required["GOAMD64"] = "v1"
for key, want in required.items():
    got = settings.get(key)
    if got != want:
        raise SystemExit(f"{label} {key}={got}, want {want}")
revision = settings.get("vcs.revision", "")
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit(f"{label} has no exact VCS revision")
if want_revision and revision != want_revision:
    raise SystemExit(f"{label} vcs.revision={revision}, want {want_revision}")

symbol = "github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate"
symbol_lines = pathlib.Path(symbols_path).read_text(encoding="utf-8").splitlines()
main_symbols = [line for line in symbol_lines if line.split()[-1:] == [symbol]]
string_symbols = [line for line in symbol_lines if line.split()[-1:] == [symbol + ".str"]]
binary = pathlib.Path(binary_path).read_bytes()
fake_marker = "udppeak.config." + (want_linker or "source-default")
selector_state = "absent"
if not main_symbols:
    if want_linker:
        raise SystemExit(f"{label} configured linker value is not bound to the exact Go string variable")
elif len(main_symbols) != 1 or not re.search(r"\s16\s+[BD]\s+" + re.escape(symbol) + r"$", main_symbols[0]):
    raise SystemExit(f"{label} has malformed benchmark selector symbol")
elif binary.startswith(b"fake-go-binary"):
    if not any(line.split()[-1:] == [fake_marker] for line in symbol_lines):
        raise SystemExit(f"{label} configured linker value does not match fake symbol proof")
    selector_state = "linked" if want_linker else "empty"
else:
    def virtual_bytes(address, size):
        if binary[:4] == b"\x7fELF" and binary[4:6] == b"\x02\x01":
            program_offset = struct.unpack_from("<Q", binary, 32)[0]
            entry_size = struct.unpack_from("<H", binary, 54)[0]
            entries = struct.unpack_from("<H", binary, 56)[0]
            for index in range(entries):
                offset = program_offset + index * entry_size
                kind = struct.unpack_from("<I", binary, offset)[0]
                if kind != 1:
                    continue
                file_offset, virtual_address = struct.unpack_from("<QQ", binary, offset + 8)
                file_size, memory_size = struct.unpack_from("<QQ", binary, offset + 32)
                if virtual_address <= address and address + size <= virtual_address + memory_size:
                    relative = address - virtual_address
                    available = max(0, min(size, file_size - relative))
                    data = binary[file_offset + relative:file_offset + relative + available]
                    return data + b"\x00" * (size - available)
        elif binary[:4] == b"\xcf\xfa\xed\xfe":
            commands = struct.unpack_from("<I", binary, 16)[0]
            offset = 32
            for _ in range(commands):
                command, command_size = struct.unpack_from("<II", binary, offset)
                if command == 0x19:
                    virtual_address, virtual_size, file_offset, file_size = struct.unpack_from("<QQQQ", binary, offset + 24)
                    if virtual_address <= address and address + size <= virtual_address + virtual_size:
                        relative = address - virtual_address
                        available = max(0, min(size, file_size - relative))
                        data = binary[file_offset + relative:file_offset + relative + available]
                        return data + b"\x00" * (size - available)
                offset += command_size
        raise SystemExit(f"{label} cannot map configured linker symbol bytes")

    variable_address = int(main_symbols[0].split()[0], 16)
    header = virtual_bytes(variable_address, 16)
    pointer, length = struct.unpack("<QQ", header)
    if want_linker:
        if len(string_symbols) != 1 or length != len(want_linker) or virtual_bytes(pointer, length) != want_linker.encode():
            raise SystemExit(f"{label} configured linker value does not equal {want_linker!r}")
        selector_state = "linked"
    elif pointer != 0 or length != 0 or string_symbols:
        raise SystemExit(f"{label} configured linker value must be empty source-default")
    else:
        selector_state = "empty"

normalized_info = ["<binary>: " + go_version, *lines[1:]]
build_info_digest = hashlib.sha256(("\n".join(normalized_info) + "\n").encode()).hexdigest()
metadata = {
    "go_version": go_version,
    "module_path": want_module,
    "module_version": module_version,
    "command_path": want_command,
    "goos": want_goos,
    "goarch": want_goarch,
    "vcs_revision": revision,
    "vcs_modified": False,
    "build_info_sha256": build_info_digest,
    "configured_linker_value": want_linker,
    "selector_state": selector_state,
}
pathlib.Path(output_path).write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  rm -f "$build_info" "$symbols"
}

append_registry_row() {
  local id="$1" commit="$2" linker_value="$3" configuration_profile="$4" engine="$5" gso_segments="$6"
  local darwin_path="$7" darwin_sha="$8" darwin_metadata="$9"
  local linux_path="${10}" linux_sha="${11}" linux_metadata="${12}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$commit" "$linker_value" "$configuration_profile" "$engine" "$gso_segments" \
    "$darwin_path" "$darwin_sha" "$darwin_metadata" \
    "$linux_path" "$linux_sha" "$linux_metadata" >>"$rows"
}

# Copy controls before inspecting them. Every identity and digest below is taken
# from the exact staged bytes that will be published, never from a replaceable
# source pathname.
control_dir="${staging}/bin/frozen-control"
mkdir -p "$control_dir"
cp "$control_local" "${control_dir}/derphole-darwin-arm64"
cp "$control_linux" "${control_dir}/derphole-linux-amd64"
control_darwin_metadata="${scratch}/control-darwin.json"
control_linux_metadata="${scratch}/control-linux.json"
inspect_binary "${control_dir}/derphole-darwin-arm64" "darwin" "arm64" "" "" "frozen control Darwin binary" "$control_darwin_metadata"
inspect_binary "${control_dir}/derphole-linux-amd64" "linux" "amd64" "" "" "frozen control Linux binary" "$control_linux_metadata"
control_revision_local="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vcs_revision"])' "$control_darwin_metadata")"
control_revision_linux="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vcs_revision"])' "$control_linux_metadata")"
if [[ "$control_revision_local" != "$control_revision_linux" ]]; then
  echo "frozen control pair revisions do not match" >&2
  exit 1
fi
append_registry_row \
  "frozen-control" "$control_revision_local" "" "frozen-bulk-gso3" "bulk-packets-v1" "3" \
  "bin/frozen-control/derphole-darwin-arm64" "$(sha256_file "${control_dir}/derphole-darwin-arm64")" "$control_darwin_metadata" \
  "bin/frozen-control/derphole-linux-amd64" "$(sha256_file "${control_dir}/derphole-linux-amd64")" "$control_linux_metadata"

for candidate in "${candidates[@]}"; do
  candidate_dir="${staging}/bin/${candidate}"
  darwin_binary="${candidate_dir}/derphole-darwin-arm64"
  linux_binary="${candidate_dir}/derphole-linux-amd64"
  linker_flags="-X github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate=${candidate}"
  mkdir -p "$candidate_dir"

  env -u GOFLAGS -u GOEXPERIMENT -u GOOS -u GOARCH -u CGO_ENABLED -u GOAMD64 -u GOARM64 -u GOTOOLCHAIN -u GOWORK -u GOFIPS140 \
    GOENV=off GOTOOLCHAIN=local GOWORK=off GOFIPS140=off GOOS=darwin GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=true -ldflags "$linker_flags" -o "$darwin_binary" ./cmd/derphole
  env -u GOFLAGS -u GOEXPERIMENT -u GOOS -u GOARCH -u CGO_ENABLED -u GOAMD64 -u GOARM64 -u GOTOOLCHAIN -u GOWORK -u GOFIPS140 \
    GOENV=off GOTOOLCHAIN=local GOWORK=off GOFIPS140=off GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=true -ldflags "$linker_flags" -o "$linux_binary" ./cmd/derphole

  darwin_metadata="${scratch}/${candidate}-darwin.json"
  linux_metadata="${scratch}/${candidate}-linux.json"
  inspect_binary "$darwin_binary" "darwin" "arm64" "$revision" "$candidate" "${candidate} Darwin binary" "$darwin_metadata"
  inspect_binary "$linux_binary" "linux" "amd64" "$revision" "$candidate" "${candidate} Linux binary" "$linux_metadata"

  if [[ "$candidate" == "quic-control" ]]; then
    engine="quic-blocks-v1"
    gso_segments="0"
  else
    engine="bulk-packets-v1"
    gso_segments="${candidate##*gso}"
  fi
  append_registry_row \
    "$candidate" "$revision" "$candidate" "benchmark-linker" "$engine" "$gso_segments" \
    "bin/${candidate}/derphole-darwin-arm64" "$(sha256_file "$darwin_binary")" "$darwin_metadata" \
    "bin/${candidate}/derphole-linux-amd64" "$(sha256_file "$linux_binary")" "$linux_metadata"
done

python3 - "$rows" "${staging}/candidates.json" "$revision" <<'PY'
import csv
import json
import sys

rows_path, output_path, source_revision = sys.argv[1:]
candidates = []
with open(rows_path, encoding="utf-8", newline="") as source:
    for row in csv.reader(source, delimiter="\t"):
        candidate_id, commit, linker_value, configuration_profile, engine, gso_segments, darwin_path, darwin_sha, darwin_metadata_path, linux_path, linux_sha, linux_metadata_path = row
        with open(darwin_metadata_path, encoding="utf-8") as metadata_source:
            darwin_metadata = json.load(metadata_source)
        with open(linux_metadata_path, encoding="utf-8") as metadata_source:
            linux_metadata = json.load(metadata_source)
        candidates.append({
            "id": candidate_id,
            "commit": commit,
            "linker_value": linker_value,
            "configuration_profile": configuration_profile,
            "engine": engine,
            "gso_segments_per_message": int(gso_segments),
            "config": {"candidate": candidate_id},
            "darwin": {
                "platform": "darwin-arm64",
                "path": darwin_path,
                "sha256": darwin_sha,
                **darwin_metadata,
            },
            "linux": {
                "platform": "linux-amd64",
                "path": linux_path,
                "sha256": linux_sha,
                **linux_metadata,
            },
        })

registry = {
    "schema_version": 1,
    "control_id": "frozen-control",
    "source_revision": source_revision,
    "candidates": candidates,
}
with open(output_path, "x", encoding="utf-8") as output:
    json.dump(registry, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY

rm -rf "$scratch"
registry_digest="$(sha256_file "${staging}/candidates.json")"
python3 - "$staging" "$root" "$parent_device" "$parent_inode" <<'PY'
import ctypes
import os
import pathlib
import stat
import sys

source_path, destination_path, expected_device, expected_inode = sys.argv[1:]
parent = os.path.dirname(destination_path)
current = pathlib.Path(parent).anchor
for component in pathlib.Path(parent).parts[1:]:
    current = os.path.join(current, component)
    status = os.lstat(current)
    if stat.S_ISLNK(status.st_mode):
        raise SystemExit("candidate output ancestor was replaced by a symlink")
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_status = os.fstat(parent_fd)
    if (parent_status.st_dev, parent_status.st_ino) != (int(expected_device), int(expected_inode)):
        raise SystemExit("candidate output parent identity changed before publication")
    source_parent, source_name = os.path.split(source_path)
    destination_parent, destination_name = os.path.split(destination_path)
    if source_parent != parent or destination_parent != parent:
        raise SystemExit("candidate staging and destination do not share the verified parent")
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = libc.renameatx_np
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        result = rename(parent_fd, source, parent_fd, destination, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        result = rename(parent_fd, source, parent_fd, destination, 1)  # RENAME_NOREPLACE
    else:
        raise SystemExit(f"atomic no-replace publication is unsupported on {sys.platform}")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination_path)
finally:
    os.close(parent_fd)
PY
trap - EXIT
printf 'registry_path=%s\n' "${root}/candidates.json"
printf 'registry_sha256=%s\n' "$registry_digest"
