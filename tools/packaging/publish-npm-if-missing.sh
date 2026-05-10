#!/usr/bin/env bash
# Copyright (c) 2026 Shayne All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: publish-npm-if-missing.sh [--tag TAG] [--dry-run] [--skip-unclaimed] <package-dir>
EOF
  exit 2
}

tag=""
dry_run=false
skip_unclaimed=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -ge 2 ]] || usage
      tag="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --skip-unclaimed)
      skip_unclaimed=true
      shift
      ;;
    -*)
      usage
      ;;
    *)
      break
      ;;
  esac
done

[[ $# -eq 1 ]] || usage

package_dir="$1"
package_json="${package_dir}/package.json"
[[ -f "${package_json}" ]] || {
  echo "missing package.json: ${package_json}" >&2
  exit 1
}

package_name="$(node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); process.stdout.write(pkg.name);" "${package_json}")"
package_version="$(node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); process.stdout.write(pkg.version);" "${package_json}")"

package_exists=true
if ! package_view_output="$(npm view "${package_name}" name 2>&1)"; then
  if grep -q "E404" <<<"${package_view_output}"; then
    package_exists=false
    if [[ "${skip_unclaimed}" == true ]]; then
      echo "${package_name} is not published yet; skipping npm publish"
      echo "run docs/releases/npm-bootstrap.md before enabling automated npm publishes"
      exit 0
    fi
  else
    printf '%s\n' "${package_view_output}" >&2
    exit 1
  fi
fi

if [[ "${package_exists}" == true ]]; then
  if package_version_output="$(npm view "${package_name}@${package_version}" version 2>&1)"; then
    echo "already published ${package_name}@${package_version}; skipping"
    exit 0
  fi
  if ! grep -q "E404" <<<"${package_version_output}"; then
    printf '%s\n' "${package_version_output}" >&2
    exit 1
  fi
fi

publish_args=("${package_dir}" --access public)
if [[ -n "${tag}" ]]; then
  publish_args+=(--tag "${tag}")
fi
if [[ "${dry_run}" == true ]]; then
  publish_args+=(--dry-run)
fi

if publish_output="$(npm publish "${publish_args[@]}" 2>&1)"; then
  printf '%s\n' "${publish_output}"
  exit 0
fi

if [[ "${skip_unclaimed}" == true ]] && grep -Eq "E404|E403" <<<"${publish_output}"; then
  printf '%s\n' "${publish_output}"
  echo "${package_name}@${package_version} is not publishable by this workflow yet; skipping npm publish"
  echo "claim the package and configure npm trusted publishing before enabling automated npm publishes"
  exit 0
fi

printf '%s\n' "${publish_output}" >&2
exit 1
