#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: publish-npm-if-missing.sh [--tag TAG] [--dry-run] <package-dir>
EOF
  exit 2
}

tag=""
dry_run=false

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

if npm view "${package_name}@${package_version}" version >/dev/null 2>&1; then
  echo "already published ${package_name}@${package_version}; skipping"
  exit 0
fi

publish_args=("${package_dir}" --access public)
if [[ -n "${tag}" ]]; then
  publish_args+=(--tag "${tag}")
fi
if [[ "${dry_run}" == true ]]; then
  publish_args+=(--dry-run)
fi

npm publish "${publish_args[@]}"
