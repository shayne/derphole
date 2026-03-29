# derpcat npm Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `viberun`-style npm packaging and GitHub release automation to `derpcat`, then prepare the repo for a manual `0.0.1` npm bootstrap publish and later trusted-publisher-driven releases.

**Architecture:** Keep the existing Go CLI intact and add a release skeleton around it: version metadata in the binary, a vendored native-binary layout under `dist/vendor`, a thin Node launcher under `packaging/npm`, local release tasks in `mise`, and a single GitHub Actions workflow that publishes `dev` from `main` and prod from `v*` tags. Reuse local shell scripts from CI so the manual `0.0.1` bootstrap and the automated publish flow share the same packaging path.

**Tech Stack:** Go 1.26, Node.js 24 via mise, bash packaging scripts, GitHub Actions, npm public registry with trusted publishing.

---

### Task 1: Add Release Metadata, `--version`, And Repo Root Docs

**Files:**
- Create: `cmd/derpcat/version.go`
- Create: `cmd/derpcat/version_test.go`
- Create: `README.md`
- Create: `LICENSE`
- Modify: `cmd/derpcat/root.go`
- Modify: `cmd/derpcat/root_test.go`

- [ ] **Step 1: Write the failing version tests**

Create `cmd/derpcat/version_test.go` with:

```go
package main

import "testing"

func TestVersionStringDefaults(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = origVersion, origCommit, origBuildDate
	})

	version = "dev"
	commit = "unknown"
	buildDate = "unknown"

	if got := versionString(); got != "dev" {
		t.Fatalf("versionString() = %q, want %q", got, "dev")
	}
}

func TestVersionStringUsesInjectedValue(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = origVersion, origCommit, origBuildDate
	})

	version = "v0.0.1"
	commit = "abc1234"
	buildDate = "2026-03-29T12:00:00Z"

	if got := versionString(); got != "v0.0.1" {
		t.Fatalf("versionString() = %q, want %q", got, "v0.0.1")
	}
}
```

Extend `cmd/derpcat/root_test.go` with:

```go
func TestRunRootVersionSucceeds(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = origVersion, origCommit, origBuildDate
	})

	version = "v0.0.1"
	commit = "abc1234"
	buildDate = "2026-03-29T12:00:00Z"

	for _, args := range [][]string{{"--version"}, {"-v", "--version"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got := stdout.String(); got != "v0.0.1\n" {
				t.Fatalf("stdout = %q, want version output", got)
			}
			if got := stderr.String(); got != "" {
				t.Fatalf("stderr = %q, want empty", got)
			}
		})
	}
}
```

- [ ] **Step 2: Run the targeted tests and confirm they fail**

Run:

```bash
mise exec -- go test ./cmd/derpcat -run 'TestVersionString|TestRunRootVersionSucceeds' -count=1
```

Expected: FAIL with undefined `version`, `commit`, `buildDate`, or missing `--version` handling.

- [ ] **Step 3: Implement release metadata plumbing and root `--version`**

Create `cmd/derpcat/version.go`:

```go
package main

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func versionString() string {
	return version
}
```

Update `cmd/derpcat/root.go` so the root parser handles `--version` before subcommand dispatch:

```go
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	level := telemetry.LevelDefault
	for len(args) > 0 {
		switch args[0] {
		case "-v", "--verbose":
			level = telemetry.LevelVerbose
			args = args[1:]
		case "-q", "--quiet":
			level = telemetry.LevelQuiet
			args = args[1:]
		case "-s", "--silent":
			level = telemetry.LevelSilent
			args = args[1:]
		case "--version":
			fmt.Fprintln(stdout, versionString())
			return 0
		case "-h", "--help":
			fmt.Fprintln(stderr, "usage: derpcat <listen|send> [flags]")
			return 0
		default:
			goto dispatch
		}
	}
```

- [ ] **Step 4: Add the root docs and license**

Create `README.md` with:

```md
# derpcat

`derpcat` is a standalone Go CLI for moving one bidirectional byte stream between two hosts using the public Tailscale DERP network for bootstrap and relay fallback, with direct UDP promotion when possible.

## Install

### npm (production)

```bash
npx derpcat --version
```

### npm (dev channel)

```bash
npx derpcat@dev --version
```

## Build

```bash
mise run build
```

## Test

```bash
mise run test
mise run smoke-local
```

## Release

`main` publishes the `dev` npm dist-tag.
Version tags like `v0.1.0` publish production releases.
The first `0.0.1` npm publish is performed manually from `dist/npm`.
```

Create `LICENSE` by copying the BSD-3-Clause license from `viberun`:

```bash
cp /Users/shayne/code/viberun/LICENSE /Users/shayne/code/derpcat/LICENSE
```

- [ ] **Step 5: Run the tests again and verify they pass**

Run:

```bash
mise exec -- go test ./cmd/derpcat -run 'TestVersionString|TestRunRootVersionSucceeds' -count=1
mise exec -- go test ./...
```

Expected: PASS for the targeted tests and the full Go test suite.

- [ ] **Step 6: Commit**

```bash
git add cmd/derpcat/version.go cmd/derpcat/version_test.go cmd/derpcat/root.go cmd/derpcat/root_test.go README.md LICENSE
git commit -m "release: add CLI version metadata"
```

### Task 2: Add Native Vendor Packaging Scripts And npm Template

**Files:**
- Create: `packaging/npm/package.json`
- Create: `packaging/npm/README.md`
- Create: `packaging/npm/bin/derpcat.js`
- Create: `tools/packaging/build-vendor.sh`
- Create: `tools/packaging/build-npm.sh`
- Create: `tools/packaging/build-release-assets.sh`
- Create: `scripts/release-package-smoke.sh`

- [ ] **Step 1: Add the npm package template**

Create `packaging/npm/package.json`:

```json
{
  "name": "derpcat",
  "version": "0.0.0",
  "license": "BSD-3-Clause",
  "bin": {
    "derpcat": "bin/derpcat.js"
  },
  "type": "module",
  "engines": {
    "node": ">=16"
  },
  "files": [
    "bin",
    "vendor",
    "README.md",
    "LICENSE"
  ],
  "repository": {
    "type": "git",
    "url": "git+https://github.com/shayne/derpcat.git"
  }
}
```

Create `packaging/npm/README.md`:

```md
# derpcat (packaging placeholder)

The published npm package uses the repository root `README.md`.
`tools/packaging/build-npm.sh` copies the root README into `dist/npm/`.
```

- [ ] **Step 2: Add the Node launcher**

Create `packaging/npm/bin/derpcat.js`:

```js
#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const triples = new Map([
  ["linux:x64", "x86_64-unknown-linux-musl"],
  ["linux:arm64", "aarch64-unknown-linux-musl"],
  ["android:x64", "x86_64-unknown-linux-musl"],
  ["android:arm64", "aarch64-unknown-linux-musl"],
  ["darwin:x64", "x86_64-apple-darwin"],
  ["darwin:arm64", "aarch64-apple-darwin"]
]);

const triple = triples.get(`${process.platform}:${process.arch}`);
if (!triple) {
  throw new Error(`Unsupported platform: ${process.platform} (${process.arch})`);
}

const binaryName = process.platform === "win32" ? "derpcat.exe" : "derpcat";
const binaryPath = path.join(__dirname, "..", "vendor", triple, "derpcat", binaryName);
if (!existsSync(binaryPath)) {
  throw new Error(`Missing vendored binary: ${binaryPath}`);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: { ...process.env, DERPCAT_MANAGED_BY_NPM: "1" }
});

child.on("error", (err) => {
  console.error(err);
  process.exit(1);
});

["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
  process.on(sig, () => {
    if (!child.killed) {
      child.kill(sig);
    }
  });
});

const result = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ signal });
      return;
    }
    resolve({ code: code ?? 1 });
  });
});

if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.code);
}
```

- [ ] **Step 3: Add the packaging scripts**

Create `tools/packaging/build-vendor.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR="${ROOT_DIR}/dist/vendor"

: "${VERSION:?VERSION is required}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

targets=(
  "linux amd64 x86_64-unknown-linux-musl derpcat"
  "linux arm64 aarch64-unknown-linux-musl derpcat"
  "darwin amd64 x86_64-apple-darwin derpcat"
  "darwin arm64 aarch64-apple-darwin derpcat"
)

for target in "${targets[@]}"; do
  read -r goos goarch triple binary <<<"${target}"
  dest_dir="${OUT_DIR}/${triple}/derpcat"
  mkdir -p "${dest_dir}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build \
      -trimpath \
      -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o "${dest_dir}/${binary}" \
      ./cmd/derpcat
  chmod +x "${dest_dir}/${binary}"
done
```

Create `tools/packaging/build-npm.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SRC_DIR="${ROOT_DIR}/packaging/npm"
VENDOR_DIR="${ROOT_DIR}/dist/vendor"
OUT_DIR="${ROOT_DIR}/dist/npm"

: "${VERSION:?VERSION is required}"
PACKAGE_VERSION="${VERSION#v}"
export PACKAGE_VERSION

if [ ! -d "${VENDOR_DIR}" ]; then
  echo "missing vendor dir: ${VENDOR_DIR}" >&2
  exit 1
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

cp -R "${SRC_DIR}/bin" "${OUT_DIR}/"
cp "${SRC_DIR}/package.json" "${OUT_DIR}/"
cp "${ROOT_DIR}/README.md" "${OUT_DIR}/"
cp "${ROOT_DIR}/LICENSE" "${OUT_DIR}/"
cp -R "${VENDOR_DIR}" "${OUT_DIR}/vendor"
chmod +x "${OUT_DIR}/bin/derpcat.js"

node -e "const fs=require('fs'); const path=require('path'); const pkgPath=path.join('${OUT_DIR}','package.json'); const pkg=JSON.parse(fs.readFileSync(pkgPath,'utf8')); pkg.version=process.env.PACKAGE_VERSION; fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');"
```

Create `tools/packaging/build-release-assets.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RAW_DIR="${ROOT_DIR}/dist/raw"
OUT_DIR="${ROOT_DIR}/dist/release"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

for asset in \
  derpcat-linux-amd64 \
  derpcat-linux-arm64 \
  derpcat-darwin-amd64 \
  derpcat-darwin-arm64
do
  if [ ! -f "${RAW_DIR}/${asset}" ]; then
    echo "missing raw asset: ${RAW_DIR}/${asset}" >&2
    exit 1
  fi
  chmod +x "${RAW_DIR}/${asset}"
  tar -czf "${OUT_DIR}/${asset}.tar.gz" -C "${RAW_DIR}" "${asset}"
  (cd "${OUT_DIR}" && shasum -a 256 "${asset}.tar.gz" > "${asset}.tar.gz.sha256")
done
```

- [ ] **Step 4: Add the reusable local packaging smoke script**

Create `scripts/release-package-smoke.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${VERSION:?VERSION is required}"

COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
export VERSION COMMIT BUILD_DATE

bash "${ROOT_DIR}/tools/packaging/build-vendor.sh"
bash "${ROOT_DIR}/tools/packaging/build-npm.sh"

test -x "${ROOT_DIR}/dist/vendor/x86_64-unknown-linux-musl/derpcat/derpcat"
test -x "${ROOT_DIR}/dist/vendor/aarch64-unknown-linux-musl/derpcat/derpcat"
test -x "${ROOT_DIR}/dist/vendor/x86_64-apple-darwin/derpcat/derpcat"
test -x "${ROOT_DIR}/dist/vendor/aarch64-apple-darwin/derpcat/derpcat"

node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${ROOT_DIR}/dist/npm/package.json','utf8')); if (pkg.version !== process.env.VERSION.replace(/^v/,'')) { process.exit(1); }"
npm publish "${ROOT_DIR}/dist/npm" --access public --dry-run
```

- [ ] **Step 5: Run the packaging smoke test**

Run:

```bash
chmod +x tools/packaging/build-vendor.sh tools/packaging/build-npm.sh tools/packaging/build-release-assets.sh scripts/release-package-smoke.sh
VERSION=v0.0.1 mise exec -- bash ./scripts/release-package-smoke.sh
```

Expected: `npm publish --dry-run` succeeds and `dist/npm/package.json` contains `0.0.1`.

- [ ] **Step 6: Commit**

```bash
git add packaging/npm/package.json packaging/npm/README.md packaging/npm/bin/derpcat.js tools/packaging/build-vendor.sh tools/packaging/build-npm.sh tools/packaging/build-release-assets.sh scripts/release-package-smoke.sh
git commit -m "release: add npm packaging scripts"
```

### Task 3: Extend `mise` With Local Release Tasks

**Files:**
- Modify: `.mise.toml`

- [ ] **Step 1: Add the release-oriented tasks and toolchain**

Update `.mise.toml` to:

```toml
[tools]
go = "1.26.1"
node = "24"

[tasks.test]
run = "go test ./..."

[tasks.vet]
run = "go vet ./..."

[tasks.build]
run = "mkdir -p dist && go build -o dist/derpcat ./cmd/derpcat"

[tasks.build-linux-amd64]
run = "mkdir -p dist && GOOS=linux GOARCH=amd64 go build -o dist/derpcat-linux-amd64 ./cmd/derpcat"

[tasks."release:build-vendor"]
run = "bash ./tools/packaging/build-vendor.sh"

[tasks."release:build-npm"]
run = "bash ./tools/packaging/build-npm.sh"

[tasks."release:package-assets"]
run = "bash ./tools/packaging/build-release-assets.sh"

[tasks."release:npm-dry-run"]
run = "npm publish ./dist/npm --access public --dry-run"

[tasks."release:smoke"]
run = "bash ./scripts/release-package-smoke.sh"

[tasks."release:build-all"]
run = """
set -euo pipefail
mkdir -p dist/raw
bash ./tools/packaging/build-vendor.sh
cp dist/vendor/x86_64-unknown-linux-musl/derpcat/derpcat dist/raw/derpcat-linux-amd64
cp dist/vendor/aarch64-unknown-linux-musl/derpcat/derpcat dist/raw/derpcat-linux-arm64
cp dist/vendor/x86_64-apple-darwin/derpcat/derpcat dist/raw/derpcat-darwin-amd64
cp dist/vendor/aarch64-apple-darwin/derpcat/derpcat dist/raw/derpcat-darwin-arm64
bash ./tools/packaging/build-release-assets.sh
bash ./tools/packaging/build-npm.sh
"""
```

- [ ] **Step 2: Run the local release tasks**

Run:

```bash
VERSION=0.0.0-dev.20260329120000+abc123 COMMIT=abc1234 BUILD_DATE=2026-03-29T12:00:00Z mise run release:build-all
VERSION=0.0.0-dev.20260329120000+abc123 mise run release:npm-dry-run
mise run vet
```

Expected: `dist/raw`, `dist/release`, and `dist/npm` are populated and `npm publish --dry-run` succeeds.

- [ ] **Step 3: Commit**

```bash
git add .mise.toml
git commit -m "release: add local packaging tasks"
```

### Task 4: Add The Unified GitHub Release Workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Add the workflow metadata and validation jobs**

Create `.github/workflows/release.yml` with the top half:

```yaml
name: Release

on:
  push:
    branches:
      - "main"
    tags:
      - "v*"

permissions:
  contents: read

jobs:
  meta:
    name: Compute version metadata
    runs-on: ubuntu-latest
    outputs:
      is_tag: ${{ steps.meta.outputs.is_tag }}
      is_main: ${{ steps.meta.outputs.is_main }}
      version: ${{ steps.meta.outputs.version }}
    steps:
      - name: Build version strings
        id: meta
        run: |
          is_tag=false
          is_main=false
          if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then is_tag=true; fi
          if [ "${GITHUB_REF_NAME:-}" = "main" ]; then is_main=true; fi
          ts=$(date -u +%Y%m%d%H%M%S)
          short_sha="${GITHUB_SHA::7}"
          if [ "$is_tag" = true ]; then
            version="${GITHUB_REF_NAME}"
          else
            version="0.0.0-dev.${ts}+${short_sha}"
          fi
          echo "is_tag=$is_tag" >> "$GITHUB_OUTPUT"
          echo "is_main=$is_main" >> "$GITHUB_OUTPUT"
          echo "version=$version" >> "$GITHUB_OUTPUT"

  check:
    name: Build + test
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v3
        with:
          install: true
          cache: true
      - name: Build
        run: mise run build
      - name: Test
        run: mise run test
      - name: Vet
        run: mise run vet
```

- [ ] **Step 2: Add the matrix build and release jobs**

Append:

```yaml
  build-derpcat:
    name: Build derpcat (${{ matrix.goos }}/${{ matrix.goarch }})
    runs-on: ${{ matrix.runner }}
    needs: [meta]
    strategy:
      fail-fast: false
      matrix:
        include:
          - runner: ubuntu-latest
            goos: linux
            goarch: amd64
            asset: derpcat-linux-amd64
          - runner: ubuntu-latest
            goos: linux
            goarch: arm64
            asset: derpcat-linux-arm64
          - runner: macos-latest
            goos: darwin
            goarch: amd64
            asset: derpcat-darwin-amd64
          - runner: macos-latest
            goos: darwin
            goarch: arm64
            asset: derpcat-darwin-arm64
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v3
        with:
          install: true
          cache: true
      - name: Build
        run: |
          mkdir -p dist
          VERSION=${{ needs.meta.outputs.version }}
          COMMIT=${{ github.sha }}
          BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} CGO_ENABLED=0 \
            go build -trimpath \
              -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
              -o dist/${{ matrix.asset }} \
              ./cmd/derpcat
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.asset }}
          path: dist/${{ matrix.asset }}
          if-no-files-found: error

  release-prod:
    name: Publish release
    runs-on: ubuntu-latest
    needs: [meta, check, build-derpcat]
    if: needs.meta.outputs.is_tag == 'true'
    permissions:
      contents: write
    steps:
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist/raw
          merge-multiple: true
      - name: Verify binary version
        run: |
          chmod +x dist/raw/derpcat-linux-amd64
          test "$(dist/raw/derpcat-linux-amd64 --version)" = "${{ needs.meta.outputs.version }}"
      - name: Package tarballs + checksums
        run: bash ./tools/packaging/build-release-assets.sh
      - name: Publish release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          fail_on_unmatched_files: true
          files: |
            dist/release/derpcat-linux-amd64.tar.gz
            dist/release/derpcat-linux-amd64.tar.gz.sha256
            dist/release/derpcat-linux-arm64.tar.gz
            dist/release/derpcat-linux-arm64.tar.gz.sha256
            dist/release/derpcat-darwin-amd64.tar.gz
            dist/release/derpcat-darwin-amd64.tar.gz.sha256
            dist/release/derpcat-darwin-arm64.tar.gz
            dist/release/derpcat-darwin-arm64.tar.gz.sha256
```

- [ ] **Step 3: Add the dev release and npm publish jobs**

Append:

```yaml
  release-dev:
    name: Publish dev release
    runs-on: ubuntu-latest
    needs: [meta, check, build-derpcat]
    if: needs.meta.outputs.is_main == 'true'
    permissions:
      contents: write
    steps:
      - name: Checkout
        uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist/raw
          merge-multiple: true
      - name: Verify binary version
        run: |
          chmod +x dist/raw/derpcat-linux-amd64
          test "$(dist/raw/derpcat-linux-amd64 --version)" = "${{ needs.meta.outputs.version }}"
      - name: Package tarballs + checksums
        run: bash ./tools/packaging/build-release-assets.sh
      - name: Update dev tag
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git tag -f dev "$GITHUB_SHA"
          git push -f origin refs/tags/dev
      - name: Publish dev release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: dev
          name: Dev
          prerelease: true
          make_latest: false
          overwrite_files: true
          fail_on_unmatched_files: true
          files: |
            dist/release/derpcat-linux-amd64.tar.gz
            dist/release/derpcat-linux-amd64.tar.gz.sha256
            dist/release/derpcat-linux-arm64.tar.gz
            dist/release/derpcat-linux-arm64.tar.gz.sha256
            dist/release/derpcat-darwin-amd64.tar.gz
            dist/release/derpcat-darwin-amd64.tar.gz.sha256
            dist/release/derpcat-darwin-arm64.tar.gz
            dist/release/derpcat-darwin-arm64.tar.gz.sha256

  publish-packages-prod:
    name: Build npm artifact (prod)
    runs-on: ubuntu-latest
    needs: [meta, release-prod]
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v3
        with:
          install: true
          cache: true
      - name: Build npm artifact
        run: |
          VERSION=${{ needs.meta.outputs.version }}
          COMMIT=${{ github.sha }}
          BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          export VERSION COMMIT BUILD_DATE
          mise run release:build-all
          tar -czf dist/npm.tgz -C dist npm
      - name: Upload package artifact
        uses: actions/upload-artifact@v4
        with:
          name: package-artifacts-prod
          path: dist/npm.tgz
          if-no-files-found: error

  publish-packages-dev:
    name: Build npm artifact (dev)
    runs-on: ubuntu-latest
    needs: [meta, release-dev]
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v3
        with:
          install: true
          cache: true
      - name: Build npm artifact
        run: |
          VERSION=${{ needs.meta.outputs.version }}
          COMMIT=${{ github.sha }}
          BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          export VERSION COMMIT BUILD_DATE
          mise run release:build-all
          tar -czf dist/npm.tgz -C dist npm
      - name: Upload package artifact
        uses: actions/upload-artifact@v4
        with:
          name: package-artifacts-dev
          path: dist/npm.tgz
          if-no-files-found: error

  publish-npm-prod:
    name: Publish npm package
    runs-on: ubuntu-latest
    needs: [publish-packages-prod]
    permissions:
      contents: read
      id-token: write
    environment:
      name: npm
      url: https://www.npmjs.com/package/derpcat
    steps:
      - name: Download package artifact
        uses: actions/download-artifact@v4
        with:
          name: package-artifacts-prod
          path: dist
      - name: Unpack npm artifact
        run: tar -xzf dist/npm.tgz -C dist
      - name: Setup Node
        uses: actions/setup-node@v6
        with:
          node-version: 24
          registry-url: https://registry.npmjs.org
      - name: Publish npm package
        run: npm publish ./dist/npm --access public

  publish-npm-dev:
    name: Publish npm package (dev tag)
    runs-on: ubuntu-latest
    needs: [publish-packages-dev]
    permissions:
      contents: read
      id-token: write
    environment:
      name: npm
      url: https://www.npmjs.com/package/derpcat
    steps:
      - name: Download package artifact
        uses: actions/download-artifact@v4
        with:
          name: package-artifacts-dev
          path: dist
      - name: Unpack npm artifact
        run: tar -xzf dist/npm.tgz -C dist
      - name: Setup Node
        uses: actions/setup-node@v6
        with:
          node-version: 24
          registry-url: https://registry.npmjs.org
      - name: Publish npm package (dev tag)
        run: npm publish ./dist/npm --access public --tag dev
```

- [ ] **Step 4: Validate the workflow-backed local path**

Run:

```bash
VERSION=0.0.0-dev.20260329123000+abc123 COMMIT=abc1234 BUILD_DATE=2026-03-29T12:30:00Z mise run release:build-all
VERSION=v0.0.1 COMMIT=abc1234 BUILD_DATE=2026-03-29T12:30:00Z mise run release:build-all
git diff --check
```

Expected: both local builds succeed and `git diff --check` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "release: add npm publishing workflow"
```

### Task 5: Document And Validate The Manual `0.0.1` Bootstrap Path

**Files:**
- Create: `docs/releases/npm-bootstrap.md`
- Modify: `README.md`

- [ ] **Step 1: Add the manual bootstrap runbook**

Create `docs/releases/npm-bootstrap.md`:

```md
# Manual npm Bootstrap Publish

This runbook is for the first npm publish before GitHub trusted publishing is configured.

## Prerequisites

- npm account with publish access to `derpcat`
- local `npm whoami` succeeds
- clean git working tree

## Build and validate `0.0.1`

```bash
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
VERSION=v0.0.1 mise run release:npm-dry-run
node ./dist/npm/bin/derpcat.js --version
```

Expected output:

- `npm publish --dry-run` succeeds
- `node ./dist/npm/bin/derpcat.js --version` prints `v0.0.1`

## Publish

```bash
npm publish ./dist/npm --access public
```

## After trusted publisher setup

Once npm trusted publishing is configured for `shayne/derpcat`:

```bash
git tag v0.1.0
git push origin main --tags
```
```

- [ ] **Step 2: Link the release runbook from the root README**

Append to `README.md`:

```md
## Publishing

- Manual bootstrap instructions: `docs/releases/npm-bootstrap.md`
- `main` is the dev channel and publishes npm dist-tag `dev`
- version tags like `v0.1.0` publish production releases through GitHub Actions
```

- [ ] **Step 3: Validate the manual bootstrap path locally**

Run:

```bash
npm whoami
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
VERSION=v0.0.1 mise run release:npm-dry-run
node ./dist/npm/bin/derpcat.js --version
```

Expected:

- `npm whoami` prints the authenticated npm username
- `npm publish --dry-run` succeeds
- the packaged launcher prints `v0.0.1`

- [ ] **Step 4: Commit**

```bash
git add README.md docs/releases/npm-bootstrap.md
git commit -m "docs: add npm bootstrap publish runbook"
```
