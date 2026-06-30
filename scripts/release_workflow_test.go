// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseWorkflowNpmPublishesSkipUnclaimedUntilBootstrap(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}

	body := string(data)
	commands := []string{
		"bash ./tools/packaging/publish-npm-if-missing.sh --skip-unclaimed ./dist/npm-derphole",
		"bash ./tools/packaging/publish-npm-if-missing.sh --skip-unclaimed ./dist/npm-derptun",
		"bash ./tools/packaging/publish-npm-if-missing.sh --skip-unclaimed ./dist/npm-derpssh",
		"bash ./tools/packaging/publish-npm-if-missing.sh --tag dev --skip-unclaimed ./dist/npm-derphole",
		"bash ./tools/packaging/publish-npm-if-missing.sh --tag dev --skip-unclaimed ./dist/npm-derptun",
		"bash ./tools/packaging/publish-npm-if-missing.sh --tag dev --skip-unclaimed ./dist/npm-derpssh",
	}
	for _, command := range commands {
		if !strings.Contains(body, command) {
			t.Fatalf("release workflow does not tolerate npm bootstrap state with command %q", command)
		}
	}
}

func TestReleaseWorkflowIncludesDerpsshArtifacts(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}

	body := string(data)
	for _, asset := range []string{
		"derpssh-linux-amd64",
		"derpssh-linux-arm64",
		"derpssh-darwin-amd64",
		"derpssh-darwin-arm64",
	} {
		if !strings.Contains(body, asset) {
			t.Fatalf("release workflow missing derpssh artifact %q", asset)
		}
	}
}

func TestReleaseWorkflowPublishesSwiftPMFramework(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}

	body := string(data)
	for _, required := range []string{
		"build-swiftpm-framework:",
		"runs-on: macos-latest",
		"mise run swiftpm:framework",
		"name: derphole-mobile-swiftpm",
		"path: dist/swiftpm/DerpholeMobile.xcframework.zip",
		"needs: [meta, check, build-binaries, build-web, build-swiftpm-framework, publish-npm-prod]",
		"needs: [check, publish-packages-prod, build-swiftpm-framework]",
		"-n derphole-mobile-swiftpm",
		"dist/release/DerpholeMobile.xcframework.zip",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("release workflow does not publish SwiftPM framework; missing %q", required)
		}
	}
}

func TestReleaseWorkflowVerifiesSwiftPMPackageTarget(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}

	body := string(data)
	for _, required := range []string{
		"Verify Package.swift binary target",
		"swift package compute-checksum dist/swiftpm/DerpholeMobile.xcframework.zip",
		"https://github.com/shayne/derphole/releases/download/${VERSION}/DerpholeMobile.xcframework.zip",
		"DerpholeMobile SwiftPM binary target does not match this release artifact",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("release workflow does not verify SwiftPM Package.swift target; missing %q", required)
		}
	}
}

func TestReleaseWorkflowDoesNotInterpolateVersionInShell(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}

	body := string(data)
	for _, unsafe := range []string{
		"VERSION=${{ needs.meta.outputs.version }}",
		"\"${{ needs.meta.outputs.version }}\"",
	} {
		if strings.Contains(body, unsafe) {
			t.Fatalf("release workflow interpolates version into shell with %q", unsafe)
		}
	}
	if !strings.Contains(body, "VERSION: ${{ needs.meta.outputs.version }}") {
		t.Fatal("release workflow does not pass version through step environment")
	}
}
