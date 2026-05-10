// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerpholeWebLandingKeepsDemoInTechnicalFrontDoor(t *testing.T) {
	t.Parallel()

	htmlPath := filepath.Join("..", "web", "derphole", "index.html")
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read web landing page: %v", err)
	}
	html := string(data)

	required := []string{
		`<main class="site-shell">`,
		`<section id="top" class="intro"`,
		`<section id="demo" class="demo-grid"`,
		`href="https://github.com/shayne/derphole"`,
		`npx -y derphole@latest`,
		`href="styles.css?v=dev"`,
		`src="wasm_exec.js?v=dev"`,
		`src="wasm_payload.js?v=dev"`,
		`src="webrtc.js?v=dev"`,
		`src="app.js?v=dev"`,
	}
	for _, want := range required {
		if !strings.Contains(html, want) {
			t.Fatalf("web landing page missing %q", want)
		}
	}

	demoIDs := []string{
		`id="select-send-file"`,
		`id="start-send"`,
		`id="send-token"`,
		`id="copy-token"`,
		`id="receive-token"`,
		`id="start-receive"`,
		`id="send-progress"`,
		`id="receive-progress"`,
	}
	for _, id := range demoIDs {
		if !strings.Contains(html, id) {
			t.Fatalf("web demo lost required element %s", id)
		}
	}
}

func TestBuildWebRewritesAssetCacheVersion(t *testing.T) {
	version := "cache-test-123"
	cmd := exec.Command("bash", filepath.Join("..", "tools", "packaging", "build-web.sh"))
	cmd.Env = append(os.Environ(), "DERPHOLE_WEB_ASSET_VERSION="+version)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build web artifact: %v\n%s", err, out)
	}

	htmlPath := filepath.Join("..", "dist", "web", "derphole-web", "index.html")
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read built web landing page: %v", err)
	}
	html := string(data)
	if strings.Contains(html, "?v=dev") {
		t.Fatal("built web page still contains development asset cache token")
	}
	for _, want := range []string{
		`href="styles.css?v=` + version + `"`,
		`src="wasm_exec.js?v=` + version + `"`,
		`src="wasm_payload.js?v=` + version + `"`,
		`src="webrtc.js?v=` + version + `"`,
		`src="app.js?v=` + version + `"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("built web page missing cache-busted asset reference %q", want)
		}
	}
}

func TestDerpholeWebStylesAvoidDecorativeLandingPagePatterns(t *testing.T) {
	t.Parallel()

	cssPath := filepath.Join("..", "web", "derphole", "styles.css")
	data, err := os.ReadFile(cssPath)
	if err != nil {
		t.Fatalf("read web styles: %v", err)
	}
	css := string(data)

	required := []string{
		"oklch(",
		"color-scheme: light dark",
		"--space-xs:",
		"font-variant-numeric: tabular-nums",
		"@media (prefers-color-scheme: dark)",
		"@media (prefers-reduced-motion: reduce)",
	}
	for _, want := range required {
		if !strings.Contains(css, want) {
			t.Fatalf("web styles missing %q", want)
		}
	}

	forbidden := []string{
		"background-clip: text",
		"-webkit-background-clip: text",
		"radial-gradient",
		"#fbebcd",
		"#f4ead9",
	}
	for _, bad := range forbidden {
		if strings.Contains(css, bad) {
			t.Fatalf("web styles still contain decorative pattern %q", bad)
		}
	}
}
