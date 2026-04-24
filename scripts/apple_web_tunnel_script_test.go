package scripts

import (
	"regexp"
	"strings"
	"testing"
)

func TestAppleWebTunnelTaskUsesRuntimePayload(t *testing.T) {
	t.Parallel()

	mise := readRepoFile(t, ".mise.toml")
	script := readScriptFile(t, "apple-web-tunnel.sh")
	launchConfig := readRepoFile(t, "apple/Derphole/Derphole/LiveWebLaunchConfiguration.swift")
	contentView := readRepoFile(t, "apple/Derphole/Derphole/ContentView.swift")
	webTabView := readRepoFile(t, "apple/Derphole/Derphole/WebTabView.swift")
	uiTests := readRepoFile(t, "apple/Derphole/DerpholeUITests/DerpholeUITests.swift")
	webView := readRepoFile(t, "apple/Derphole/Derphole/WebViewRepresentable.swift")

	if !strings.Contains(mise, `[tasks."apple:web-tunnel"]`) {
		t.Fatal(".mise.toml missing apple:web-tunnel task")
	}
	if !strings.Contains(mise, `bash ./scripts/apple-web-tunnel.sh`) {
		t.Fatal("apple:web-tunnel task does not call scripts/apple-web-tunnel.sh")
	}

	for _, want := range []string{
		"derptun serve",
		"--qr",
		"wait_for_compact_invite",
		"DERPHOLE_LIVE_WEB_PAYLOAD",
		"DERPHOLE_LIVE_WEB_MARKER",
		"Invite: (DT1[^[:space:]]+)",
		"testLiveWebTunnelPayloadLoadsFixtureMarker",
		"-only-testing:DerpholeUITests/DerpholeUITests/testLiveWebTunnelPayloadLoadsFixtureMarker",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("apple-web-tunnel.sh missing %q", want)
		}
	}

	for _, want := range []string{
		"LiveWebLaunchConfiguration",
		"DERPHOLE_LIVE_WEB_PAYLOAD",
		"--derphole-live-web-payload",
	} {
		if !strings.Contains(launchConfig, want) {
			t.Fatalf("LiveWebLaunchConfiguration.swift missing %q", want)
		}
	}
	if !strings.Contains(contentView, "selectedTab") || !strings.Contains(contentView, "LiveAppLaunchConfiguration") {
		t.Fatal("ContentView.swift does not select the Web tab for a live web launch payload")
	}
	if !strings.Contains(webTabView, "openRuntimeInjectedPayloadIfConfigured") {
		t.Fatal("WebTabView.swift does not invoke the runtime injected web payload hook")
	}
	if !strings.Contains(uiTests, "testLiveWebTunnelPayloadLoadsFixtureMarker") ||
		!strings.Contains(uiTests, "DERPHOLE_LIVE_WEB_PAYLOAD") ||
		!strings.Contains(uiTests, "DERPHOLE_LIVE_WEB_MARKER") ||
		!strings.Contains(uiTests, "webBrowserView") {
		t.Fatal("DerpholeUITests.swift missing live web tunnel marker verification")
	}
	if !strings.Contains(webView, "WKWebView") {
		t.Fatal("WebViewRepresentable.swift does not provide the WKWebView under test")
	}

	generatedToken := regexp.MustCompile(`\b(?:dtc1|dts1)_[A-Za-z0-9_-]{20,}\b`)
	for name, contents := range map[string]string{
		"apple-web-tunnel.sh":              script,
		"LiveWebLaunchConfiguration.swift": launchConfig,
		"ContentView.swift":                contentView,
		"WebTabView.swift":                 webTabView,
		"DerpholeUITests.swift":            uiTests,
	} {
		if generatedToken.MatchString(contents) {
			t.Fatalf("%s contains a hardcoded generated derptun token", name)
		}
	}
}
