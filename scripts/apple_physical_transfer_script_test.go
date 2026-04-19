package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplePhysicalTransferTaskUsesRuntimeTokenInjection(t *testing.T) {
	t.Parallel()

	mise := readRepoFile(t, ".mise.toml")
	script := readScriptFile(t, "apple-physical-transfer.sh")
	launchConfig := readRepoFile(t, "apple/Derphole/Derphole/LiveReceiveLaunchConfiguration.swift")
	contentView := readRepoFile(t, "apple/Derphole/Derphole/ContentView.swift")

	if !strings.Contains(mise, `[tasks."apple:physical-transfer"]`) {
		t.Fatal(".mise.toml missing apple:physical-transfer task")
	}
	if !strings.Contains(mise, `bash ./scripts/apple-physical-transfer.sh`) {
		t.Fatal("apple:physical-transfer task does not call scripts/apple-physical-transfer.sh")
	}

	info, err := os.Stat(filepath.Join(".", "apple-physical-transfer.sh"))
	if err != nil {
		t.Fatalf("stat apple-physical-transfer.sh: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("apple-physical-transfer.sh is not executable")
	}

	for _, want := range []string{
		"DERPHOLE_LIVE_RECEIVE_TOKEN",
		"DERPHOLE_LIVE_RECEIVE_FILENAME",
		"DERPHOLE_LIVE_RECEIVE_TIMEOUT",
		"DERPHOLE_LIVE_RECEIVE_AUTOSTART",
		"--derphole-live-receive-token",
		"receive ([A-Za-z0-9_-]{20,})",
		"DerpholeLiveReceivePayload.txt",
		"devicectl device copy to",
		"devicectl device process launch",
		"--environment-variables",
		"devicectl device copy from",
		`--destination "${copy_dir}/${payload_name}"`,
		"shasum -a 256",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("apple-physical-transfer.sh missing %q", want)
		}
	}

	for _, want := range []string{
		"LiveReceiveLaunchConfiguration",
		"DERPHOLE_LIVE_RECEIVE_AUTOSTART",
		"DERPHOLE_LIVE_RECEIVE_TOKEN",
	} {
		if !strings.Contains(launchConfig, want) {
			t.Fatalf("LiveReceiveLaunchConfiguration.swift missing %q", want)
		}
	}
	if !strings.Contains(contentView, "receiveRuntimeInjectedPayloadIfConfigured") {
		t.Fatal("ContentView.swift does not invoke the runtime injected receive hook")
	}

	for _, forbidden := range []string{
		"testLivePhysicalReceive" + "DirectFirst",
		strings.Join([]string{"iphone", "direct", "live"}, "-"),
	} {
		if strings.Contains(script, forbidden) || strings.Contains(launchConfig, forbidden) || strings.Contains(contentView, forbidden) {
			t.Fatalf("live transfer harness contains forbidden hardcoded test token artifact %q", forbidden)
		}
	}
}

func readScriptFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}
