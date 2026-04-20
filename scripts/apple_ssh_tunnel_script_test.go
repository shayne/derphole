package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppleSSHTunnelScriptIsWiredThroughMise(t *testing.T) {
	script := readScriptFile(t, "apple-ssh-tunnel.sh")
	mise := readRepoFile(t, ".mise.toml")

	if !strings.Contains(mise, `[tasks."apple:ssh-tunnel"]`) {
		t.Fatal(".mise.toml missing apple:ssh-tunnel task")
	}
	if !strings.Contains(mise, `bash ./scripts/apple-ssh-tunnel.sh`) {
		t.Fatal("apple:ssh-tunnel task does not call scripts/apple-ssh-tunnel.sh")
	}
	info, err := os.Stat(filepath.Join(".", "apple-ssh-tunnel.sh"))
	if err != nil {
		t.Fatalf("stat apple-ssh-tunnel.sh: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("apple-ssh-tunnel.sh is not executable")
	}

	for _, want := range []string{
		"go run ./tools/ssh-fixture",
		"derptun serve",
		"derphole://tcp",
		"DERPHOLE_LIVE_SSH_PAYLOAD",
		"DERPHOLE_LIVE_SSH_USERNAME",
		"DERPHOLE_LIVE_SSH_PASSWORD",
		"testLiveSSHTunnelPayloadOpensTerminal",
		"VVTERM_VENDOR_ROOT",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("apple-ssh-tunnel.sh missing %q", want)
		}
	}
}
