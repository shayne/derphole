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
		"bash ./tools/packaging/publish-npm-if-missing.sh --tag dev --skip-unclaimed ./dist/npm-derphole",
		"bash ./tools/packaging/publish-npm-if-missing.sh --tag dev --skip-unclaimed ./dist/npm-derptun",
	}
	for _, command := range commands {
		if !strings.Contains(body, command) {
			t.Fatalf("release workflow does not tolerate npm bootstrap state with command %q", command)
		}
	}
}
