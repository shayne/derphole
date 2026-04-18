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
