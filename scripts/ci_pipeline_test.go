// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readCIPipelineFile(t *testing.T, parts ...string) string {
	t.Helper()
	pathParts := append([]string{".."}, parts...)
	data, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(data)
}

func miseTaskBlock(t *testing.T, body, header string) string {
	t.Helper()
	start := strings.Index(body, header)
	if start < 0 {
		t.Fatalf("mise config missing task header %q", header)
	}
	rest := body[start+len(header):]
	if end := strings.Index(rest, "\n[tasks."); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func preCommitHookBlock(t *testing.T, body, id string) string {
	t.Helper()
	marker := "      - id: " + id
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("pre-commit config missing hook %q", id)
	}
	rest := body[start+len(marker):]
	if end := strings.Index(rest, "\n      - id: "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func requireCIPipelineContains(t *testing.T, name, body string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(body, value) {
			t.Fatalf("%s missing %q:\n%s", name, value, body)
		}
	}
}

func requireCIPipelineExcludes(t *testing.T, name, body string, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(body, value) {
			t.Fatalf("%s unexpectedly contains %q:\n%s", name, value, body)
		}
	}
}

func requireExactCommand(t *testing.T, name, body, command string) {
	t.Helper()
	pattern := `(^|[^[:alnum:]_:-])` + regexp.QuoteMeta(command) + `($|[^[:alnum:]_:-])`
	if !regexp.MustCompile(pattern).MatchString(body) {
		t.Fatalf("%s missing exact command %q:\n%s", name, command, body)
	}
}

func requireExactYAMLRunScalar(t *testing.T, name, body, command string) {
	t.Helper()
	want := "run: " + command
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == want {
			return
		}
	}
	t.Fatalf("%s missing exact YAML run scalar %q:\n%s", name, want, body)
}

func markdownSection(t *testing.T, body, heading string) string {
	t.Helper()
	start := strings.Index(body, heading)
	if start < 0 {
		t.Fatalf("markdown missing heading %q", heading)
	}
	rest := body[start+len(heading):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	return strings.Join(strings.Fields(strings.ToLower(rest)), " ")
}

func workflowYAMLBlock(t *testing.T, body string, indent int, name string) string {
	t.Helper()
	prefix := strings.Repeat(" ", indent)
	header := prefix + name + ":"
	lines := strings.Split(body, "\n")
	start := -1
	for i, line := range lines {
		if line == header {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("workflow missing block %q", header)
	}

	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if len(line) <= indent || !strings.HasPrefix(line, prefix) || line[indent] == ' ' {
			continue
		}
		if strings.HasSuffix(line, ":") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func workflowCheckoutBlocks(t *testing.T, name, body string) []string {
	t.Helper()
	lines := strings.Split(body, "\n")
	var blocks []string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "uses: actions/checkout@") &&
			!strings.HasPrefix(trimmed, "- uses: actions/checkout@") {
			continue
		}

		usesIndent := len(line) - len(strings.TrimLeft(line, " "))
		stepIndent := usesIndent
		start := i
		if !strings.HasPrefix(trimmed, "- ") {
			stepIndent -= 2
			for start = i - 1; start >= 0; start-- {
				candidate := lines[start]
				candidateIndent := len(candidate) - len(strings.TrimLeft(candidate, " "))
				if candidateIndent == stepIndent && strings.HasPrefix(strings.TrimSpace(candidate), "- ") {
					break
				}
			}
			if start < 0 {
				t.Fatalf("%s has checkout without a containing workflow step:\n%s", name, body)
			}
		}

		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			candidate := lines[j]
			candidateIndent := len(candidate) - len(strings.TrimLeft(candidate, " "))
			if candidateIndent == stepIndent && strings.HasPrefix(strings.TrimSpace(candidate), "- ") {
				end = j
				break
			}
		}
		blocks = append(blocks, strings.Join(lines[start:end], "\n"))
	}
	if len(blocks) == 0 {
		t.Fatalf("%s has no actions/checkout step:\n%s", name, body)
	}
	return blocks
}

func requireWorkflowCheckoutsAtEventSHA(t *testing.T, name, body string) {
	t.Helper()
	refOverride := regexp.MustCompile(`(?m)^[[:space:]]+ref[[:space:]]*:`)
	for _, checkout := range workflowCheckoutBlocks(t, name, body) {
		if refOverride.MatchString(checkout) {
			t.Fatalf("%s checkout overrides the event SHA:\n%s", name, checkout)
		}
	}
}

func TestMiseSeparatesFastAndFullCheckLanes(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".mise.toml")

	fastHooks := miseTaskBlock(t, body, `[tasks."check:fast:hooks"]`)
	requireCIPipelineContains(t, "check:fast:hooks", fastHooks,
		`pre-commit run --all-files --hook-stage pre-commit`,
	)
	requireCIPipelineExcludes(t, "check:fast:hooks", fastHooks,
		`--hook-stage manual`,
	)
	if got := strings.Count(fastHooks, "--hook-stage"); got != 1 {
		t.Fatalf("check:fast:hooks has %d hook stages, want exactly 1:\n%s", got, fastHooks)
	}

	fullHooks := miseTaskBlock(t, body, `[tasks."check:full:hooks"]`)
	requireCIPipelineContains(t, "check:full:hooks", fullHooks,
		`pre-commit run --all-files --hook-stage pre-commit`,
		`pre-commit run --all-files --hook-stage manual`,
	)

	compatibility := miseTaskBlock(t, body, `[tasks."check:hooks"]`)
	requireCIPipelineContains(t, "check:hooks", compatibility,
		`mise run check:full:hooks`,
	)
	requireCIPipelineExcludes(t, "check:hooks", compatibility,
		`mise run check:fast:hooks`,
		`pre-commit run`,
	)

	static := miseTaskBlock(t, body, `[tasks."check:static"]`)
	requireCIPipelineContains(t, "check:static", static,
		`tools/hooks/go-vet`,
		`tools/hooks/staticcheck`,
		`tools/hooks/govulncheck`,
		`tools/hooks/depaware-check`,
		`tools/hooks/depaware-deps-check`,
	)

	fast := miseTaskBlock(t, body, `[tasks."check:fast"]`)
	requireCIPipelineContains(t, "check:fast", fast,
		`mise run build`,
	)
	requireCIPipelineExcludes(t, "check:fast", fast,
		`check:fast:hooks`,
		`check:full:hooks`,
		`pre-commit`,
		`--hook-stage`,
		`quality`,
		`test`,
	)

	ciFast := miseTaskBlock(t, body, `[tasks."check:ci-fast"]`)
	requireCIPipelineContains(t, "check:ci-fast", ciFast,
		`mise run check:fast:hooks`,
		`mise run check:fast`,
	)
	requireCIPipelineExcludes(t, "check:ci-fast", ciFast,
		`check:full:hooks`,
		`--hook-stage manual`,
		`quality`,
		`test`,
	)

	full := miseTaskBlock(t, body, "[tasks.check]")
	requireCIPipelineContains(t, "check", full,
		`mise run check:full:hooks`,
		`mise run build`,
	)
	requireCIPipelineExcludes(t, "check", full,
		`mise run test`,
		`go test ./...`,
	)
}

func TestPreCommitWrapperUsesFastLane(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, "tools", "hooks", "pre-commit")

	requireCIPipelineContains(t, "tools/hooks/pre-commit", body,
		`exec mise run check:fast:hooks`,
	)
	requireCIPipelineExcludes(t, "tools/hooks/pre-commit", body,
		`mise run check:hooks`,
		`check:full:hooks`,
		`quality`,
		`test`,
	)
}

func TestPreCommitSeparatesFastAndManualHooks(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".pre-commit-config.yaml")

	fast := []string{
		"derphole-license-check",
		"derphole-gofmt-check",
		"derphole-go-mod-tidy",
		"derphole-private-info-scan",
		"derphole-depaware-deps",
	}
	heavy := []string{
		"derphole-go-vet",
		"derphole-staticcheck",
		"derphole-govulncheck",
		"derphole-quality",
		"derphole-depaware",
	}

	for _, id := range fast {
		block := preCommitHookBlock(t, body, id)
		if !strings.Contains(block, "stages: [pre-commit]") {
			t.Fatalf("fast hook %s is not in the pre-commit stage", id)
		}
	}
	for _, id := range heavy {
		block := preCommitHookBlock(t, body, id)
		if !strings.Contains(block, "stages: [manual]") {
			t.Fatalf("heavy hook %s is not in the manual stage", id)
		}
	}
}

func TestChecksWorkflowRunsIndependentLanes(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "checks.yml")

	for _, required := range []string{
		"group: checks-${{ github.workflow }}-${{ github.ref }}",
		"cancel-in-progress: true",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("checks workflow missing %q", required)
		}
	}
	jobs := map[string]string{
		"fast":     "run: mise run check:ci-fast",
		"quality":  "run: mise run quality",
		"static":   "run: mise run check:static",
		"topology": "run: mise run toposim",
	}
	for job, command := range jobs {
		block := workflowYAMLBlock(t, body, 2, job)
		requireCIPipelineContains(t, job+" job", block, command)
	}
	fastJob := workflowYAMLBlock(t, body, 2, "fast")
	requireCIPipelineExcludes(t, "fast job", fastJob,
		"run: mise run check:fast\n",
		"run: mise run check:fast:hooks",
	)
	if strings.Contains(body, "\n  checks:\n") {
		t.Fatal("checks workflow still contains the old serial checks job")
	}
	if strings.Contains(body, "run: mise run check\n") {
		t.Fatal("checks workflow still invokes the serial full local gate")
	}

	topology := workflowYAMLBlock(t, body, 2, "topology")
	for _, tool := range []string{"iproute2", "iptables", "iputils-ping"} {
		if !strings.Contains(topology, tool) {
			t.Fatalf("topology job missing %s", tool)
		}
	}
	if strings.Count(body, "Install topology tools") != strings.Count(topology, "Install topology tools") {
		t.Fatal("topology packages are installed outside the topology job")
	}
}

func TestDevReleaseRunsDirectlyFromMainPush(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "release.yml")
	requireCIPipelineExcludes(t, "release workflow", body,
		"workflow_run", "source_sha", "WORKFLOW_RUN_HEAD_SHA", "SOURCE_SHA",
	)

	trigger := workflowYAMLBlock(t, body, 0, "on")
	requireCIPipelineExcludes(t, "release trigger", trigger, "workflow_run:")
	push := workflowYAMLBlock(t, trigger, 2, "push")
	requireCIPipelineContains(t, "release push trigger", push,
		"branches:\n      - \"main\"",
		"tags:\n      - \"v*\"",
	)

	meta := workflowYAMLBlock(t, body, 2, "meta")
	requireCIPipelineContains(t, "release meta job", meta,
		`if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then is_tag=true; fi`,
		`if [ "${GITHUB_REF_NAME:-}" = "main" ]; then is_main=true; fi`,
		`short_sha="${GITHUB_SHA::7}"`,
	)
	requireCIPipelineExcludes(t, "release meta job", meta,
		"workflow_run", "source_sha", "WORKFLOW_RUN_HEAD_SHA",
	)

	releaseDev := workflowYAMLBlock(t, body, 2, "release-dev")
	requireCIPipelineContains(t, "release-dev", releaseDev,
		"needs: [meta, build-binaries, build-web, publish-npm-dev]",
		`git tag -f dev "$GITHUB_SHA"`,
	)
	requireCIPipelineExcludes(t, "release-dev", releaseDev,
		"needs: [meta, check", "SOURCE_SHA:", "source_sha",
	)

	buildBinaries := workflowYAMLBlock(t, body, 2, "build-binaries")
	requireCIPipelineContains(t, "build-binaries", buildBinaries,
		`COMMIT: ${{ github.sha }}`,
	)

	checkoutJobs := []string{
		"check",
		"build-binaries",
		"build-web",
		"build-swiftpm-framework",
		"release-prod",
		"release-dev",
		"publish-packages-prod",
		"publish-packages-dev",
		"publish-npm-prod",
		"publish-npm-dev",
	}
	for _, job := range checkoutJobs {
		block := workflowYAMLBlock(t, body, 2, job)
		requireWorkflowCheckoutsAtEventSHA(t, job, block)
	}
	for _, job := range []string{"release-prod", "release-dev"} {
		block := workflowYAMLBlock(t, body, 2, job)
		for _, checkout := range workflowCheckoutBlocks(t, job, block) {
			requireCIPipelineContains(t, job+" checkout", checkout, "fetch-depth: 0")
		}
	}
}

func TestReleaseKeepsProductionCheckAndRemovesDevDuplicate(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "release.yml")

	productionNeeds := map[string]string{
		"release-prod":          "needs: [meta, check, build-binaries, build-web, build-swiftpm-framework, publish-npm-prod]",
		"publish-packages-prod": "needs: [meta, check, build-binaries]",
		"publish-npm-prod":      "needs: [meta, check, publish-packages-prod, build-swiftpm-framework]",
	}
	for job, needs := range productionNeeds {
		block := workflowYAMLBlock(t, body, 2, job)
		requireCIPipelineContains(t, job, block, needs)
	}
	releaseProd := workflowYAMLBlock(t, body, 2, "release-prod")
	requireCIPipelineContains(t, "release-prod", releaseProd,
		"if: needs.meta.outputs.is_tag == 'true'",
	)
	check := workflowYAMLBlock(t, body, 2, "check")
	requireCIPipelineContains(t, "check", check,
		"needs: [meta]",
		"if: needs.meta.outputs.is_tag == 'true'",
	)
	requireExactYAMLRunScalar(t, "check", check, "mise run check")
	requireCIPipelineExcludes(t, "check", check,
		"run: mise run build", "run: mise run test", "run: mise run vet",
	)

	devNeeds := map[string]string{
		"release-dev":          "needs: [meta, build-binaries, build-web, publish-npm-dev]",
		"publish-packages-dev": "needs: [meta, build-binaries]",
		"publish-npm-dev":      "needs: [meta, publish-packages-dev]",
	}
	for job, needs := range devNeeds {
		block := workflowYAMLBlock(t, body, 2, job)
		requireCIPipelineContains(t, job, block, needs)
		requireCIPipelineExcludes(t, job, block,
			"needs: [check",
			"needs: [meta, check",
		)
	}
}

func TestDeveloperDocsExplainIterationCommitAndPushBoundaries(t *testing.T) {
	t.Parallel()
	readme := readCIPipelineFile(t, "README.md")
	agents := readCIPipelineFile(t, "AGENTS.md")

	sections := map[string]string{
		"README development guidance":     markdownSection(t, readme, "## Development"),
		"AGENTS version-control guidance": markdownSection(t, agents, "## Version Control"),
	}
	for name, section := range sections {
		requireExactCommand(t, name, section, "mise run check:fast")
		requireExactCommand(t, name, section, "mise run check")
		requireCIPipelineContains(t, name, section,
			"focused tests",
			"build-only",
			"checkpoint",
			"commit hook",
			"format",
			"hygiene",
			"immediately before",
			"push",
		)
	}
	if strings.Contains(agents, "Pre-commit hooks are intentionally expensive") {
		t.Fatal("AGENTS still describes checkpoint hooks as intentionally expensive")
	}
}

func TestAgentsCheckFastCommandDescriptionIsBuildOnly(t *testing.T) {
	t.Parallel()
	agents := readCIPipelineFile(t, "AGENTS.md")
	commands := markdownSection(t, agents, "## Build, Test, and Development Commands")

	requireExactCommand(t, "AGENTS build and test commands", commands, "mise run check:fast")
	requireCIPipelineContains(t, "AGENTS build and test commands", commands,
		"build-only",
		"builds every product",
		"without commit hooks",
	)
	requireCIPipelineExcludes(t, "AGENTS build and test commands", commands,
		"runs deterministic repository checks",
	)
}

func TestSupersededCIPlanPointsToThreeBoundaryPlan(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, "docs", "superpowers", "plans", "2026-07-18-ci-feedback-and-release-gating.md")
	top := body
	if len(top) > 800 {
		top = top[:800]
	}
	top = strings.ToLower(top)

	requireCIPipelineContains(t, "superseded CI plan banner", top,
		"superseded",
		"do not execute",
		"2026-07-18-three-boundary-verification.md",
		"workflow_run",
		"abandoned",
		"historical",
	)
}
