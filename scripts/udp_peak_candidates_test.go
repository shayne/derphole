// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/udpbenchproof"
)

var udpPeakCandidateIDs = []string{
	"coalesced-gso3",
	"connected-gso3",
	"combined-gso1",
	"combined-gso2",
	"combined-gso3",
	"combined-gso4",
	"combined-gso6",
	"combined-gso8",
	"combined-gso12",
	"quic-control",
}

type udpPeakCandidateRegistry struct {
	SchemaVersion  int                     `json:"schema_version"`
	ControlID      string                  `json:"control_id"`
	SourceRevision string                  `json:"source_revision"`
	Candidates     []udpPeakCandidateEntry `json:"candidates"`
}

type udpPeakCandidateEntry struct {
	ID                   string                 `json:"id"`
	Commit               string                 `json:"commit"`
	LinkerValue          string                 `json:"linker_value"`
	ConfigurationProfile string                 `json:"configuration_profile"`
	Engine               string                 `json:"engine"`
	GSOSegments          int                    `json:"gso_segments_per_message"`
	Config               map[string]string      `json:"config"`
	Darwin               udpPeakCandidateBinary `json:"darwin"`
	Linux                udpPeakCandidateBinary `json:"linux"`
}

type udpPeakCandidateBinary struct {
	Platform         string `json:"platform"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	GoVersion        string `json:"go_version"`
	VCSRevision      string `json:"vcs_revision"`
	VCSModified      bool   `json:"vcs_modified"`
	ModulePath       string `json:"module_path"`
	ModuleVersion    string `json:"module_version"`
	CommandPath      string `json:"command_path"`
	GOOS             string `json:"goos"`
	GOARCH           string `json:"goarch"`
	BuildInfoSHA256  string `json:"build_info_sha256"`
	ConfiguredLinker string `json:"configured_linker_value"`
	SelectorState    string `json:"selector_state"`
}

func TestUDPPeakCandidatesShellContract(t *testing.T) {
	t.Parallel()

	body := readUDPPeakCandidateScript(t)
	required := []string{
		`--root`,
		`--control-local`,
		`--control-linux`,
		`--revision`,
		`candidates=(coalesced-gso3 connected-gso3 combined-gso1 combined-gso2 combined-gso3 combined-gso4 combined-gso6 combined-gso8 combined-gso12 quic-control)`,
		`-trimpath`,
		`-buildvcs=true`,
		`-ldflags`,
		`-X github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate=${candidate}`,
		`GOOS=darwin`,
		`GOARCH=arm64`,
		`GOOS=linux`,
		`GOARCH=amd64`,
		`CGO_ENABLED=0`,
		`GOENV=off`,
		`GOTOOLCHAIN=local`,
		`GOWORK=off`,
		`GOFIPS140=off`,
		`vcs.modified`,
		`github.com/shayne/derphole/cmd/derphole`,
		`github.com/shayne/derphole`,
		`go tool nm`,
		`os.fsencode`,
		`registry_sha256=`,
		`sha256`,
		`json.dump`,
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Errorf("udp-peak-candidates.sh missing %q", want)
		}
	}

	forbidden := []string{
		"git checkout",
		"git switch",
		"git reset",
		"git clean",
		"apt-get",
		"apt install",
		"brew install",
		"mise install",
		"sysctl",
		"sudo ",
	}
	for _, reject := range forbidden {
		if strings.Contains(body, reject) {
			t.Errorf("udp-peak-candidates.sh contains forbidden mutation command %q", reject)
		}
	}
	if strings.Contains(body, `--candidate`) {
		t.Error("udp-peak-candidates.sh exposes a subset registry mode")
	}
}

func TestUDPPeakCandidatesRequiresExplicitInputs(t *testing.T) {
	t.Parallel()

	command := exec.Command("bash", "./udp-peak-candidates.sh")
	if err := command.Run(); err == nil {
		t.Fatal("candidate builder accepted missing explicit inputs")
	}
}

func TestUDPPeakCandidatesRejectsAmbientBuildDrift(t *testing.T) {
	t.Parallel()

	for _, variable := range []string{"GOFLAGS", "GOEXPERIMENT", "GOOS", "GOARCH", "CGO_ENABLED", "GOAMD64", "GOARM64", "GOTOOLCHAIN", "GOWORK", "GOFIPS140"} {
		t.Run(variable, func(t *testing.T) {
			revision := strings.Repeat("a", 40)
			toolDir := installFakeUDPPeakGo(t)
			controlLocal, controlLinux := writeFakeUDPPeakControls(t, revision)
			root := filepath.Join(t.TempDir(), "candidate-root")
			command := udpPeakCandidateBuilderCommand(root, controlLocal, controlLinux, revision)
			command.Env = fakeUDPPeakEnvironment(toolDir, revision, variable+"=ambient-drift")
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), variable+" must be unset") {
				t.Fatalf("builder with %s returned %v\n%s", variable, err, output)
			}
			if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
				t.Fatalf("failed builder published root: %v", statErr)
			}
		})
	}
}

func TestUDPPeakCandidatesRejectsDanglingSymlinks(t *testing.T) {
	t.Parallel()

	revision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, revision)
	dangling := filepath.Join(t.TempDir(), "dangling-control")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "candidate-root")
	command := udpPeakCandidateBuilderCommand(root, dangling, controlLinux, revision)
	command.Env = fakeUDPPeakEnvironment(toolDir, revision)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "control-local must be a non-symlink executable file") {
		t.Fatalf("dangling control returned %v\n%s", err, output)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("failed builder published root: %v", statErr)
	}

	danglingRoot := filepath.Join(t.TempDir(), "dangling-root")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), danglingRoot); err != nil {
		t.Fatal(err)
	}
	command = udpPeakCandidateBuilderCommand(danglingRoot, controlLocal, controlLinux, revision)
	command.Env = fakeUDPPeakEnvironment(toolDir, revision)
	output, err = command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "candidate output root already exists") {
		t.Fatalf("dangling output root returned %v\n%s", err, output)
	}
}

func TestUDPPeakCandidatesRejectsDirtyOrWrongControlMetadata(t *testing.T) {
	t.Parallel()

	revision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	for _, test := range []struct {
		name        string
		localBody   string
		linuxBody   string
		wantMessage string
	}{
		{
			name:        "dirty",
			localBody:   fakeUDPPeakBinaryBody("darwin", "arm64", revision, "true", ""),
			linuxBody:   fakeUDPPeakBinaryBody("linux", "amd64", revision, "false", ""),
			wantMessage: "vcs.modified=true, want false",
		},
		{
			name:        "wrong platform",
			localBody:   fakeUDPPeakBinaryBody("linux", "amd64", revision, "false", ""),
			linuxBody:   fakeUDPPeakBinaryBody("linux", "amd64", revision, "false", ""),
			wantMessage: "GOOS=linux, want darwin",
		},
		{
			name:        "configured override",
			localBody:   fakeUDPPeakBinaryBody("darwin", "arm64", revision, "false", "combined-gso8"),
			linuxBody:   fakeUDPPeakBinaryBody("linux", "amd64", revision, "false", ""),
			wantMessage: "configured linker value",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := filepath.Join(t.TempDir(), "control-darwin")
			linux := filepath.Join(t.TempDir(), "control-linux")
			mustWriteExecutable(t, local, test.localBody)
			mustWriteExecutable(t, linux, test.linuxBody)
			root := filepath.Join(t.TempDir(), "candidate-root")
			command := udpPeakCandidateBuilderCommand(root, local, linux, revision)
			command.Env = fakeUDPPeakEnvironment(toolDir, revision)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.wantMessage) {
				t.Fatalf("builder returned %v\n%s", err, output)
			}
			if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
				t.Fatalf("failed builder published root: %v", statErr)
			}
		})
	}
}

func TestUDPPeakCandidatesUsesIndependentMatchingControlRevision(t *testing.T) {
	t.Parallel()
	sourceRevision := strings.Repeat("a", 40)
	controlRevision := strings.Repeat("b", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, controlRevision)
	root := filepath.Join(t.TempDir(), "candidate-root")
	registry := runUDPPeakCandidateBuilder(t, toolDir, root, controlLocal, controlLinux, sourceRevision)
	control := registry.Candidates[0]
	if registry.SourceRevision != sourceRevision || control.Commit != controlRevision {
		t.Fatalf("source/control revisions = %q/%q, want %q/%q", registry.SourceRevision, control.Commit, sourceRevision, controlRevision)
	}
	if control.ConfigurationProfile != "frozen-bulk-gso3" || control.Darwin.SelectorState != "empty" || control.Linux.SelectorState != "empty" {
		t.Fatalf("control production configuration was not explicitly bound: %#v", control)
	}
}

func TestUDPPeakCandidatesAcceptsLegacyControlWithoutSelectorSymbol(t *testing.T) {
	t.Parallel()
	sourceRevision := strings.Repeat("a", 40)
	controlRevision := strings.Repeat("b", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, controlRevision)
	root := filepath.Join(t.TempDir(), "candidate-root")
	registry := runUDPPeakCandidateBuilder(t, toolDir, root, controlLocal, controlLinux, sourceRevision, "FAKE_LEGACY_CONTROL_SELECTOR_ABSENT=1")
	control := registry.Candidates[0]
	if control.ConfigurationProfile != "frozen-bulk-gso3" || control.Darwin.SelectorState != "absent" || control.Linux.SelectorState != "absent" {
		t.Fatalf("legacy control configuration was not bound without selector symbol: %#v", control)
	}
}

func TestUDPPeakCandidatesRejectsMismatchedControlRevisions(t *testing.T) {
	t.Parallel()
	sourceRevision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal := filepath.Join(t.TempDir(), "control-darwin")
	controlLinux := filepath.Join(t.TempDir(), "control-linux")
	mustWriteExecutable(t, controlLocal, fakeUDPPeakBinaryBody("darwin", "arm64", strings.Repeat("b", 40), "false", ""))
	mustWriteExecutable(t, controlLinux, fakeUDPPeakBinaryBody("linux", "amd64", strings.Repeat("c", 40), "false", ""))
	root := filepath.Join(t.TempDir(), "candidate-root")
	command := udpPeakCandidateBuilderCommand(root, controlLocal, controlLinux, sourceRevision)
	command.Env = fakeUDPPeakEnvironment(toolDir, sourceRevision)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "frozen control pair revisions do not match") {
		t.Fatalf("mismatched controls returned %v\n%s", err, output)
	}
}

func TestUDPPeakCandidatesResolvesSymlinkedOutputAncestor(t *testing.T) {
	t.Parallel()
	revision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, revision)
	realParent := t.TempDir()
	symlinkParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(symlinkParent, "candidate-root")
	registry := runUDPPeakCandidateBuilder(t, toolDir, root, controlLocal, controlLinux, revision)
	if registry.SourceRevision != revision {
		t.Fatalf("registry through resolved ancestor has source revision %q", registry.SourceRevision)
	}
	if _, err := os.Stat(filepath.Join(realParent, "candidate-root", "candidates.json")); err != nil {
		t.Fatalf("registry was not published into resolved parent: %v", err)
	}
}

func TestUDPPeakCandidatesRejectsDirtyBuiltCandidate(t *testing.T) {
	t.Parallel()
	revision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, revision)
	root := filepath.Join(t.TempDir(), "candidate-root")
	command := udpPeakCandidateBuilderCommand(root, controlLocal, controlLinux, revision)
	command.Env = fakeUDPPeakEnvironment(toolDir, revision, "FAKE_BUILD_MODIFIED=true")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "vcs.modified=true, want false") {
		t.Fatalf("dirty built candidate returned %v\n%s", err, output)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("failed builder published root: %v", statErr)
	}
}

func TestUDPPeakCandidatesCopiesControlsBeforeVerification(t *testing.T) {
	t.Parallel()
	revision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, revision)
	original := []byte(fakeUDPPeakBinaryBody("darwin", "arm64", revision, "false", ""))
	root := filepath.Join(t.TempDir(), "candidate-root")
	marker := filepath.Join(t.TempDir(), "replacement-fired")
	registry := runUDPPeakCandidateBuilder(t, toolDir, root, controlLocal, controlLinux, revision,
		"FAKE_REPLACE_CONTROL="+controlLocal, "FAKE_REPLACE_MARKER="+marker)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control replacement hook did not run: %v", err)
	}
	assertFileBytes(t, filepath.Join(root, registry.Candidates[0].Darwin.Path), original)
	if bytes.Equal(mustReadFile(t, controlLocal), original) {
		t.Fatal("source control was not replaced after staged verification began")
	}
}

func TestUDPPeakCandidatesBuildsHashedReproducibleRegistry(t *testing.T) {
	t.Parallel()

	revision := strings.Repeat("a", 40)
	toolDir := installFakeUDPPeakGo(t)
	controlLocal, controlLinux := writeFakeUDPPeakControls(t, revision)

	rootA := filepath.Join(t.TempDir(), "candidate-root")
	rootB := filepath.Join(t.TempDir(), "candidate-root")
	registryA := runUDPPeakCandidateBuilder(t, toolDir, rootA, controlLocal, controlLinux, revision)
	registryB := runUDPPeakCandidateBuilder(t, toolDir, rootB, controlLocal, controlLinux, revision)

	wantIDs := append([]string{"frozen-control"}, udpPeakCandidateIDs...)
	if registryA.SchemaVersion != 1 || registryA.ControlID != "frozen-control" || registryA.SourceRevision != revision {
		t.Fatalf("registry identity = %#v", registryA)
	}
	if len(registryA.Candidates) != len(wantIDs) {
		t.Fatalf("candidate count = %d, want %d", len(registryA.Candidates), len(wantIDs))
	}

	for index, entry := range registryA.Candidates {
		if entry.ID != wantIDs[index] {
			t.Fatalf("candidate %d ID = %q, want %q", index, entry.ID, wantIDs[index])
		}
		if entry.Config["candidate"] != entry.ID || len(entry.Config) != 1 {
			t.Fatalf("candidate %q manifest config = %#v", entry.ID, entry.Config)
		}
		if entry.Darwin.Platform != "darwin-arm64" || entry.Linux.Platform != "linux-amd64" {
			t.Fatalf("candidate %q platforms = %q, %q", entry.ID, entry.Darwin.Platform, entry.Linux.Platform)
		}
		if entry.Darwin.VCSRevision != entry.Commit || entry.Linux.VCSRevision != entry.Commit {
			t.Fatalf("candidate %q revisions do not bind commit %#v", entry.ID, entry)
		}
		assertUDPPeakBinaryIdentity(t, entry, entry.Darwin, "darwin", "arm64")
		assertUDPPeakBinaryIdentity(t, entry, entry.Linux, "linux", "amd64")
		assertUDPPeakBinaryDigest(t, rootA, entry.Darwin)
		assertUDPPeakBinaryDigest(t, rootA, entry.Linux)

		other := registryB.Candidates[index]
		if entry.Darwin.SHA256 != other.Darwin.SHA256 || entry.Linux.SHA256 != other.Linux.SHA256 {
			t.Fatalf("candidate %q was not reproducible: A=(%s,%s) B=(%s,%s)", entry.ID, entry.Darwin.SHA256, entry.Linux.SHA256, other.Darwin.SHA256, other.Linux.SHA256)
		}
		if entry.Darwin.BuildInfoSHA256 != other.Darwin.BuildInfoSHA256 || entry.Linux.BuildInfoSHA256 != other.Linux.BuildInfoSHA256 {
			t.Fatalf("candidate %q build metadata was not reproducible", entry.ID)
		}
	}

	if got := registryA.Candidates[0]; got.LinkerValue != "" || got.ConfigurationProfile != "frozen-bulk-gso3" || got.Engine != "bulk-packets-v1" || got.GSOSegments != 3 {
		t.Fatalf("frozen control metadata = %#v", got)
	}
	for _, entry := range registryA.Candidates[1:] {
		wantEngine, wantGSO := udpPeakCandidateEngineAndGSO(entry.ID)
		if entry.LinkerValue != entry.ID || entry.ConfigurationProfile != "benchmark-linker" || entry.Engine != wantEngine || entry.GSOSegments != wantGSO {
			t.Fatalf("candidate %q metadata = linker %q engine %q gso %d; want %q %q %d", entry.ID, entry.LinkerValue, entry.Engine, entry.GSOSegments, entry.ID, wantEngine, wantGSO)
		}
	}

	assertFileBytes(t, filepath.Join(rootA, registryA.Candidates[0].Darwin.Path), []byte(fakeUDPPeakBinaryBody("darwin", "arm64", revision, "false", "")))
	assertFileBytes(t, filepath.Join(rootA, registryA.Candidates[0].Linux.Path), []byte(fakeUDPPeakBinaryBody("linux", "amd64", revision, "false", "")))
	validateUDPPeakRegistryManifestBoundary(t, registryA)
	entries, err := os.ReadDir(rootA)
	if err != nil {
		t.Fatal(err)
	}
	gotEntries := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotEntries = append(gotEntries, entry.Name())
	}
	if !reflect.DeepEqual(gotEntries, []string{"bin", "candidates.json"}) {
		t.Fatalf("published root contains scratch artifacts: %v", gotEntries)
	}

	command := udpPeakCandidateBuilderCommand(rootA, controlLocal, controlLinux, revision)
	command.Env = fakeUDPPeakEnvironment(toolDir, revision)
	if err := command.Run(); err == nil {
		t.Fatal("candidate builder overwrote an existing immutable registry")
	}
}

func TestUDPPeakCandidatesRealBuildIsReproducible(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("real cross-platform candidate-pair reproducibility check runs on the canonical Darwin arm64 builder")
	}
	if testing.Short() {
		t.Skip("real candidate-pair reproducibility check is intentionally excluded from short tests")
	}

	repo := makeCleanUDPPeakSourceTree(t)
	revision := gitOutput(t, repo, "rev-parse", "HEAD")
	controlLocal := filepath.Join(t.TempDir(), "control-darwin")
	controlLinux := filepath.Join(t.TempDir(), "control-linux")
	buildRealUDPPeakBinary(t, repo, controlLocal, "darwin", "arm64", "")
	buildRealUDPPeakBinary(t, repo, controlLinux, "linux", "amd64", "")

	rootA := filepath.Join(t.TempDir(), "candidate-root-a")
	rootB := filepath.Join(t.TempDir(), "candidate-root-b")
	registryA := runRealUDPPeakCandidateBuilder(t, repo, rootA, controlLocal, controlLinux, revision)
	registryB := runRealUDPPeakCandidateBuilder(t, repo, rootB, controlLocal, controlLinux, revision)
	if len(registryA.Candidates) != 11 || len(registryB.Candidates) != 11 {
		t.Fatalf("real registry sizes = %d, %d; want exact frozen control plus ten candidates", len(registryA.Candidates), len(registryB.Candidates))
	}
	for index, first := range registryA.Candidates {
		second := registryB.Candidates[index]
		if first.ID != second.ID || first.Darwin.SHA256 != second.Darwin.SHA256 || first.Linux.SHA256 != second.Linux.SHA256 {
			t.Fatalf("real production-path candidate pair %q is not reproducible: %#v vs %#v", first.ID, first, second)
		}
	}
}

func validateUDPPeakRegistryManifestBoundary(t *testing.T, registry udpPeakCandidateRegistry) {
	t.Helper()
	fixturePath := filepath.Join("..", "pkg", "udpbenchproof", "testdata", "manifest-valid.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture udpbenchproof.Manifest
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	input := fixture.ManifestInput
	input.Candidates = make([]udpbenchproof.CandidateIdentity, 0, len(registry.Candidates))
	for _, entry := range registry.Candidates {
		input.Candidates = append(input.Candidates, udpPeakManifestCandidate(entry))
	}
	input.ScreeningControlID = registry.ControlID
	input.Schedules = udpPeakRegistrySchedules(input, registry.Candidates)
	manifest, err := udpbenchproof.NewManifest(input)
	if err != nil {
		t.Fatalf("registry identities do not satisfy the manifest boundary: %v", err)
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	digest, err := udpbenchproof.WriteImmutableJSON(manifestPath, manifest)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "run", "./tools/udppeak", "validate", "-manifest", manifestPath, "-sha256", string(digest))
	command.Dir = ".."
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("udppeak validate rejected registry-derived manifest: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != string(digest) {
		t.Fatalf("udppeak validate output = %q, want %q", strings.TrimSpace(string(output)), digest)
	}
}

func udpPeakManifestCandidate(entry udpPeakCandidateEntry) udpbenchproof.CandidateIdentity {
	return udpbenchproof.CandidateIdentity{
		ID:     entry.ID,
		Commit: entry.Commit,
		Darwin: udpbenchproof.BinaryIdentity{
			Platform:    entry.Darwin.Platform,
			SHA256:      udpbenchproof.SHA256Digest(entry.Darwin.SHA256),
			VCSRevision: entry.Darwin.VCSRevision,
		},
		Linux: udpbenchproof.BinaryIdentity{
			Platform:    entry.Linux.Platform,
			SHA256:      udpbenchproof.SHA256Digest(entry.Linux.SHA256),
			VCSRevision: entry.Linux.VCSRevision,
		},
		Config: map[string]string{"candidate": entry.ID},
	}
}

func readUDPPeakCandidateScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", "udp-peak-candidates.sh"))
	if err != nil {
		t.Fatalf("read udp-peak-candidates.sh: %v", err)
	}
	return string(data)
}

func installFakeUDPPeakGo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  build)
    shift
    output=""
    linker=""
    while (( $# > 0 )); do
      case "$1" in
        -o) output="$2"; shift 2 ;;
        -ldflags) linker="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    [[ -n "$output" && -n "$linker" ]]
	 candidate="${linker##*=}"
	 modified="${FAKE_BUILD_MODIFIED:-false}"
	 printf 'fake-go-binary goos=%s goarch=%s revision=%s modified=%s candidate=%s\n' "${GOOS:?}" "${GOARCH:?}" "${FAKE_REVISION:?}" "$modified" "$candidate" >"$output"
	 if [[ -n "$candidate" ]]; then
	   printf '%s\0' "$candidate" >>"$output"
	 fi
    chmod 0755 "$output"
    ;;
  version)
    [[ "${2:-}" == "-m" && -n "${3:-}" ]]
	 read -r _ goos_field goarch_field revision_field modified_field candidate_field <"$3"
	 if [[ -n "${FAKE_REPLACE_CONTROL:-}" && -n "${FAKE_REPLACE_MARKER:-}" && ! -e "$FAKE_REPLACE_MARKER" ]]; then
	   printf 'replaced-after-copy\n' >"$FAKE_REPLACE_CONTROL"
	   : >"$FAKE_REPLACE_MARKER"
	 fi
	 goos="${goos_field#goos=}"
	 goarch="${goarch_field#goarch=}"
	 revision="${revision_field#revision=}"
	 modified="${modified_field#modified=}"
	 printf '%s: go1.26.5\n' "$3"
	 printf '\tpath\tgithub.com/shayne/derphole/cmd/derphole\n'
	 printf '\tmod\tgithub.com/shayne/derphole\tv0.0.0\n'
	 printf '\tbuild\t-buildmode=exe\n'
	 printf '\tbuild\t-compiler=gc\n'
	 printf '\tbuild\t-trimpath=true\n'
	 printf '\tbuild\tCGO_ENABLED=0\n'
	 printf '\tbuild\tGOARCH=%s\n' "$goarch"
	 printf '\tbuild\tGOOS=%s\n' "$goos"
	 if [[ "$goos" == "darwin" ]]; then
	   printf '\tbuild\tGOARM64=v8.0\n'
	 else
	   printf '\tbuild\tGOAMD64=v1\n'
	 fi
	 printf '\tbuild\tvcs=git\n'
	 printf '\tbuild\tvcs.revision=%s\n' "$revision"
	 printf '\tbuild\tvcs.modified=%s\n' "$modified"
	 ;;
	tool)
	 [[ "${2:-}" == "nm" && "${3:-}" == "-size" && -n "${4:-}" ]]
	 read -r _ _ _ _ _ candidate_field <"$4"
	 candidate="${candidate_field#candidate=}"
	 if [[ -z "$candidate" ]]; then
	   if [[ -z "${FAKE_LEGACY_CONTROL_SELECTOR_ABSENT:-}" ]]; then
	     printf '1000 16 B github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate\n'
	     printf '3000 0 R udppeak.config.source-default\n'
	   else
	     printf '4000 8 D github.com/shayne/derphole/pkg/session.someLegacySymbol\n'
	   fi
	 else
	   printf '1000 16 D github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate\n'
	   printf '2000 192 R github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate.str\n'
	   printf '3000 %d R udppeak.config.%s\n' "${#candidate}" "$candidate"
	 fi
    ;;
  *)
    printf 'unexpected fake go invocation: %s\n' "$*" >&2
    exit 91
    ;;
esac
`
	path := filepath.Join(dir, "go")
	mustWriteExecutable(t, path, script)
	return dir
}

func runUDPPeakCandidateBuilder(t *testing.T, toolDir, root, controlLocal, controlLinux, revision string, extraEnvironment ...string) udpPeakCandidateRegistry {
	t.Helper()
	command := udpPeakCandidateBuilderCommand(root, controlLocal, controlLinux, revision)
	command.Env = fakeUDPPeakEnvironment(toolDir, revision, extraEnvironment...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("candidate builder: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	physicalParent, err := filepath.EvalSymlinks(filepath.Dir(root))
	if err != nil {
		t.Fatal(err)
	}
	wantRegistryPath := filepath.Join(physicalParent, filepath.Base(root), "candidates.json")
	if len(lines) != 2 || lines[0] != "registry_path="+wantRegistryPath || !strings.HasPrefix(lines[1], "registry_sha256=") || len(strings.TrimPrefix(lines[1], "registry_sha256=")) != 64 {
		t.Fatalf("candidate builder output = %q", output)
	}
	data, err := os.ReadFile(filepath.Join(root, "candidates.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantRegistryDigest := strings.TrimPrefix(lines[1], "registry_sha256=")
	registryDigest := sha256.Sum256(data)
	if got := hex.EncodeToString(registryDigest[:]); got != wantRegistryDigest {
		t.Fatalf("emitted registry SHA-256 = %s, want exact %s", wantRegistryDigest, got)
	}
	var registry udpPeakCandidateRegistry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		t.Fatalf("decode registry: %v\n%s", err, data)
	}
	return registry
}

func udpPeakCandidateBuilderCommand(root, controlLocal, controlLinux, revision string, extra ...string) *exec.Cmd {
	arguments := []string{
		"./udp-peak-candidates.sh",
		"--root", root,
		"--control-local", controlLocal,
		"--control-linux", controlLinux,
		"--revision", revision,
	}
	arguments = append(arguments, extra...)
	return exec.Command("bash", arguments...)
}

func fakeUDPPeakEnvironment(toolDir, revision string, extra ...string) []string {
	rejected := map[string]bool{
		"GOFLAGS": true, "GOEXPERIMENT": true, "GOOS": true, "GOARCH": true,
		"CGO_ENABLED": true, "GOAMD64": true, "GOARM64": true,
		"GOTOOLCHAIN": true, "GOWORK": true, "GOFIPS140": true,
	}
	environment := make([]string, 0, len(os.Environ())+len(extra)+2)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if !rejected[name] && name != "PATH" && name != "FAKE_REVISION" {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"), "FAKE_REVISION="+revision)
	return append(environment, extra...)
}

func writeFakeUDPPeakControls(t *testing.T, revision string) (string, string) {
	t.Helper()
	local := filepath.Join(t.TempDir(), "control-darwin")
	linux := filepath.Join(t.TempDir(), "control-linux")
	mustWriteExecutable(t, local, fakeUDPPeakBinaryBody("darwin", "arm64", revision, "false", ""))
	mustWriteExecutable(t, linux, fakeUDPPeakBinaryBody("linux", "amd64", revision, "false", ""))
	return local, linux
}

func fakeUDPPeakBinaryBody(goos, goarch, revision, modified, candidate string) string {
	return fmt.Sprintf("fake-go-binary goos=%s goarch=%s revision=%s modified=%s candidate=%s\n", goos, goarch, revision, modified, candidate)
}

func assertUDPPeakBinaryIdentity(t *testing.T, entry udpPeakCandidateEntry, binary udpPeakCandidateBinary, goos, goarch string) {
	t.Helper()
	if binary.ModulePath != "github.com/shayne/derphole" || binary.CommandPath != "github.com/shayne/derphole/cmd/derphole" {
		t.Fatalf("candidate %q module identity = %q / %q", entry.ID, binary.ModulePath, binary.CommandPath)
	}
	if binary.GOOS != goos || binary.GOARCH != goarch || binary.VCSModified {
		t.Fatalf("candidate %q build identity = %s/%s modified=%t", entry.ID, binary.GOOS, binary.GOARCH, binary.VCSModified)
	}
	if len(binary.BuildInfoSHA256) != 64 {
		t.Fatalf("candidate %q build-info digest = %q", entry.ID, binary.BuildInfoSHA256)
	}
	wantLinker := entry.LinkerValue
	if binary.ConfiguredLinker != wantLinker {
		t.Fatalf("candidate %q configured linker value = %q, want %q", entry.ID, binary.ConfiguredLinker, wantLinker)
	}
	wantProfile := "benchmark-linker"
	wantSelector := "linked"
	if entry.ID == "frozen-control" {
		wantProfile = "frozen-bulk-gso3"
		wantSelector = "empty"
	}
	if entry.ConfigurationProfile != wantProfile || binary.SelectorState != wantSelector {
		t.Fatalf("candidate %q configuration profile/state = %q/%q, want %q/%q", entry.ID, entry.ConfigurationProfile, binary.SelectorState, wantProfile, wantSelector)
	}
}

func udpPeakRegistrySchedules(input udpbenchproof.ManifestInput, entries []udpPeakCandidateEntry) []udpbenchproof.FrozenSchedule {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	primary := ""
	for _, host := range input.FleetInventory {
		if host.Role == udpbenchproof.HostRolePrimary {
			primary = host.ID
			break
		}
	}
	screening := udpbenchproof.FrozenSchedule{Stage: "screening", Repetitions: 1}
	for block, candidate := range ids {
		for offset, row := range []struct{ candidate, role string }{
			{input.ScreeningControlID, "control-before"},
			{candidate, "candidate"},
			{input.ScreeningControlID, "control-after"},
		} {
			screening.RunIDs = append(screening.RunIDs, fmt.Sprintf("screen-%02d-%d", block, offset))
			screening.CandidateOrder = append(screening.CandidateOrder, row.candidate)
			screening.HostOrder = append(screening.HostOrder, primary)
			screening.DirectionOrder = append(screening.DirectionOrder, "hetz-to-mac")
			screening.BlockOrder = append(screening.BlockOrder, block)
			screening.RunRoles = append(screening.RunRoles, row.role)
		}
	}
	return []udpbenchproof.FrozenSchedule{
		screening,
		udpPeakBalancedSchedule("preliminary", ids, primary, 3),
		udpPeakBalancedSchedule("finalist", ids, primary, 3),
		udpPeakBalancedSchedule("finalist-rerun", ids, primary, 6),
	}
}

func udpPeakBalancedSchedule(stage string, candidateIDs []string, host string, repetitions int) udpbenchproof.FrozenSchedule {
	ids := append([]string(nil), candidateIDs...)
	sort.Strings(ids)
	rotations := make([][]string, 3)
	for block := range rotations {
		rotation := make([]string, len(ids))
		for index := range ids {
			rotation[index] = ids[(index+block)%len(ids)]
		}
		rotations[block] = rotation
	}
	schedule := udpbenchproof.FrozenSchedule{Stage: stage, Repetitions: repetitions}
	row := 0
	for _, direction := range []string{"hetz-to-mac", "mac-to-hetz"} {
		for repetition := range repetitions {
			for _, candidate := range rotations[repetition%len(rotations)] {
				schedule.RunIDs = append(schedule.RunIDs, fmt.Sprintf("%s-%04d", stage, row))
				schedule.CandidateOrder = append(schedule.CandidateOrder, candidate)
				schedule.HostOrder = append(schedule.HostOrder, host)
				schedule.DirectionOrder = append(schedule.DirectionOrder, direction)
				schedule.BlockOrder = append(schedule.BlockOrder, repetition)
				schedule.RunRoles = append(schedule.RunRoles, "file")
				row++
			}
		}
	}
	return schedule
}

func makeCleanUDPPeakSourceTree(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	archiveCommand := exec.Command("git", "archive", "--format=tar", "HEAD")
	archiveCommand.Dir = ".."
	archive, err := archiveCommand.Output()
	if err != nil {
		t.Fatalf("archive repository: %v", err)
	}
	extract := exec.Command("tar", "-xf", "-", "-C", repo)
	extract.Stdin = bytes.NewReader(archive)
	if output, err := extract.CombinedOutput(); err != nil {
		t.Fatalf("extract repository: %v\n%s", err, output)
	}
	script, err := os.ReadFile("./udp-peak-candidates.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "scripts", "udp-peak-candidates.sh"), script, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q")
	gitRun(t, repo, "config", "user.name", "UDP peak test")
	gitRun(t, repo, "config", "user.email", "udp-peak-test@example.invalid")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-q", "-m", "test: freeze candidate source")
	return repo
}

func buildRealUDPPeakBinary(t *testing.T, repo, output, goos, goarch, candidate string) {
	t.Helper()
	arguments := []string{"build", "-trimpath", "-buildvcs=true"}
	if candidate != "" {
		arguments = append(arguments, "-ldflags", "-X github.com/shayne/derphole/pkg/session.externalV2BulkPacketBenchmarkCandidate="+candidate)
	}
	arguments = append(arguments, "-o", output, "./cmd/derphole")
	command := exec.Command("go", arguments...)
	command.Dir = repo
	command.Env = cleanRealUDPPeakEnvironment(goos, goarch)
	if outputBytes, err := command.CombinedOutput(); err != nil {
		t.Fatalf("real %s/%s build: %v\n%s", goos, goarch, err, outputBytes)
	}
}

func runRealUDPPeakCandidateBuilder(t *testing.T, repo, root, controlLocal, controlLinux, revision string) udpPeakCandidateRegistry {
	t.Helper()
	command := exec.Command("bash", "./scripts/udp-peak-candidates.sh",
		"--root", root,
		"--control-local", controlLocal,
		"--control-linux", controlLinux,
		"--revision", revision,
	)
	command.Dir = repo
	command.Env = cleanRealUDPPeakEnvironment("", "")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real candidate builder: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(root, "candidates.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry udpPeakCandidateRegistry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		t.Fatalf("decode real registry: %v", err)
	}
	return registry
}

func cleanRealUDPPeakEnvironment(goos, goarch string) []string {
	rejected := map[string]bool{
		"GOFLAGS": true, "GOEXPERIMENT": true, "GOOS": true, "GOARCH": true,
		"CGO_ENABLED": true, "GOAMD64": true, "GOARM64": true, "GOENV": true,
		"GOTOOLCHAIN": true, "GOWORK": true, "GOFIPS140": true,
	}
	environment := make([]string, 0, len(os.Environ())+6)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if !rejected[name] {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "GOENV=off")
	if goos != "" {
		environment = append(environment, "GOTOOLCHAIN=local", "GOWORK=off", "GOFIPS140=off", "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		if goos == "darwin" {
			environment = append(environment, "GOARM64=v8.0")
		} else {
			environment = append(environment, "GOAMD64=v1")
		}
	}
	return environment
}

func gitRun(t *testing.T, repo string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func gitOutput(t *testing.T, repo string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = repo
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func assertUDPPeakBinaryDigest(t *testing.T, root string, binary udpPeakCandidateBinary) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(binary.Path)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != binary.SHA256 {
		t.Fatalf("%s digest = %s, registry has %s", binary.Path, got, binary.SHA256)
	}
}

func udpPeakCandidateEngineAndGSO(id string) (string, int) {
	if id == "quic-control" {
		return "quic-blocks-v1", 0
	}
	parts := strings.Split(id, "gso")
	var segments int
	if len(parts) != 2 {
		panic(fmt.Sprintf("bad test candidate %q", id))
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &segments); err != nil {
		panic(err)
	}
	return "bulk-packets-v1", segments
}

func mustWriteExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s bytes = %q, want %q", path, got, want)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
