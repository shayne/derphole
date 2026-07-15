// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type rotationFixture struct {
	Three rotationCase `json:"three"`
	Latin rotationCase `json:"latin"`
}

type rotationCase struct {
	Candidates []string   `json:"candidates"`
	Expected   [][]string `json:"expected"`
}

func TestScheduleUsesFrozenThreeCandidateAndLatinRotations(t *testing.T) {
	t.Parallel()

	fixture := loadFixtureTwice[rotationFixture](t, "finalist-three-candidate-rotation.json")
	for name, test := range map[string]rotationCase{"three": fixture.Three, "latin": fixture.Latin} {
		t.Run(name, func(t *testing.T) {
			got := finalistRotation(test.Candidates)
			if !reflect.DeepEqual(got, test.Expected) {
				t.Fatalf("rotation = %#v, want %#v", got, test.Expected)
			}
		})
	}
}

func TestScheduleIsDeterministicAndRejectsMissingPriorDecision(t *testing.T) {
	t.Parallel()

	manifest, err := NewManifest(validExperimentInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSchedule(manifest, StageFinalist, ScheduleAuthorization{}); err == nil {
		t.Fatal("finalist schedule accepted missing prior decision")
	}
}

func TestScheduleBindsPriorManifestAndKnownCandidates(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := Decision{
		SchemaVersion:  decisionSchemaVersion,
		ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage:          StageScreening,
		Passed:         true,
		PeakFrontier:   []string{"challenger", "control"},
	}
	prior = bindDecisionArtifact(t, manifest, prior)
	first, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: prior})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: prior})
	if err != nil {
		t.Fatal(err)
	}
	left, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("schedule bytes differ across identical builds")
	}
	counts := make(map[string]int)
	for index, run := range first {
		if index < len(first)/2 && run.Direction != DirectionRemoteToLocal {
			t.Fatal("reverse direction did not run first")
		}
		counts[run.CandidateID+"/"+string(run.Direction)]++
	}
	for _, candidate := range []string{"challenger", "control"} {
		for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
			if got := counts[candidate+"/"+string(direction)]; got != 3 {
				t.Fatalf("%s/%s count = %d, want 3", candidate, direction, got)
			}
		}
	}

	badDigest := prior
	badDigest.ManifestSHA256 = hexDigest('f')
	if _, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: badDigest}); err == nil {
		t.Fatal("prior decision for a different manifest accepted")
	}
	unknown := prior
	unknown.PeakFrontier = []string{"unknown", "control"}
	if _, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: unknown}); err == nil {
		t.Fatal("unknown prior candidate accepted")
	}
}

func TestFinalistRotationIsCandidateOrderInvariant(t *testing.T) {
	t.Parallel()

	fixture := loadFixtureTwice[rotationFixture](t, "finalist-three-candidate-rotation.json")
	reversed := append([]string(nil), fixture.Latin.Candidates...)
	sort.Sort(sort.Reverse(sort.StringSlice(reversed)))
	if got := finalistRotation(reversed); !reflect.DeepEqual(got, fixture.Latin.Expected) {
		t.Fatalf("rotation changed with input order: %v", got)
	}
}

func TestFinalistRotationBalancesEveryCandidatePosition(t *testing.T) {
	t.Parallel()

	for _, candidates := range [][]string{{"A", "B"}, {"A", "B", "C", "D"}, {"A", "B", "C", "D", "E"}} {
		rotations := finalistRotation(candidates)
		positionCounts := make(map[string][]int, len(candidates))
		for _, rotation := range rotations {
			for position, candidate := range rotation {
				if positionCounts[candidate] == nil {
					positionCounts[candidate] = make([]int, len(candidates))
				}
				positionCounts[candidate][position]++
			}
		}
		for candidate, counts := range positionCounts {
			minimum, maximum := counts[0], counts[0]
			for _, count := range counts[1:] {
				minimum = min(minimum, count)
				maximum = max(maximum, count)
			}
			if maximum-minimum > 1 {
				t.Fatalf("%v candidate %s position counts = %v, want balanced", candidates, candidate, counts)
			}
		}
	}
}

func TestBuildScheduleNeverInventsRowsAfterManifestPublication(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := Decision{
		SchemaVersion:  decisionSchemaVersion,
		ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage:          StageScreening,
		Passed:         true,
		PeakFrontier:   []string{"challenger", "control"},
	}
	prior = bindDecisionArtifact(t, manifest, prior)
	runs, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: prior})
	if err != nil {
		t.Fatal(err)
	}
	frozen := make(map[string]bool)
	for _, schedule := range manifest.ManifestInput.Schedules {
		for _, runID := range schedule.RunIDs {
			frozen[runID] = true
		}
	}
	for _, run := range runs {
		if !frozen[run.ID] {
			t.Fatalf("BuildSchedule invented run %q after manifest publication", run.ID)
		}
	}
}

func TestFinalistRerunSchedulesCompleteRecordedFinalistSet(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := Decision{
		PeakFrontier:       []string{"challenger"},
		FinalistCandidates: []string{"challenger", "control"},
	}
	got, err := scheduleCandidates(manifest, StageFinalistRerun, prior)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"challenger", "control"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rerun candidates = %v, want complete recorded finalist set %v", got, want)
	}
}

func TestBuildScheduleRejectsPassedDecisionWithoutExactArtifact(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	fabricated := Decision{
		SchemaVersion:  decisionSchemaVersion,
		ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage:          StageScreening,
		Passed:         true,
		PeakFrontier:   []string{"control", "challenger"},
	}
	if _, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: fabricated}); err == nil {
		t.Fatal("dependent schedule accepted Passed=true decision without an exact opened artifact")
	}
}

func TestBuildScheduleRejectsHandAuthoredPassedDecisionWithoutReplayableSamples(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := bindUncheckedDecisionArtifact(t, Decision{
		SchemaVersion:  decisionSchemaVersion,
		ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage:          StageScreening,
		Passed:         true,
		PeakFrontier:   []string{"challenger", "control"},
	})
	if _, err := BuildSchedule(manifest, StagePreliminary, ScheduleAuthorization{Peak: prior}); err == nil {
		t.Fatal("dependent schedule accepted hand-authored Passed=true authorization without replayable samples")
	}
}

func TestBuildScheduleProductionReplaysParentManifestTransition(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	root := t.TempDir()
	peak := Decision{
		SchemaVersion:     decisionSchemaVersion,
		ManifestSHA256:    canonicalManifestDigest(t, experiment),
		Stage:             StageFinalist,
		Passed:            true,
		SelectedCandidate: "challenger",
		PeakFrontier:      []string{"challenger"},
	}
	peakDigest := writeFixtureCanonicalJSON(t, filepath.Join(root, "decisions", "finalist.json"), peak)
	peak.Artifact = ArtifactRef{Role: "finalist", Path: "decisions/finalist.json", SHA256: peakDigest}
	peak.EvidenceRoot = root

	input := validProductionInput(t, experiment)
	input.ParentDecisionRefs = []ArtifactRef{peak.Artifact}
	production := mustManifest(t, input)
	production.EvidenceRoot = root
	// Deliberately do not publish manifest.json. A production authorization must
	// reopen it and verify the experiment -> production transition.
	if _, err := BuildSchedule(production, StageProduction, ScheduleAuthorization{Peak: peak}); err == nil {
		t.Fatal("production schedule skipped exact parent-manifest transition replay")
	}
}

func TestBuildScheduleProductionAcceptsCompletedFinalistRerun(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	root := t.TempDir()
	rerun := bindDecisionArtifactAtRoot(t, experiment, Decision{Stage: StageFinalistRerun}, root)
	finalPath := filepath.Join(root, "decisions", "finalist.json")
	finalDigest := writeFixtureCanonicalJSON(t, finalPath, rerun)
	finalRef := ArtifactRef{Role: "finalist", Path: "decisions/finalist.json", SHA256: finalDigest}
	rerun.Artifact = finalRef
	rerun.EvidenceRoot = root

	input := validProductionInput(t, experiment)
	input.ParentDecisionRefs = []ArtifactRef{finalRef}
	production := mustManifest(t, input)
	production.EvidenceRoot = root
	writeBoundJSON(t, root, *production.ManifestInput.ParentManifest, experiment)
	if _, err := BuildSchedule(production, StageProduction, ScheduleAuthorization{Peak: rerun}); err != nil {
		t.Fatalf("completed exact finalist rerun did not authorize production: %v", err)
	}
}

func bindDecisionArtifact(t *testing.T, manifest Manifest, desired Decision) Decision {
	t.Helper()
	return bindDecisionArtifactAtRoot(t, manifest, desired, t.TempDir())
}

func bindDecisionArtifactAtRoot(t *testing.T, manifest Manifest, desired Decision, root string) Decision {
	t.Helper()
	decision, stageSamples := buildReplayableStageDecision(t, manifest, root, StageScreening, Decision{}, nil, desired)
	if desired.Stage == StageScreening {
		return decision
	}
	prior := decision
	decision, stageSamples = buildReplayableStageDecision(t, manifest, root, StagePreliminary, prior, stageSamples, desired)
	if desired.Stage == StagePreliminary {
		return decision
	}
	prior = decision
	finalDesired := desired
	if desired.Stage == StageFinalistRerun {
		finalDesired.RerunRequired = true
	}
	decision, stageSamples = buildReplayableStageDecision(t, manifest, root, StageFinalist, prior, stageSamples, finalDesired)
	if desired.Stage == StageFinalist {
		return decision
	}
	if desired.Stage == StageFinalistRerun {
		return bindReplayableRerunDecision(t, manifest, root, decision, stageSamples)
	}
	if desired.Stage != StageFinalist {
		t.Fatalf("unsupported replayable fixture stage %q", desired.Stage)
	}
	return decision
}

func authorizedProductionManifest(t *testing.T, experiment Manifest, root string) Manifest {
	t.Helper()
	return authorizedProductionManifestWithPeakStage(t, experiment, root, StageFinalist)
}

func authorizedProductionManifestWithPeakStage(t *testing.T, experiment Manifest, root string, stage Stage) Manifest {
	t.Helper()
	peak := bindDecisionArtifactAtRoot(t, experiment, Decision{Stage: stage}, root)
	if stage == StageFinalistRerun {
		path := filepath.ToSlash(filepath.Join("decisions", "finalist.json"))
		peak.Artifact = ArtifactRef{Role: string(StageFinalist), Path: path, SHA256: writeFixtureCanonicalJSON(t, filepath.Join(root, filepath.FromSlash(path)), peak)}
	}
	input := validProductionInput(t, experiment)
	input.ParentDecisionRefs = []ArtifactRef{peak.Artifact}
	production := mustManifest(t, input)
	production.EvidenceRoot = root
	writeBoundJSON(t, root, *production.ManifestInput.ParentManifest, experiment)
	return production
}

func bindReplayableRerunDecision(t *testing.T, manifest Manifest, root string, prior Decision, priorSamples []Sample) Decision {
	t.Helper()
	decision, _ := buildReplayableStageDecision(t, manifest, root, StageFinalistRerun, prior, priorSamples, Decision{Stage: StageFinalistRerun})
	return decision
}

func bindUncheckedDecisionArtifact(t *testing.T, decision Decision) Decision {
	t.Helper()
	root := t.TempDir()
	path := filepath.ToSlash(filepath.Join("decisions", string(decision.Stage)+".json"))
	digest := writeFixtureCanonicalJSON(t, filepath.Join(root, filepath.FromSlash(path)), decision)
	decision.Artifact = ArtifactRef{Role: string(decision.Stage), Path: path, SHA256: digest}
	decision.EvidenceRoot = root
	return decision
}

func buildReplayableStageDecision(t *testing.T, manifest Manifest, root string, stage Stage, prior Decision, priorSamples []Sample, desired Decision) (Decision, []Sample) {
	t.Helper()
	var frozen FrozenSchedule
	for _, schedule := range manifest.ManifestInput.Schedules {
		if schedule.Stage == string(stage) {
			frozen = schedule
			break
		}
	}
	if len(frozen.RunIDs) == 0 {
		t.Fatalf("missing frozen %s schedule", stage)
	}
	stageSamples := make([]Sample, 0, len(frozen.RunIDs))
	for index, candidateID := range frozen.CandidateOrder {
		goodput := 2100.0
		if desired.RerunRequired || desired.Stage == StageFinalistRerun {
			goodput = 2150
		}
		if candidateID != manifest.ManifestInput.ScreeningControlID {
			goodput = 2200
		}
		sample := validEvidenceSample(t, manifest, index%len(manifest.ManifestInput.Schedules[0].RunIDs), goodput)
		if stage != StageScreening {
			bindSampleToFrozenSchedule(t, manifest, &sample, frozen, index)
			sample.Run.PriorDecisionRef = prior.Artifact
			if stage == StageFinalist && desired.RerunRequired {
				capacity := 2050.0
				if index%3 == 0 {
					capacity = 3000
				}
				sample.Capacity.Mbps = capacity
				sample.Capacity.Valid = true
				sample.Capacity.Artifact = writeEvidence(t, sample.EvidenceRoot, "capacity", sample.Capacity.Artifact.Path, capacityEvidenceRecord{
					SchemaVersion: 1, Kind: "capacity", RunID: sample.Run.ID, Direction: sample.Run.Direction, Mbps: capacity, Valid: true,
				})
			}
			bindSampleArtifact(t, &sample, "fixture-prior-"+sample.Run.ID+".json")
		}
		relocateSampleEvidence(t, &sample, root)
		stageSamples = append(stageSamples, sample)
	}
	allSamples := stageSamples
	if stage == StageFinalist || stage == StageFinalistRerun {
		allSamples = append(append([]Sample(nil), priorSamples...), stageSamples...)
	}
	decision, err := Evaluate(manifest, allSamples, stage, prior)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Passed {
		t.Fatalf("generated replayable %s decision did not pass: %#v", stage, decision)
	}
	path := filepath.ToSlash(filepath.Join("decisions", string(stage)+".json"))
	if stage == StageFinalist && desired.Stage == StageFinalistRerun {
		path = "decisions/finalist-first.json"
	}
	if err := os.MkdirAll(filepath.Join(root, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := writeFixtureCanonicalJSON(t, filepath.Join(root, filepath.FromSlash(path)), decision)
	decision.Artifact = ArtifactRef{Role: string(stage), Path: path, SHA256: digest}
	decision.EvidenceRoot = root
	return decision, allSamples
}
