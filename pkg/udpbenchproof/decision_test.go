// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

type screeningFixture struct {
	Candidate          string           `json:"candidate"`
	Challenger         screeningMetrics `json:"challenger"`
	Competitor         screeningMetrics `json:"competitor"`
	ControlBeforeMbps  float64          `json:"control_before_mbps"`
	ControlAfterMbps   float64          `json:"control_after_mbps"`
	ExpectedEliminated bool             `json:"expected_eliminated"`
}

func TestDecisionScreeningRequiresStableBracketsAndStrictTripleDomination(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"screening-dominated.json", "screening-unstable-brackets.json"} {
		fixture := loadFixtureTwice[screeningFixture](t, name)
		manifest := mustManifest(t, validExperimentInput())
		schedule := manifest.ManifestInput.Schedules[0]
		samples := make([]Sample, len(schedule.RunIDs))
		for index, role := range schedule.RunRoles {
			metrics := fixture.Competitor
			switch role {
			case "control-before":
				metrics = screeningMetrics{RawMbps: fixture.ControlBeforeMbps, Normalized: fixture.ControlBeforeMbps / 2200, CPUEfficiency: fixture.ControlBeforeMbps / 4}
			case "control-after":
				metrics = screeningMetrics{RawMbps: fixture.ControlAfterMbps, Normalized: fixture.ControlAfterMbps / 2200, CPUEfficiency: fixture.ControlAfterMbps / 4}
			case "candidate":
				if schedule.CandidateOrder[index] == fixture.Candidate {
					metrics = fixture.Challenger
				}
			}
			samples[index] = validEvidenceSample(t, manifest, index, 2100)
			rewriteScreeningPerformance(t, &samples[index], metrics)
		}
		first, err := Evaluate(manifest, samples, StageScreening, Decision{})
		if err != nil {
			t.Fatal(err)
		}
		second, err := Evaluate(manifest, samples, StageScreening, Decision{})
		if err != nil {
			t.Fatal(err)
		}
		assertByteIdenticalJSON(t, first, second)
		eliminated := !stringInSlice(fixture.Candidate, first.PeakFrontier)
		if eliminated != fixture.ExpectedEliminated {
			t.Fatalf("%s public screening decision = %#v", name, first)
		}
	}
}

func rewriteScreeningPerformance(t *testing.T, sample *Sample, fixture screeningMetrics) {
	t.Helper()
	raw := fixture.RawMbps * 1.5
	normalized := fixture.Normalized * 1.5
	efficiency := fixture.CPUEfficiency * 2
	if normalized <= 0 || efficiency <= 0 {
		t.Fatal("invalid screening fixture metrics")
	}
	sample.GoodputMbps = raw
	sample.WallGoodputMbps = raw - 10
	sample.Capacity.Mbps = raw / normalized
	sample.Capacity.Valid = sample.Capacity.Mbps >= 2050
	sample.Resource.SenderUserSeconds = raw / efficiency
	sample.Resource.SenderSystemSeconds = 0
	sample.Resource.ReceiverUserSeconds = raw / efficiency
	sample.Resource.ReceiverSystemSeconds = 0
	root := sample.EvidenceRoot
	sample.Capacity.Artifact = writeEvidence(t, root, "capacity", sample.Capacity.Artifact.Path, capacityEvidenceRecord{1, "capacity", sample.Run.ID, sample.Run.Direction, sample.Capacity.Mbps, sample.Capacity.Valid})
	sample.Resource.Sender = writeEvidence(t, root, "resource-sender", sample.Resource.Sender.Path, resourceEvidenceRecord{1, "resource", sample.Run.ID, "sender", sample.Resource.SenderUserSeconds, 0})
	sample.Resource.Receiver = writeEvidence(t, root, "resource-receiver", sample.Resource.Receiver.Path, resourceEvidenceRecord{1, "resource", sample.Run.ID, "receiver", sample.Resource.ReceiverUserSeconds, 0})
	sample.ReceiverResult = writeEvidence(t, root, "receiver-result", sample.ReceiverResult.Path, receiverResultRecord{
		SchemaVersion: 1, Kind: "file-result", RunID: sample.Run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(*sample),
		CommittedBytes: sample.Run.SizeBytes, PayloadSeconds: secondsForMbps(sample.Run.SizeBytes, sample.GoodputMbps),
		WallSeconds: secondsForMbps(sample.Run.SizeBytes, sample.WallGoodputMbps), MaxFlatlineSeconds: sample.FlatlineSeconds,
		Started: true, ObservedAtUTC: sample.ObservedAtUTC,
	})
	bindSampleArtifact(t, sample, "fixture-"+sample.Run.ID+".json")
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestEvaluateScreeningUsesFrozenBracketsAndStrictTripleDomination(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	schedule := manifest.ManifestInput.Schedules[0]
	makeSamples := func(challengerMbps float64) []Sample {
		samples := make([]Sample, 0, len(schedule.RunIDs))
		for index := range schedule.RunIDs {
			goodput := 2200.0
			if schedule.CandidateOrder[index] == "challenger" {
				goodput = challengerMbps
			}
			sample := validEvidenceSample(t, manifest, index, goodput)
			samples = append(samples, sample)
		}
		return samples
	}

	dominated, err := Evaluate(manifest, makeSamples(1990), StageScreening, Decision{})
	if err != nil {
		t.Fatal(err)
	}
	if !dominated.Passed || !reflect.DeepEqual(dominated.PeakFrontier, []string{"control"}) {
		t.Fatalf("strictly dominated screening decision = %#v", dominated)
	}
	exactBoundary, err := Evaluate(manifest, makeSamples(2000), StageScreening, Decision{})
	if err != nil {
		t.Fatal(err)
	}
	if !exactBoundary.Passed || !reflect.DeepEqual(exactBoundary.PeakFrontier, []string{"challenger", "control"}) {
		t.Fatalf("exact 10%% boundary was eliminated: %#v", exactBoundary)
	}
}

func TestEvaluateScreeningAlwaysAdvancesControlAndRejectsUnstableDominator(t *testing.T) {
	t.Parallel()

	input := validExperimentInput()
	input.Candidates = []CandidateIdentity{
		testCandidate("control", '1', '2', '3'),
		testCandidate("challenger", '4', '5', '6'),
		testCandidate("competitor", '7', '8', '9'),
	}
	input.ScreeningControlID = "control"
	input.Schedules = experimentSchedulesForCandidates("control", []string{"control", "challenger", "competitor"})
	manifest := mustManifest(t, input)
	schedule := manifest.ManifestInput.Schedules[0]
	samples := make([]Sample, len(schedule.RunIDs))
	for index := range samples {
		metrics := screeningMetrics{RawMbps: 2200, Normalized: 1, CPUEfficiency: 550}
		block := schedule.BlockOrder[index]
		role := schedule.RunRoles[index]
		if role == "candidate" {
			switch schedule.CandidateOrder[index] {
			case "control":
				metrics = screeningMetrics{RawMbps: 1700, Normalized: 0.75, CPUEfficiency: 400}
			case "challenger":
				metrics = screeningMetrics{RawMbps: 1900, Normalized: 0.80, CPUEfficiency: 430}
			case "competitor":
				metrics = screeningMetrics{RawMbps: 2300, Normalized: 1.00, CPUEfficiency: 575}
			}
		}
		if block == 2 && role == "control-after" {
			metrics = screeningMetrics{RawMbps: 2000, Normalized: 2000.0 / 2200, CPUEfficiency: 500}
		}
		samples[index] = validEvidenceSample(t, manifest, index, 2100)
		rewriteScreeningPerformance(t, &samples[index], metrics)
	}

	decision, err := Evaluate(manifest, samples, StageScreening, Decision{})
	if err != nil {
		t.Fatal(err)
	}
	if !stringInSlice("control", decision.PeakFrontier) {
		t.Fatalf("frozen control did not advance: %#v", decision.PeakFrontier)
	}
	if !stringInSlice("challenger", decision.PeakFrontier) {
		t.Fatalf("unstable competitor eliminated challenger: %#v", decision.PeakFrontier)
	}
}

type preliminaryFixture struct {
	Candidates       []preliminaryFixtureCandidate `json:"candidates"`
	ExpectedAdvanced []string                      `json:"expected_advanced"`
}

type preliminaryFixtureCandidate struct {
	ID                string  `json:"id"`
	LocalToRemoteMbps float64 `json:"local_to_remote_mbps"`
	RemoteToLocalMbps float64 `json:"remote_to_local_mbps"`
}

func TestDecisionPreliminaryFivePercentRulesAlwaysAdvanceAtLeastTwo(t *testing.T) {
	t.Parallel()

	fixture := loadFixtureTwice[preliminaryFixture](t, "preliminary-five-percent-frontier.json")
	input := validExperimentInput()
	input.Candidates = make([]CandidateIdentity, len(fixture.Candidates))
	ids := make([]string, len(fixture.Candidates))
	for index, candidate := range fixture.Candidates {
		ids[index] = candidate.ID
		digit := rune('1' + index*3)
		input.Candidates[index] = testCandidate(candidate.ID, digit, digit+1, digit+2)
	}
	input.ScreeningControlID = ids[0]
	input.Schedules = experimentSchedulesForCandidates(ids[0], ids)
	manifest := mustManifest(t, input)
	prior := bindDecisionArtifact(t, manifest, Decision{
		SchemaVersion: decisionSchemaVersion, ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage: StageScreening, Passed: true, SelectedCandidate: ids[0], PeakFrontier: append([]string(nil), ids...),
		Reasons: []string{}, InputDecisionRefs: []ArtifactRef{}, SampleRefs: []ArtifactRef{}, FleetProbeRefs: []ArtifactRef{},
		Statistics: []CandidateStatistics{}, MaterialEdges: []MaterialEdge{}, ClosedCandidates: []string{},
	})
	byID := make(map[string]preliminaryFixtureCandidate, len(fixture.Candidates))
	for _, candidate := range fixture.Candidates {
		byID[candidate.ID] = candidate
	}
	schedule := manifest.ManifestInput.Schedules[1]
	samples := make([]Sample, len(schedule.RunIDs))
	for index, candidateID := range schedule.CandidateOrder {
		candidate := byID[candidateID]
		goodput := candidate.RemoteToLocalMbps
		if manifestDirection(schedule.DirectionOrder[index]) == DirectionLocalToRemote {
			goodput = candidate.LocalToRemoteMbps
		}
		samples[index] = validEvidenceSample(t, manifest, index%len(manifest.ManifestInput.Schedules[0].RunIDs), goodput)
		bindSampleToFrozenSchedule(t, manifest, &samples[index], schedule, index)
		samples[index].Run.PriorDecisionRef = prior.Artifact
		bindSampleArtifact(t, &samples[index], "fixture-prior-"+samples[index].Run.ID+".json")
	}
	first, err := Evaluate(manifest, samples, StagePreliminary, prior)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(manifest, samples, StagePreliminary, prior)
	if err != nil {
		t.Fatal(err)
	}
	assertByteIdenticalJSON(t, first, second)
	if !reflect.DeepEqual(first.PeakFrontier, fixture.ExpectedAdvanced) {
		t.Fatalf("public preliminary frontier = %v, want %v", first.PeakFrontier, fixture.ExpectedAdvanced)
	}
}

func TestDecisionClosurePropagatesAcrossEliminatedCampaignStages(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	root := t.TempDir()
	makeStageSamples := func(schedule FrozenSchedule, candidate string, prior ArtifactRef) []Sample {
		var samples []Sample
		for index, candidateID := range schedule.CandidateOrder {
			if candidateID != candidate {
				continue
			}
			sample := validEvidenceSample(t, manifest, index%len(manifest.ManifestInput.Schedules[0].RunIDs), 2200)
			bindSampleToFrozenSchedule(t, manifest, &sample, schedule, index)
			sample.Run.PriorDecisionRef = prior
			bindSampleArtifact(t, &sample, "closure-"+sample.Run.ID+".json")
			relocateSampleEvidence(t, &sample, root)
			samples = append(samples, sample)
		}
		return samples
	}

	var screeningSamples []Sample
	for index, candidateID := range manifest.ManifestInput.Schedules[0].CandidateOrder {
		goodput := 2200.0
		if candidateID == "challenger" && manifest.ManifestInput.Schedules[0].RunRoles[index] == "candidate" {
			goodput = 1900
		}
		sample := validEvidenceSample(t, manifest, index, goodput)
		relocateSampleEvidence(t, &sample, root)
		screeningSamples = append(screeningSamples, sample)
	}
	screening, err := Evaluate(manifest, screeningSamples, StageScreening, Decision{})
	if err != nil {
		t.Fatal(err)
	}
	screening = writeReplayableDecisionAtRoot(t, root, screening)
	preliminarySamples := makeStageSamples(manifest.ManifestInput.Schedules[1], "control", screening.Artifact)
	preliminary, err := Evaluate(manifest, preliminarySamples, StagePreliminary, screening)
	if err != nil {
		t.Fatal(err)
	}
	preliminary = writeReplayableDecisionAtRoot(t, root, preliminary)
	finalistSamples := append([]Sample(nil), preliminarySamples...)
	finalistSamples = append(finalistSamples, makeStageSamples(manifest.ManifestInput.Schedules[2], "control", preliminary.Artifact)...)
	finalist, err := Evaluate(manifest, finalistSamples, StageFinalist, preliminary)
	if err != nil {
		t.Fatal(err)
	}
	if !finalist.Passed || !reflect.DeepEqual(finalist.PeakFrontier, []string{"control"}) || !reflect.DeepEqual(finalist.ClosedCandidates, []string{"challenger"}) {
		t.Fatalf("finalist did not preserve full candidate partition: %#v", finalist)
	}
	if reasons := validateCeilingPeakClosure(manifest, finalist); len(reasons) != 0 {
		t.Fatalf("ceiling rejected exact finalist frontier after an earlier-stage elimination: %v", reasons)
	}
}

func writeReplayableDecisionAtRoot(t *testing.T, root string, decision Decision) Decision {
	t.Helper()
	path := filepath.ToSlash(filepath.Join("decisions", string(decision.Stage)+".json"))
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := writeFixtureCanonicalJSON(t, filepath.Join(root, filepath.FromSlash(path)), decision)
	decision.Artifact = ArtifactRef{Role: string(decision.Stage), Path: path, SHA256: digest}
	decision.EvidenceRoot = root
	return decision
}

func experimentSchedulesForCandidates(control string, candidates []string) []FrozenSchedule {
	screening := FrozenSchedule{Stage: "screening", Repetitions: 1}
	for block, candidate := range candidates {
		for _, row := range []struct{ suffix, candidate, role string }{
			{"before", control, "control-before"},
			{"candidate", candidate, "candidate"},
			{"after", control, "control-after"},
		} {
			appendFrozenTestRow(&screening, "screen-"+candidate+"-"+row.suffix, row.candidate, "primary", "hetz-to-mac", block, row.role)
		}
	}
	return []FrozenSchedule{
		screening,
		balancedCandidateSchedule("preliminary", "prelim", candidates, 3),
		balancedCandidateSchedule("finalist", "final", candidates, 3),
		balancedCandidateSchedule("finalist-rerun", "rerun", candidates, 6),
	}
}

type wrongBinaryFixture struct {
	Mutation       string `json:"mutation"`
	Value          string `json:"value"`
	ExpectedPassed bool   `json:"expected_passed"`
	ExpectedReason string `json:"expected_reason"`
}

func TestPrerequisiteRejectsWrongBinary(t *testing.T) {
	t.Parallel()

	fixture := loadFixtureTwice[wrongBinaryFixture](t, "prerequisite-wrong-binary.json")
	experiment := mustManifest(t, validExperimentInput())
	root := t.TempDir()
	production := authorizedProductionManifest(t, experiment, root)
	samples := make([]Sample, len(production.ManifestInput.Schedules[0].RunIDs))
	for index := range samples {
		samples[index] = validEvidenceSample(t, production, index, 2100)
		relocateSampleEvidence(t, &samples[index], root)
	}
	decision := DecidePrerequisite(production, samples)
	assertByteIdenticalJSON(t, decision, DecidePrerequisite(production, samples))
	digest := mustCanonicalDigest(t, decision)
	ref := ArtifactRef{Role: "prerequisite", Path: "prerequisite.json", SHA256: digest}
	writeBoundJSON(t, root, ref, decision)
	decision.Artifact = ref
	decision.EvidenceRoot = root
	wrong := decision.BinarySet
	if fixture.Mutation != "linux_sha256" {
		t.Fatalf("unsupported fixture mutation %q", fixture.Mutation)
	}
	wrong.Linux.SHA256 = SHA256Digest(fixture.Value)
	err := VerifyPrerequisite(production, canonicalManifestDigest(t, production), decision, digest, wrong)
	passed := err == nil
	if passed != fixture.ExpectedPassed || err == nil || !containsReason([]string{err.Error()}, fixture.ExpectedReason) {
		t.Fatalf("wrong-binary verification passed=%t err=%v", passed, err)
	}
}

type fleetProbeFixture struct {
	HostID            string `json:"host_id"`
	InitialAvailable  bool   `json:"initial_available"`
	RecheckAvailable  bool   `json:"recheck_available"`
	ExpectedMandatory bool   `json:"expected_mandatory"`
}

type acceptanceFixture struct {
	LocalToRemoteMbps []float64 `json:"local_to_remote_mbps"`
	RemoteToLocalMbps []float64 `json:"remote_to_local_mbps"`
	ExpectedPassed    bool      `json:"expected_passed"`
	ExpectedMet       bool      `json:"expected_acceptance_met"`
}

type replacementFixture struct {
	ScheduledRunID string `json:"scheduled_run_id"`
	ExpectedPassed bool   `json:"expected_passed"`
	ExpectedReason string `json:"expected_reason"`
}

func TestAcceptanceDecisionBindsManifestPriorDecisionsAndExactSixSamples(t *testing.T) {
	t.Parallel()

	fleetFixture := loadFixtureTwice[fleetProbeFixture](t, "fleet-unavailable-at-second-probe.json")
	experiment := mustManifest(t, validExperimentInput())
	parentRoot := t.TempDir()
	production := authorizedProductionManifest(t, experiment, parentRoot)
	productionDigest := canonicalManifestDigest(t, production)
	candidate := production.ManifestInput.Candidates[0]
	if err := os.MkdirAll(filepath.Join(parentRoot, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	productionRef := ArtifactRef{Role: "manifest", Path: "production-manifest.json", SHA256: productionDigest}
	writeBoundJSON(t, parentRoot, productionRef, production)
	productionSamples := make([]Sample, len(production.ManifestInput.Schedules[0].RunIDs))
	for index := range productionSamples {
		productionSamples[index] = validEvidenceSample(t, production, index, 2100)
		relocateSampleEvidence(t, &productionSamples[index], parentRoot)
	}
	prerequisite := DecidePrerequisite(production, productionSamples)
	if !prerequisite.Passed {
		t.Fatalf("generated prerequisite = %#v", prerequisite)
	}
	prerequisiteDigest := mustCanonicalDigest(t, prerequisite)
	acceptanceInput := validAcceptanceInput(t, production)
	acceptanceInput.ParentDecisionRefs = []ArtifactRef{
		{Role: "prerequisite", Path: "decisions/prerequisite.json", SHA256: prerequisiteDigest},
		{Role: "fleet", Path: "decisions/fleet.json", SHA256: hexDigest('e')},
	}
	if got := writeFixtureCanonicalJSON(t, filepath.Join(parentRoot, "decisions", "prerequisite.json"), prerequisite); got != prerequisiteDigest {
		t.Fatalf("bind prerequisite: digest=%s", got)
	}
	prerequisite.Artifact = acceptanceInput.ParentDecisionRefs[0]
	prerequisite.EvidenceRoot = parentRoot
	if err := os.MkdirAll(filepath.Join(parentRoot, "probes"), 0o700); err != nil {
		t.Fatal(err)
	}
	var probeRefs []ArtifactRef
	fixtureHostSeen := false
	for _, host := range production.ManifestInput.FleetInventory {
		if host.Role == HostRolePrimary {
			continue
		}
		for phaseIndex, phase := range []string{"initial", "recheck"} {
			available := true
			if host.ID == fleetFixture.HostID {
				fixtureHostSeen = true
				available = fleetFixture.InitialAvailable
				if phase == "recheck" {
					available = fleetFixture.RecheckAvailable
				}
			}
			path := filepath.ToSlash(filepath.Join("probes", host.ID+"-"+phase+".json"))
			ref := writeEvidence(t, parentRoot, "fleet-probe", path, fleetProbeRecord{1, "fleet-probe", host.ID, phase, available, time.Date(2026, 7, 16, 2, phaseIndex, 0, 0, time.UTC).Format(time.RFC3339)})
			probeRefs = append(probeRefs, ref)
		}
	}
	if !fixtureHostSeen || !fleetFixture.ExpectedMandatory || (!fleetFixture.InitialAvailable && !fleetFixture.RecheckAvailable) {
		t.Fatal("fleet recheck fixture does not identify a mandatory manifest host")
	}
	fleetSchedule := production.ManifestInput.Schedules[1]
	var fleetSamples []Sample
	for index := range fleetSchedule.RunIDs {
		sample := validEvidenceSample(t, production, index%len(production.ManifestInput.Schedules[0].RunIDs), 2100)
		bindSampleToFrozenSchedule(t, production, &sample, fleetSchedule, index)
		sample.Run.PriorDecisionRef = acceptanceInput.ParentDecisionRefs[0]
		bindSampleArtifact(t, &sample, "fleet-prior-"+sample.Run.ID+".json")
		relocateSampleEvidence(t, &sample, parentRoot)
		fleetSamples = append(fleetSamples, sample)
	}
	fleetInputs := FleetInputs{
		Manifest: production, ManifestRef: productionRef, Prerequisite: prerequisite,
		PrerequisiteRef: acceptanceInput.ParentDecisionRefs[0], ProbeRefs: probeRefs,
		Samples: fleetSamples, EvidenceRoot: parentRoot,
	}
	fleet := DecideFleet(fleetInputs)
	assertByteIdenticalJSON(t, fleet, DecideFleet(fleetInputs))
	if !fleet.Passed || fleet.SelectedCandidate != candidate.ID {
		t.Fatalf("generated fleet decision = %#v", fleet)
	}
	missingFleetRun := fleetInputs
	missingFleetRun.Samples = fleetInputs.Samples[:len(fleetInputs.Samples)-1]
	if decision := DecideFleet(missingFleetRun); decision.Passed {
		t.Fatal("fleet decision path accepted an omitted mandatory frozen sample")
	}
	fleetDigest := mustCanonicalDigest(t, fleet)
	acceptanceInput.ParentDecisionRefs[1].SHA256 = fleetDigest
	if got := writeFixtureCanonicalJSON(t, filepath.Join(parentRoot, "decisions", "fleet.json"), fleet); got != fleetDigest {
		t.Fatalf("bind fleet: digest=%s", got)
	}
	fleet.Artifact = acceptanceInput.ParentDecisionRefs[1]
	fleet.EvidenceRoot = parentRoot
	acceptance := mustManifest(t, acceptanceInput)
	acceptance.EvidenceRoot = parentRoot
	rates := loadFixtureTwice[acceptanceFixture](t, "acceptance-six-run-pass.json")
	samples := make([]Sample, 6)
	for index := range samples {
		goodput := 0.0
		if index < 3 {
			goodput = rates.RemoteToLocalMbps[index]
		} else {
			goodput = rates.LocalToRemoteMbps[index-3]
		}
		samples[index] = validEvidenceSample(t, acceptance, index, goodput)
		samples[index].Run.PriorDecisionRef = fleet.Artifact
		bindSampleArtifact(t, &samples[index], "acceptance-prior-"+samples[index].Run.ID+".json")
	}
	manifestDigest := canonicalManifestDigest(t, acceptance)
	inputs := AcceptanceInputs{
		Manifest:        acceptance,
		ManifestRef:     ArtifactRef{Role: "manifest", Path: "acceptance-manifest.json", SHA256: manifestDigest},
		Prerequisite:    prerequisite,
		PrerequisiteRef: acceptanceInput.ParentDecisionRefs[0],
		Fleet:           fleet,
		FleetRef:        acceptanceInput.ParentDecisionRefs[1],
		Samples:         samples,
	}
	decision := DecideAcceptance(inputs)
	assertByteIdenticalJSON(t, decision, DecideAcceptance(inputs))
	if !decision.Passed || !decision.AcceptanceMet || len(decision.SampleRefs) != 6 || !reflect.DeepEqual(decision.InputDecisionRefs, acceptanceInput.ParentDecisionRefs) {
		t.Fatalf("acceptance decision = %#v", decision)
	}

	replacementFixture := loadFixtureTwice[replacementFixture](t, "acceptance-replacement-attempt.json")
	replacement := inputs
	replacement.Samples = append([]Sample(nil), inputs.Samples...)
	replacementIndex := -1
	for index := range replacement.Samples {
		if replacement.Samples[index].Run.ID == replacementFixture.ScheduledRunID {
			replacementIndex = index
			break
		}
	}
	if replacementIndex < 0 {
		t.Fatalf("replacement fixture run %q is not frozen", replacementFixture.ScheduledRunID)
	}
	replacementSample := replacement.Samples[replacementIndex]
	relocateSampleEvidence(t, &replacementSample, t.TempDir())
	replacementSample.ObservedAtUTC = "2026-07-16T01:01:00Z"
	replacementSample.ReceiverResult = writeEvidence(t, replacementSample.EvidenceRoot, "receiver-result", replacementSample.ReceiverResult.Path, receiverResultRecord{
		SchemaVersion: 1, Kind: "file-result", RunID: replacementSample.Run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(replacementSample),
		CommittedBytes: replacementSample.Run.SizeBytes, PayloadSeconds: secondsForMbps(replacementSample.Run.SizeBytes, replacementSample.GoodputMbps),
		WallSeconds: secondsForMbps(replacementSample.Run.SizeBytes, replacementSample.WallGoodputMbps), MaxFlatlineSeconds: replacementSample.FlatlineSeconds,
		Started: true, ObservedAtUTC: replacementSample.ObservedAtUTC,
	})
	bindSampleArtifact(t, &replacementSample, "replacement-"+replacementSample.Run.ID+".json")
	replacement.Samples = append(replacement.Samples, replacementSample)
	replacementDecision := DecideAcceptance(replacement)
	assertByteIdenticalJSON(t, replacementDecision, DecideAcceptance(replacement))
	if replacementDecision.Passed != replacementFixture.ExpectedPassed || replacementDecision.AcceptanceMet || !containsReason(replacementDecision.Reasons, replacementFixture.ExpectedReason) {
		t.Fatalf("replacement decision = %#v", replacementDecision)
	}
	wrongPrior := inputs
	wrongPrior.PrerequisiteRef.SHA256 = hexDigest('f')
	if decision := DecideAcceptance(wrongPrior); decision.Passed {
		t.Fatal("wrong prerequisite digest accepted")
	}
	wrongSamplePrior := inputs
	wrongSamplePrior.Samples = append([]Sample(nil), inputs.Samples...)
	wrongSamplePrior.Samples[0].Run.PriorDecisionRef = inputs.PrerequisiteRef
	bindSampleArtifact(t, &wrongSamplePrior.Samples[0], "wrong-prior-"+wrongSamplePrior.Samples[0].Run.ID+".json")
	if decision := DecideAcceptance(wrongSamplePrior); decision.Passed || !containsReason(decision.Reasons, "prior decision reference mismatch") {
		t.Fatalf("acceptance sample prior substitution was not rejected explicitly: %#v", decision)
	}
	missingMandatoryFleetRun := inputs
	missingMandatoryFleetRun.Fleet.SampleRefs = append([]ArtifactRef(nil), inputs.Fleet.SampleRefs[:len(inputs.Fleet.SampleRefs)-1]...)
	if reasons := validateFleetProbeProof(missingMandatoryFleetRun); len(reasons) == 0 {
		t.Fatal("fleet proof accepted a mandatory available host with an omitted frozen sample")
	}
}

func TestAcceptanceRejectsFabricatedParentValuesWithoutExactArtifacts(t *testing.T) {
	t.Parallel()

	prerequisite := PrerequisiteDecision{SchemaVersion: 1, Passed: true, Reasons: []string{}, Samples: sixNumberedRefs("sample", "production", 1)}
	fleet := Decision{SchemaVersion: 1, Stage: StageFleet, Passed: true, Reasons: []string{}}
	prerequisiteRef := ArtifactRef{Role: "prerequisite", Path: "prerequisite.json", SHA256: mustCanonicalDigest(t, prerequisite)}
	fleetRef := ArtifactRef{Role: "fleet", Path: "fleet.json", SHA256: mustCanonicalDigest(t, fleet)}
	inputs := AcceptanceInputs{Prerequisite: prerequisite, PrerequisiteRef: prerequisiteRef, Fleet: fleet, FleetRef: fleetRef}
	decision := Decision{InputDecisionRefs: []ArtifactRef{prerequisiteRef, fleetRef}}
	validateAcceptanceParentRefs(inputs, &decision)
	if len(decision.Reasons) == 0 {
		t.Fatal("acceptance trusted fabricated passed parent values without opening exact artifacts")
	}
}

func mustCanonicalDigest(t *testing.T, value any) SHA256Digest {
	t.Helper()
	digest, err := canonicalDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func sixNumberedRefs(role, prefix string, start int) []ArtifactRef {
	refs := make([]ArtifactRef, 6)
	for index := range refs {
		refs[index] = numberedRef(role, fmt.Sprintf("%s-%d.json", prefix, index+1), start+index)
	}
	return refs
}

func TestDecisionStatisticsAreExactAndBootstrapReproducible(t *testing.T) {
	t.Parallel()

	first := statistics([]float64{4, 1, 3, 2})
	second := statistics([]float64{2, 3, 1, 4})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("statistics depend on order: %#v / %#v", first, second)
	}
	if first.Count != 4 || first.Mean != 2.5 || first.Median != 2.5 || first.Minimum != 1 || first.Maximum != 4 {
		t.Fatalf("basic statistics = %#v", first)
	}
	if math.Abs(first.PopulationStdDev-math.Sqrt(1.25)) > 1e-12 || math.Abs(first.CoefficientOfVariation-math.Sqrt(1.25)/2.5) > 1e-12 {
		t.Fatalf("spread statistics = %#v", first)
	}
	if !(first.BootstrapLow < first.Median && first.BootstrapHigh > first.Median) {
		t.Fatalf("bootstrap interval = [%v,%v], want interval around median", first.BootstrapLow, first.BootstrapHigh)
	}
}

func TestDecisionNearestTimeMatchingDoesNotReuseAndBreaksTiesEarlier(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	left := []timedMetric{
		{ObservedAt: base.Add(10 * time.Second), Raw: 11, Normalized: 11},
		{ObservedAt: base.Add(30 * time.Second), Raw: 9, Normalized: 9},
	}
	right := []timedMetric{
		{ObservedAt: base, Raw: 12, Normalized: 12},
		{ObservedAt: base.Add(20 * time.Second), Raw: 8, Normalized: 8},
	}
	wins, matches := nearestTimeWins(left, right)
	if wins != 1 || matches != 2 {
		t.Fatalf("wins/matches = %d/%d, want 1/2", wins, matches)
	}
}

func TestDecisionNearestTimeMatchingNeverCrossesFrozenScheduleBlocks(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	left := []timedMetric{
		{ObservedAt: base, Raw: 20, Normalized: 20, Block: "preliminary/0"},
		{ObservedAt: base.Add(time.Second), Raw: 20, Normalized: 20, Block: "preliminary/1"},
	}
	right := []timedMetric{
		{ObservedAt: base, Raw: 10, Normalized: 10, Block: "preliminary/1"},
		{ObservedAt: base.Add(time.Second), Raw: 10, Normalized: 10, Block: "preliminary/0"},
	}
	wins, matches := nearestTimeWins(left, right)
	if wins != 2 || matches != 2 {
		t.Fatalf("block-local wins/matches = %d/%d, want 2/2", wins, matches)
	}
}

func TestDecisionPreliminaryAdvancesNormalizedDirectionLeader(t *testing.T) {
	t.Parallel()

	summaries := []CandidateStatistics{
		candidateSummary("alpha", 1000, 1000, 0.40, 0.40),
		candidateSummary("beta", 700, 700, 0.50, 0.50),
		candidateSummary("gamma", 900, 900, 0.35, 0.35),
	}
	if got := selectPreliminaryCandidates(summaries, 0.05); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatalf("advanced = %v, want raw and normalized leaders", got)
	}
}

func TestDecisionMaterialEdgeRequiresStrictThresholdNoRegressionAndFourOfSix(t *testing.T) {
	t.Parallel()

	from := candidateSummary("A", 104, 104, 1.04, 1.04)
	to := candidateSummary("B", 100, 100, 1.00, 1.00)
	base := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	var samples []Sample
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		for index := range 6 {
			fromRaw := 104.0
			if index >= 4 {
				fromRaw = 99
			}
			samples = append(samples,
				Sample{CandidateID: "A", Run: ScheduledRun{Direction: direction}, ObservedAtUTC: base.Add(time.Duration(index*10) * time.Second).Format(time.RFC3339), GoodputMbps: fromRaw, Capacity: CapacityEvidence{Mbps: 100}},
				Sample{CandidateID: "B", Run: ScheduledRun{Direction: direction}, ObservedAtUTC: base.Add(time.Duration(index*10+1) * time.Second).Format(time.RFC3339), GoodputMbps: 100, Capacity: CapacityEvidence{Mbps: 100}},
			)
		}
	}
	if !materiallyBeats(from, to, samples, 0.03) {
		t.Fatal("strict >3 percent and four-of-six win rejected")
	}
	exactlyThree := candidateSummary("A", 103, 103, 1.03, 1.03)
	if materiallyBeats(exactlyThree, to, samples, 0.03) {
		t.Fatal("exactly 3 percent incorrectly treated as material")
	}
	regressed := from
	regressed.Directions[0].Raw.Median = 96
	if materiallyBeats(regressed, to, samples, 0.03) {
		t.Fatal("direction regression accepted")
	}
}

func TestDecisionMaterialEdgeScalesNearestTimeThresholdToEightOfTwelve(t *testing.T) {
	t.Parallel()

	from := candidateSummary("A", 104, 104, 1.04, 1.04)
	to := candidateSummary("B", 100, 100, 1, 1)
	base := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	makeSamples := func(wins int) []Sample {
		var samples []Sample
		for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
			for index := range 12 {
				fromRaw := 99.0
				if index < wins {
					fromRaw = 104
				}
				samples = append(samples,
					Sample{CandidateID: "A", Run: ScheduledRun{Direction: direction, Schedule: "pooled", Block: index}, ObservedAtUTC: base.Add(time.Duration(index*10) * time.Second).Format(time.RFC3339), GoodputMbps: fromRaw, Capacity: CapacityEvidence{Mbps: 100}},
					Sample{CandidateID: "B", Run: ScheduledRun{Direction: direction, Schedule: "pooled", Block: index}, ObservedAtUTC: base.Add(time.Duration(index*10+1) * time.Second).Format(time.RFC3339), GoodputMbps: 100, Capacity: CapacityEvidence{Mbps: 100}},
				)
			}
		}
		return samples
	}
	if materiallyBeats(from, to, makeSamples(7), 0.03) {
		t.Fatal("seven of twelve nearest-time wins incorrectly established material domination")
	}
	if !materiallyBeats(from, to, makeSamples(8), 0.03) {
		t.Fatal("eight of twelve nearest-time wins did not establish material domination")
	}
}

func TestEvaluateFinalistsIsDeterministicAndRanksFrontier(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := bindDecisionArtifact(t, manifest, Decision{
		SchemaVersion:  decisionSchemaVersion,
		ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage:          StagePreliminary,
		Passed:         true,
		PeakFrontier:   []string{"challenger", "control"},
	})
	screeningRef := artifactRefByRole(prior.InputDecisionRefs, string(StageScreening))
	var samples []Sample
	for scheduleIndex, schedule := range manifest.ManifestInput.Schedules[1:3] {
		for index := range schedule.RunIDs {
			goodput := 2100.0
			if schedule.CandidateOrder[index] == "challenger" {
				goodput = 2200
			}
			sample := validEvidenceSample(t, manifest, index%2, goodput)
			bindSampleToFrozenSchedule(t, manifest, &sample, schedule, index)
			if scheduleIndex == 0 {
				sample.Run.PriorDecisionRef = screeningRef
			} else {
				sample.Run.PriorDecisionRef = prior.Artifact
			}
			bindSampleArtifact(t, &sample, "prior-bound-"+sample.Run.ID+".json")
			samples = append(samples, sample)
		}
	}
	first, err := Evaluate(manifest, samples, StageFinalist, prior)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Run.ID > samples[j].Run.ID })
	second, err := Evaluate(manifest, samples, StageFinalist, prior)
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
		t.Fatalf("decision changes with sample order:\n%s\n%s", left, right)
	}
	if !first.Passed || first.SelectedCandidate != "challenger" || !reflect.DeepEqual(first.PeakFrontier, []string{"challenger"}) {
		t.Fatalf("decision = %#v", first)
	}
}

func TestEvaluateRejectsDuplicateScheduledRunAndStartedFailure(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	var samples []Sample
	for index := range manifest.ManifestInput.Schedules[0].RunIDs {
		sample := validEvidenceSample(t, manifest, index, 2100)
		samples = append(samples, sample)
	}
	duplicate := append(append([]Sample(nil), samples...), samples[0])
	if _, err := Evaluate(manifest, duplicate, StageScreening, Decision{}); err == nil {
		t.Fatal("duplicate scheduled result accepted")
	}
	samples[0].Payload.SourceSHAReports = 0
	bindSampleArtifact(t, &samples[0], "started-failure-"+samples[0].Run.ID+".json")
	decision, err := Evaluate(manifest, samples, StageScreening, Decision{})
	if err != nil {
		t.Fatalf("started failure was discarded instead of retained: %v", err)
	}
	if decision.Passed {
		t.Fatal("started invalid sample passed decision")
	}
	if len(decision.SampleRefs) != len(samples) {
		t.Fatalf("started failure refs = %v, want retained sample ref", decision.SampleRefs)
	}
}

func TestTournamentRejectsRecoveryAtLimitWithoutThroughputFloor(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	makeSamples := func(t *testing.T) []Sample {
		t.Helper()
		samples := make([]Sample, len(manifest.ManifestInput.Schedules[0].RunIDs))
		for index := range samples {
			samples[index] = validEvidenceSample(t, manifest, index, 1900)
		}
		return samples
	}
	samples := makeSamples(t)
	if decision, err := Evaluate(manifest, samples, StageScreening, Decision{}); err != nil || !decision.Passed {
		t.Fatalf("structurally valid sub-2Gbps tournament sample was rejected: decision=%#v err=%v", decision, err)
	}

	for name, mutate := range map[string]func(*testing.T, *Sample){
		"recovery": func(t *testing.T, sample *Sample) {
			sample.RecoveryRatio = manifest.ManifestInput.Rules.MaxRecovery
			sample.MechanismResult = writeEvidence(t, sample.EvidenceRoot, "mechanism-result", "mechanism-result-at-recovery-limit.json", mechanismResultRecord{
				1, "mechanism-result", sample.Run.ID, "receiver", receiverObserverHost(*sample), sample.Trace.Engine,
				sample.Trace.PublicUDP, sample.Trace.StrictValid, 2, 100, 100, 100,
			})
		},
		"bulk scan": func(t *testing.T, sample *Sample) {
			sample.ScanPerPacket = manifest.ManifestInput.Rules.MaxScanPerPacket
			sample.MechanismResult = writeEvidence(t, sample.EvidenceRoot, "mechanism-result", "mechanism-result-at-scan-limit.json", mechanismResultRecord{
				1, "mechanism-result", sample.Run.ID, "receiver", receiverObserverHost(*sample), sample.Trace.Engine,
				sample.Trace.PublicUDP, sample.Trace.StrictValid, 1, 100, 200, 100,
			})
		},
		"flatline": func(t *testing.T, sample *Sample) {
			sample.FlatlineSeconds = 1
			sample.ReceiverResult = writeEvidence(t, sample.EvidenceRoot, "receiver-result", "receiver-result-at-flatline-limit.json", receiverResultRecord{
				1, "file-result", sample.Run.ID, "receiver", receiverObserverHost(*sample), sample.Run.SizeBytes,
				secondsForMbps(sample.Run.SizeBytes, sample.GoodputMbps), secondsForMbps(sample.Run.SizeBytes, sample.WallGoodputMbps),
				sample.FlatlineSeconds, sample.Started, sample.ObservedAtUTC,
			})
		},
		"Hetz CPU": func(t *testing.T, sample *Sample) {
			seconds := manifest.ManifestInput.Rules.MaxCPUSecondsPerGiB * float64(sample.Run.SizeBytes) / float64(oneGiBBytes)
			sample.Resource.SenderUserSeconds, sample.Resource.SenderSystemSeconds = seconds, 0
			sample.Resource.ReceiverUserSeconds, sample.Resource.ReceiverSystemSeconds = seconds, 0
			sample.Resource.Sender = writeEvidence(t, sample.EvidenceRoot, "resource-sender", "resource-sender-at-cpu-limit.json", resourceEvidenceRecord{1, "resource", sample.Run.ID, "sender", seconds, 0})
			sample.Resource.Receiver = writeEvidence(t, sample.EvidenceRoot, "resource-receiver", "resource-receiver-at-cpu-limit.json", resourceEvidenceRecord{1, "resource", sample.Run.ID, "receiver", seconds, 0})
		},
	} {
		t.Run(name, func(t *testing.T) {
			samples := makeSamples(t)
			mutate(t, &samples[0])
			bindSampleArtifact(t, &samples[0], "tournament-limit-"+samples[0].Run.ID+".json")
			decision, err := Evaluate(manifest, samples, StageScreening, Decision{})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Passed {
				t.Fatalf("tournament ranked a sample at the frozen %s limit", name)
			}
		})
	}
}

func TestEvaluateRejectsOmittedAndExtraFrozenOutcomes(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := bindDecisionArtifact(t, manifest, Decision{
		SchemaVersion:  decisionSchemaVersion,
		ManifestSHA256: canonicalManifestDigest(t, manifest),
		Stage:          StageScreening,
		Passed:         true,
		PeakFrontier:   []string{"challenger", "control"},
	})
	schedule := manifest.ManifestInput.Schedules[1]
	samples := make([]Sample, 0, len(schedule.RunIDs))
	for index := range schedule.RunIDs {
		sample := validEvidenceSample(t, manifest, index%2, 2100)
		bindSampleToFrozenSchedule(t, manifest, &sample, schedule, index)
		sample.Run.PriorDecisionRef = prior.Artifact
		bindSampleArtifact(t, &sample, "prior-bound-"+sample.Run.ID+".json")
		samples = append(samples, sample)
	}
	if _, err := Evaluate(manifest, samples[:len(samples)-1], StagePreliminary, prior); err == nil {
		t.Fatal("dependent decision accepted an omitted frozen outcome")
	}
	extra := append([]Sample(nil), samples...)
	mutated := samples[0]
	mutated.Run.ID = "extra-run"
	extra = append(extra, mutated)
	if _, err := Evaluate(manifest, extra, StagePreliminary, prior); err == nil {
		t.Fatal("dependent decision accepted an extra outcome")
	}
}

func TestFinalistRerunPoolsFrozenOutcomesAndRequiresSameWinner(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	prior := bindDecisionArtifact(t, manifest, Decision{
		SchemaVersion:     decisionSchemaVersion,
		ManifestSHA256:    canonicalManifestDigest(t, manifest),
		Stage:             StageFinalist,
		Passed:            true,
		SelectedCandidate: "challenger",
		PeakFrontier:      []string{"challenger", "control"},
		RerunRequired:     true,
	})
	screeningRef := artifactRefByRole(prior.InputDecisionRefs, string(StageScreening))
	preliminaryRef := artifactRefByRole(prior.InputDecisionRefs, string(StagePreliminary))
	runs, err := BuildSchedule(manifest, StageFinalistRerun, ScheduleAuthorization{Peak: prior})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(runs), len(manifest.ManifestInput.Schedules[3].RunIDs); got != want {
		t.Fatalf("rerun rows = %d, want exact frozen rows %d", got, want)
	}

	makeSamples := func(rerunControlMbps float64) []Sample {
		var samples []Sample
		for scheduleIndex, schedule := range manifest.ManifestInput.Schedules[1:] {
			for index := range schedule.RunIDs {
				goodput := 2200.0
				if schedule.CandidateOrder[index] == "control" {
					goodput = 2100
					if schedule.Stage == string(StageFinalistRerun) {
						goodput = rerunControlMbps
					}
				}
				sample := validEvidenceSample(t, manifest, index%2, goodput)
				bindSampleToFrozenSchedule(t, manifest, &sample, schedule, index)
				switch scheduleIndex {
				case 0:
					sample.Run.PriorDecisionRef = screeningRef
				case 1:
					sample.Run.PriorDecisionRef = preliminaryRef
				case 2:
					sample.Run.PriorDecisionRef = prior.Artifact
				}
				bindSampleArtifact(t, &sample, "prior-bound-"+sample.Run.ID+".json")
				samples = append(samples, sample)
			}
		}
		return samples
	}
	stable, err := Evaluate(manifest, makeSamples(2100), StageFinalistRerun, prior)
	if err != nil || !stable.Passed || stable.SelectedCandidate != "challenger" {
		t.Fatalf("stable rerun decision=%#v err=%v", stable, err)
	}
	changed, err := Evaluate(manifest, makeSamples(4000), StageFinalistRerun, prior)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Passed || !containsReason(changed.Reasons, "pooled rerun winner differs") {
		t.Fatalf("changed pooled winner accepted: %#v", changed)
	}
}

func bindSampleToFrozenSchedule(t *testing.T, manifest Manifest, sample *Sample, schedule FrozenSchedule, index int) {
	t.Helper()
	candidate, ok := manifestCandidate(manifest, schedule.CandidateOrder[index])
	if !ok {
		t.Fatal("candidate missing")
	}
	sample.CandidateID = candidate.ID
	sample.BinarySet = BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}
	sample.Run.ID = schedule.RunIDs[index]
	sample.Run.Stage = stageForFrozenSchedule(schedule.Stage)
	sample.Run.CandidateID = candidate.ID
	sample.Run.HostID = schedule.HostOrder[index]
	sample.Run.Direction = manifestDirection(schedule.DirectionOrder[index])
	sample.Run.Order = index + 1
	sample.Run.Block = schedule.BlockOrder[index]
	sample.Run.Schedule = schedule.Stage
	sample.Run.Role = schedule.RunRoles[index]
	sample.ObservedAtUTC = time.Date(2026, 7, 16, 1, 0, index, 0, time.UTC).Format(time.RFC3339)
	root := sample.EvidenceRoot
	sample.Payload.SourceHashArtifact = writeEvidence(t, root, "source-sha", "source.json", hashEvidenceRecord{
		SchemaVersion: 1, Kind: "hash-observation", RunID: sample.Run.ID, ObserverHostID: sourceObserverHost(*sample), ObserverRole: "source",
		SHA256: sample.Payload.SourceSHA256, Reports: 1,
	})
	sample.Payload.SinkHashArtifact = writeEvidence(t, root, "sink-sha", "sink.json", hashEvidenceRecord{
		SchemaVersion: 1, Kind: "hash-observation", RunID: sample.Run.ID, ObserverHostID: receiverObserverHost(*sample), ObserverRole: "sink",
		SHA256: sample.Payload.SinkSHA256, Reports: 1,
	})
	sample.Payload.SinkSizeArtifact = writeEvidence(t, root, "sink-size", "size.json", sizeEvidenceRecord{1, "size", sample.Run.ID, sample.Payload.SinkSizeBytes})
	sample.Capacity.Direction = sample.Run.Direction
	sample.Capacity.Artifact = writeEvidence(t, root, "capacity", "capacity.json", capacityEvidenceRecord{1, "capacity", sample.Run.ID, sample.Run.Direction, sample.Capacity.Mbps, true})
	sample.Trace.Sender = writeEvidence(t, root, "trace-sender", "trace-sender.json", traceEvidenceRecord{1, "trace", sample.Run.ID, "sender", sample.Run.Direction, sample.Trace.Engine, true, true})
	sample.Trace.Receiver = writeEvidence(t, root, "trace-receiver", "trace-receiver.json", traceEvidenceRecord{1, "trace", sample.Run.ID, "receiver", sample.Run.Direction, sample.Trace.Engine, true, true})
	sample.Resource.Sender = writeEvidence(t, root, "resource-sender", "resource-sender.json", resourceEvidenceRecord{1, "resource", sample.Run.ID, "sender", sample.Resource.SenderUserSeconds, sample.Resource.SenderSystemSeconds})
	sample.Resource.Receiver = writeEvidence(t, root, "resource-receiver", "resource-receiver.json", resourceEvidenceRecord{1, "resource", sample.Run.ID, "receiver", sample.Resource.ReceiverUserSeconds, sample.Resource.ReceiverSystemSeconds})
	sample.Health.Before = writeEvidence(t, root, "health-before", "health-before.json", healthEvidenceRecord{1, "health", sample.Run.ID, "before", true})
	sample.Health.After = writeEvidence(t, root, "health-after", "health-after.json", healthEvidenceRecord{1, "health", sample.Run.ID, "after", true})
	sample.Cleanup.Artifact = writeEvidence(t, root, "cleanup", "cleanup.json", cleanupEvidenceRecord{1, "cleanup", sample.Run.ID, true, true, true, true})
	sample.ReceiverResult = writeEvidence(t, root, "receiver-result", "receiver-result.json", receiverResultRecord{
		SchemaVersion: 1, Kind: "file-result", RunID: sample.Run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(*sample),
		CommittedBytes: sample.Run.SizeBytes, PayloadSeconds: secondsForMbps(sample.Run.SizeBytes, sample.GoodputMbps),
		WallSeconds: secondsForMbps(sample.Run.SizeBytes, sample.WallGoodputMbps), MaxFlatlineSeconds: sample.FlatlineSeconds,
		Started: sample.Started, ObservedAtUTC: sample.ObservedAtUTC,
	})
	sample.MechanismResult = writeEvidence(t, root, "mechanism-result", "mechanism-result.json", mechanismResultRecord{
		SchemaVersion: 1, Kind: "mechanism-result", RunID: sample.Run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(*sample),
		Engine: sample.Trace.Engine, PublicUDP: sample.Trace.PublicUDP, StrictValid: sample.Trace.StrictValid,
		RecoveredUnits: 1, TotalUnits: 100, ScanChecks: 100, PayloadPackets: 100,
	})
	bindSampleArtifact(t, sample, "bound-"+sample.Run.ID+".json")
}

func candidateSummary(id string, localRaw, remoteRaw, localNormalized, remoteNormalized float64) CandidateStatistics {
	return CandidateStatistics{
		CandidateID:          id,
		RawBottleneck:        math.Min(localRaw, remoteRaw),
		NormalizedBottleneck: math.Min(localNormalized, remoteNormalized),
		Directions: []DirectionStatistics{
			{Direction: DirectionLocalToRemote, Raw: Statistics{Median: localRaw}, Normalized: Statistics{Median: localNormalized}},
			{Direction: DirectionRemoteToLocal, Raw: Statistics{Median: remoteRaw}, Normalized: Statistics{Median: remoteNormalized}},
		},
	}
}
