// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"sort"
	"time"
)

type screeningMetrics struct {
	RawMbps       float64 `json:"raw_mbps"`
	Normalized    float64 `json:"normalized"`
	CPUEfficiency float64 `json:"cpu_efficiency"`
}

type timedMetric struct {
	ObservedAt time.Time
	Raw        float64
	Normalized float64
	Block      string
}

type screeningBracket struct {
	before, candidate, after *Sample
}

type fleetProbeRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	HostID        string `json:"host_id"`
	Phase         string `json:"phase"`
	Available     bool   `json:"available"`
	ObservedAtUTC string `json:"observed_at_utc"`
}

type fleetProbeState struct {
	seen      map[string]bool
	available bool
}

// Evaluate produces a deterministic stage decision from immutable samples.
func Evaluate(manifest Manifest, samples []Sample, stage Stage, prior Decision) (Decision, error) {
	if err := ValidateManifest(manifest); err != nil {
		return Decision{}, err
	}
	if !validDecisionStage(stage) {
		return Decision{}, fmt.Errorf("unsupported decision stage %q", stage)
	}
	if err := validateScheduleInputs(manifest, stage, prior); err != nil {
		return Decision{}, err
	}
	return evaluateAuthorized(manifest, samples, stage, prior)
}

func evaluateAuthorized(manifest Manifest, samples []Sample, stage Stage, prior Decision) (Decision, error) {
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return Decision{}, err
	}
	decision := newStageDecision(manifest, manifestDigest, stage, prior)
	validSamples, err := collectDecisionSamples(manifest, samples, stage, prior, &decision)
	if err != nil {
		return Decision{}, err
	}
	statisticsSamples := validSamples
	if stage == StageScreening {
		statisticsSamples = samplesWithRole(validSamples, "candidate")
	}
	decision.Statistics = summarizeCandidates(manifest, statisticsSamples)
	if len(decision.Statistics) == 0 {
		decision.Reasons = append(decision.Reasons, "decision has no valid candidate samples")
	}
	applyStageDecision(manifest, validSamples, &decision)
	finalizeStageDecision(manifest, &decision)
	if stage == StageFinalistRerun && decision.SelectedCandidate != prior.SelectedCandidate {
		decision.Reasons = append(decision.Reasons, "pooled rerun winner differs from original finalist winner")
		sort.Strings(decision.Reasons)
		decision.Reasons = compactStrings(decision.Reasons)
		decision.Passed = false
	}
	return decision, nil
}

func newStageDecision(manifest Manifest, manifestDigest SHA256Digest, stage Stage, prior Decision) Decision {
	inputRefs := cloneArtifactRefs(manifest.ManifestInput.ParentDecisionRefs)
	for _, ref := range prior.InputDecisionRefs {
		if !artifactRefInSlice(ref, inputRefs) {
			inputRefs = append(inputRefs, ref)
		}
	}
	if prior.Artifact != (ArtifactRef{}) && !artifactRefInSlice(prior.Artifact, inputRefs) {
		inputRefs = append(inputRefs, prior.Artifact)
	}
	decision := Decision{
		SchemaVersion:      decisionSchemaVersion,
		ManifestSHA256:     manifestDigest,
		Stage:              stage,
		PeakFrontier:       []string{},
		FinalistCandidates: []string{},
		Reasons:            []string{},
		InputDecisionRefs:  inputRefs,
		SampleRefs:         []ArtifactRef{},
		FleetProbeRefs:     []ArtifactRef{},
		Statistics:         []CandidateStatistics{},
		MaterialEdges:      []MaterialEdge{},
		ClosedCandidates:   append([]string(nil), prior.ClosedCandidates...),
	}
	if stage == StageFinalistRerun {
		decision.FinalistCandidates = append([]string(nil), prior.FinalistCandidates...)
	}
	sortArtifactRefs(decision.InputDecisionRefs)
	return decision
}

func collectDecisionSamples(manifest Manifest, samples []Sample, stage Stage, prior Decision, decision *Decision) ([]Sample, error) {
	ordered := append([]Sample(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Run.ID != ordered[j].Run.ID {
			return ordered[i].Run.ID < ordered[j].Run.ID
		}
		left, _ := sampleArtifactRef(ordered[i])
		right, _ := sampleArtifactRef(ordered[j])
		return left.SHA256 < right.SHA256
	})
	seenRuns := make(map[string]SHA256Digest, len(ordered))
	expectedRuns, err := validateExactDecisionRunSet(manifest, ordered, stage, prior)
	if err != nil {
		return nil, err
	}
	validSamples := make([]Sample, 0, len(ordered))
	for _, sample := range ordered {
		ref, refErr := sampleArtifactRef(sample)
		if refErr != nil {
			return nil, refErr
		}
		if prior, duplicate := seenRuns[sample.Run.ID]; duplicate {
			if prior == ref.SHA256 {
				return nil, fmt.Errorf("duplicate sample for scheduled run %s", sample.Run.ID)
			}
			return nil, fmt.Errorf("replacement sample attempted for scheduled run %s", sample.Run.ID)
		}
		seenRuns[sample.Run.ID] = ref.SHA256
		if sample.Run.PriorDecisionRef != expectedRuns[sample.Run.ID].PriorDecisionRef {
			return nil, fmt.Errorf("run %s prior decision reference mismatch", sample.Run.ID)
		}
		decision.SampleRefs = append(decision.SampleRefs, ref)
		if sampleReasons := validateCollectedDecisionSample(manifest, sample, stage); len(sampleReasons) != 0 {
			decision.Reasons = append(decision.Reasons, prefixReasons(sample.Run.ID, sampleReasons)...)
			continue
		}
		validSamples = append(validSamples, sample)
	}
	return validSamples, nil
}

func validateCollectedDecisionSample(manifest Manifest, sample Sample, stage Stage) []string {
	verdict := ValidateSample(manifest, sample)
	if verdict.Status != "valid" {
		return verdict.Reasons
	}
	if !runStageAllowed(stage, sample.Run.Stage) {
		return []string{fmt.Sprintf("belongs to stage %s, not %s", sample.Run.Stage, stage)}
	}
	return validateTournamentSampleQuality(manifest, sample)
}

func validateTournamentSampleQuality(manifest Manifest, sample Sample) []string {
	checks := []decisionCheck{
		{sample.Started && sample.Capacity.Valid && sample.Capacity.Mbps >= manifest.ManifestInput.Rules.CapacityMinimumMbps && sample.Capacity.Direction == sample.Run.Direction, "tournament sample did not start behind the frozen capacity gate"},
		{sample.RecoveryRatio < manifest.ManifestInput.Rules.MaxRecovery, "tournament recovery is not below limit"},
		{sample.Trace.Engine != "bulk-packets-v1" || sample.ScanPerPacket < manifest.ManifestInput.Rules.MaxScanPerPacket, "tournament bulk scan work is not below limit"},
		{sample.FlatlineSeconds < 1, "tournament payload flatline is not below one second"},
		{cpuPerGiB(sample, manifest) < manifest.ManifestInput.Rules.MaxCPUSecondsPerGiB, "tournament Hetzner-role CPU is not below limit"},
	}
	var reasons []string
	for _, check := range checks {
		if !check.valid {
			reasons = append(reasons, check.reason)
		}
	}
	return reasons
}

func runStageAllowed(decisionStage, runStage Stage) bool {
	if runStage == decisionStage {
		return true
	}
	if decisionStage == StageFinalist {
		return runStage == StagePreliminary
	}
	if decisionStage == StageFinalistRerun {
		return runStage == StagePreliminary || runStage == StageFinalist
	}
	return false
}

func validateExactDecisionRunSet(manifest Manifest, samples []Sample, stage Stage, prior Decision) (map[string]ScheduledRun, error) {
	expected, err := expectedDecisionRuns(manifest, stage, prior)
	if err != nil {
		return nil, err
	}
	want := make(map[string]ScheduledRun, len(expected))
	for _, run := range expected {
		want[run.ID] = run
	}
	got := make(map[string]int, len(samples))
	for _, sample := range samples {
		got[sample.Run.ID]++
	}
	for runID := range want {
		if got[runID] != 1 {
			return nil, fmt.Errorf("scheduled outcome %s count = %d, want exactly one", runID, got[runID])
		}
	}
	for runID := range got {
		if _, ok := want[runID]; !ok {
			return nil, fmt.Errorf("extra outcome %s is not authorized for %s decision", runID, stage)
		}
	}
	return want, nil
}

func expectedDecisionRuns(manifest Manifest, stage Stage, prior Decision) ([]ScheduledRun, error) {
	if stage != StageFinalist && stage != StageFinalistRerun {
		return buildAuthorizedSchedule(manifest, stage, prior)
	}
	candidates, err := scheduleCandidates(manifest, stage, prior)
	if err != nil {
		return nil, err
	}
	preliminaryPrior := artifactRefByRole(prior.InputDecisionRefs, string(StageScreening))
	preliminary, err := frozenRuns(manifest, "preliminary", StagePreliminary, candidates, preliminaryPrior)
	if err != nil {
		return nil, err
	}
	finalistPrior := prior.Artifact
	if stage == StageFinalistRerun {
		finalistPrior = artifactRefByRole(prior.InputDecisionRefs, string(StagePreliminary))
	}
	finalist, err := frozenRuns(manifest, "finalist", StageFinalist, candidates, finalistPrior)
	if err != nil {
		return nil, err
	}
	result := append(preliminary, finalist...)
	if stage == StageFinalistRerun {
		rerun, rerunErr := frozenRuns(manifest, "finalist-rerun", StageFinalistRerun, candidates, prior.Artifact)
		if rerunErr != nil {
			return nil, rerunErr
		}
		result = append(result, rerun...)
	}
	return result, nil
}

func artifactRefByRole(refs []ArtifactRef, role string) ArtifactRef {
	for _, ref := range refs {
		if ref.Role == role {
			return ref
		}
	}
	return ArtifactRef{}
}

func applyStageDecision(manifest Manifest, validSamples []Sample, decision *Decision) {
	switch decision.Stage {
	case StageScreening:
		decision.PeakFrontier = screeningSurvivors(validSamples)
		decision.PeakFrontier = uniqueSortedCandidates(append(decision.PeakFrontier, manifest.ManifestInput.ScreeningControlID))
	case StagePreliminary:
		decision.PeakFrontier = selectPreliminaryCandidates(decision.Statistics, manifest.ManifestInput.Rules.FinalistDelta)
	case StageFinalist:
		decision.MaterialEdges = materialEdges(decision.Statistics, validSamples, manifest.ManifestInput.Rules.MaterialDelta)
		candidateIDs := candidateIDsFromStatistics(decision.Statistics)
		decision.FinalistCandidates = append([]string(nil), candidateIDs...)
		decision.PeakFrontier = PeakFrontier(candidateIDs, decision.MaterialEdges)
		validateFinalistVariation(decision, manifest)
	case StageFinalistRerun:
		decision.MaterialEdges = materialEdges(decision.Statistics, validSamples, manifest.ManifestInput.Rules.MaterialDelta)
		decision.PeakFrontier = PeakFrontier(candidateIDsFromStatistics(decision.Statistics), decision.MaterialEdges)
		validateFinalistVariation(decision, manifest)
	case StageProduction, StageFleet:
		decision.PeakFrontier = candidateIDsFromStatistics(decision.Statistics)
	case StageCeiling, StageAcceptance:
		decision.Reasons = append(decision.Reasons, "stage requires its dedicated decision function")
	}
}

func finalizeStageDecision(manifest Manifest, decision *Decision) {
	if decision.Stage == StageFinalist && capacityVariationExceeds(decision.Statistics, manifest.ManifestInput.Rules.MaxCV) {
		decision.RerunRequired = true
	}
	decision.SelectedCandidate = rankFrontier(decision.PeakFrontier, decision.Statistics)
	if decision.SelectedCandidate != "" {
		if candidate, ok := manifestCandidate(manifest, decision.SelectedCandidate); ok {
			decision.BinarySet = BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}
		}
	}
	frontierSet := make(map[string]bool, len(decision.PeakFrontier))
	for _, candidate := range decision.PeakFrontier {
		frontierSet[candidate] = true
	}
	for _, candidate := range candidateIDsFromStatistics(decision.Statistics) {
		if !frontierSet[candidate] {
			decision.ClosedCandidates = append(decision.ClosedCandidates, candidate)
		}
	}
	sort.Strings(decision.PeakFrontier)
	sort.Strings(decision.FinalistCandidates)
	sort.Strings(decision.ClosedCandidates)
	decision.ClosedCandidates = compactStrings(decision.ClosedCandidates)
	sort.Slice(decision.MaterialEdges, func(i, j int) bool {
		if decision.MaterialEdges[i].From != decision.MaterialEdges[j].From {
			return decision.MaterialEdges[i].From < decision.MaterialEdges[j].From
		}
		return decision.MaterialEdges[i].To < decision.MaterialEdges[j].To
	})
	sort.Strings(decision.Reasons)
	decision.Reasons = compactStrings(decision.Reasons)
	decision.Passed = len(decision.Reasons) == 0 && decision.SelectedCandidate != ""
}

func samplesWithRole(samples []Sample, role string) []Sample {
	var filtered []Sample
	for _, sample := range samples {
		if sample.Run.Role == role {
			filtered = append(filtered, sample)
		}
	}
	return filtered
}

func screeningSurvivors(samples []Sample) []string {
	brackets := make(map[int]*screeningBracket)
	for index := range samples {
		sample := &samples[index]
		if brackets[sample.Run.Block] == nil {
			brackets[sample.Run.Block] = &screeningBracket{}
		}
		addScreeningSample(brackets[sample.Run.Block], sample)
	}
	var survivors []string
	for _, active := range brackets {
		if candidate, survives := survivingScreeningCandidate(active, brackets); survives {
			survivors = append(survivors, candidate)
		}
	}
	return uniqueSortedCandidates(survivors)
}

func addScreeningSample(bracket *screeningBracket, sample *Sample) {
	switch sample.Run.Role {
	case "control-before":
		bracket.before = sample
	case "candidate":
		bracket.candidate = sample
	case "control-after":
		bracket.after = sample
	}
}

func survivingScreeningCandidate(active *screeningBracket, brackets map[int]*screeningBracket) (string, bool) {
	if active.candidate == nil {
		return "", false
	}
	complete := active.before != nil && active.after != nil
	return active.candidate.CandidateID, !complete || !screeningCandidateDominated(*active, brackets)
}

func screeningCandidateDominated(active screeningBracket, brackets map[int]*screeningBracket) bool {
	challenger := screeningSampleMetrics(*active.candidate)
	for _, other := range brackets {
		if other.candidate == nil || other.candidate.CandidateID == active.candidate.CandidateID {
			continue
		}
		if !screeningBracketStable(*other) {
			continue
		}
		if screeningEliminated(active.before.GoodputMbps, active.after.GoodputMbps, challenger, screeningSampleMetrics(*other.candidate)) {
			return true
		}
	}
	return false
}

func screeningBracketStable(bracket screeningBracket) bool {
	if bracket.before == nil || bracket.candidate == nil || bracket.after == nil {
		return false
	}
	before, after := bracket.before.GoodputMbps, bracket.after.GoodputMbps
	return finitePositive(before) && finitePositive(after) && math.Abs(after-before)/math.Min(before, after) <= 0.03
}

func screeningSampleMetrics(sample Sample) screeningMetrics {
	cpu := sample.Resource.SenderUserSeconds + sample.Resource.SenderSystemSeconds
	if sample.Run.Direction == DirectionLocalToRemote {
		cpu = sample.Resource.ReceiverUserSeconds + sample.Resource.ReceiverSystemSeconds
	}
	efficiency := 0.0
	if cpu > 0 {
		efficiency = sample.GoodputMbps / cpu
	}
	return screeningMetrics{RawMbps: sample.GoodputMbps, Normalized: sample.GoodputMbps / sample.Capacity.Mbps, CPUEfficiency: efficiency}
}

// DecidePrerequisite evaluates the exact six-sample 1 GiB production gate.
func DecidePrerequisite(manifest Manifest, samples []Sample) PrerequisiteDecision {
	decision := newPrerequisiteDecision(manifest, len(samples))
	byDirection := map[Direction][]float64{DirectionLocalToRemote: {}, DirectionRemoteToLocal: {}}
	seenRuns := make(map[string]SHA256Digest, len(samples))
	for _, sample := range samples {
		recordPrerequisiteSample(manifest, sample, &decision, seenRuns, byDirection)
	}
	sortArtifactRefs(decision.Samples)
	decision.Reasons = append(decision.Reasons, validatePrerequisiteDirections(byDirection, manifest.ManifestInput.Rules.MaxCV)...)
	sort.Strings(decision.Reasons)
	decision.Reasons = compactStrings(decision.Reasons)
	decision.Passed = len(decision.Reasons) == 0
	return decision
}

func newPrerequisiteDecision(manifest Manifest, sampleCount int) PrerequisiteDecision {
	decision := PrerequisiteDecision{
		SchemaVersion:     decisionSchemaVersion,
		InputDecisionRefs: cloneArtifactRefs(manifest.ManifestInput.ParentDecisionRefs),
		Samples:           []ArtifactRef{},
		Reasons:           []string{},
	}
	digest, digestErr := canonicalDigest(manifest)
	decision.ManifestSHA256 = digest
	if digestErr != nil {
		decision.Reasons = append(decision.Reasons, digestErr.Error())
	}
	if err := ValidateManifest(manifest); err != nil {
		decision.Reasons = append(decision.Reasons, "invalid production manifest: "+err.Error())
	}
	if manifest.ManifestInput.Kind != ManifestProduction {
		decision.Reasons = append(decision.Reasons, "prerequisite requires production manifest")
	}
	if err := verifyProductionAuthorization(manifest); err != nil {
		decision.Reasons = append(decision.Reasons, "production authorization: "+err.Error())
	}
	if len(manifest.ManifestInput.Candidates) != 1 {
		decision.Reasons = append(decision.Reasons, "prerequisite requires exactly one candidate and binary set")
	} else {
		candidate := manifest.ManifestInput.Candidates[0]
		decision.CandidateID = candidate.ID
		decision.BinarySet = BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}
	}
	if sampleCount != 6 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("prerequisite sample count = %d, want exactly 6", sampleCount))
	}
	return decision
}

func recordPrerequisiteSample(manifest Manifest, sample Sample, decision *PrerequisiteDecision, seenRuns map[string]SHA256Digest, byDirection map[Direction][]float64) {
	ref, err := sampleArtifactRef(sample)
	if err != nil {
		decision.Reasons = append(decision.Reasons, "sample artifact: "+err.Error())
		return
	}
	if previous, duplicate := seenRuns[sample.Run.ID]; duplicate {
		decision.Reasons = append(decision.Reasons, duplicatePrerequisiteReason(sample.Run.ID, previous, ref.SHA256))
		return
	}
	seenRuns[sample.Run.ID] = ref.SHA256
	decision.Samples = append(decision.Samples, ref)
	decision.Reasons = append(decision.Reasons, validatePrerequisiteSample(manifest, sample, *decision)...)
	if validDirectionValue(sample.Run.Direction) {
		byDirection[sample.Run.Direction] = append(byDirection[sample.Run.Direction], sample.GoodputMbps)
	}
}

func duplicatePrerequisiteReason(runID string, previous, current SHA256Digest) string {
	if previous != current {
		return "replacement sample attempted for run " + runID
	}
	return "duplicate sample for run " + runID
}

func validatePrerequisiteSample(manifest Manifest, sample Sample, decision PrerequisiteDecision) []string {
	var reasons []string
	if sample.CandidateID != decision.CandidateID || sample.BinarySet != decision.BinarySet {
		reasons = append(reasons, "sample candidate or binary set mismatch")
	}
	if sample.ManifestSHA256 != decision.ManifestSHA256 {
		reasons = append(reasons, "sample production manifest mismatch")
	}
	if sample.Run.PriorDecisionRef != artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, "finalist") {
		reasons = append(reasons, "production sample prior decision reference mismatch")
	}
	if verdict := ValidateSample(manifest, sample); verdict.Status != "valid" {
		reasons = append(reasons, verdict.Reasons...)
	}
	reasons = append(reasons, validatePrerequisiteMetrics(manifest, sample)...)
	return reasons
}

func validatePrerequisiteMetrics(manifest Manifest, sample Sample) []string {
	checks := []decisionCheck{
		{sample.Run.Stage == StageProduction, "prerequisite sample is not production stage"},
		{sample.Run.SizeBytes == oneGiBBytes, "prerequisite sample is not exactly 1 GiB"},
		{sample.Started && sample.Capacity.Valid && sample.Capacity.Mbps >= manifest.ManifestInput.Rules.CapacityMinimumMbps, "sample did not start behind the frozen capacity gate"},
		{sample.GoodputMbps > manifest.ManifestInput.Rules.FileMinimumMbps, "sample does not exceed 2.0 Gbps"},
		{sample.RecoveryRatio < manifest.ManifestInput.Rules.MaxRecovery, "sample recovery is not below limit"},
		{sample.Trace.Engine != "bulk-packets-v1" || sample.ScanPerPacket < manifest.ManifestInput.Rules.MaxScanPerPacket, "bulk scan work is not below limit"},
		{sample.FlatlineSeconds < 1, "payload flatline is not below one second"},
		{cpuPerGiB(sample, manifest) < manifest.ManifestInput.Rules.MaxCPUSecondsPerGiB, "Hetzner-role CPU is not below limit"},
	}
	var reasons []string
	for _, check := range checks {
		if !check.valid {
			reasons = append(reasons, check.reason)
		}
	}
	return reasons
}

type decisionCheck struct {
	valid  bool
	reason string
}

func validatePrerequisiteDirections(byDirection map[Direction][]float64, maxCV float64) []string {
	var reasons []string
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		values := byDirection[direction]
		if len(values) != 3 {
			reasons = append(reasons, fmt.Sprintf("%s sample count = %d, want 3", direction, len(values)))
			continue
		}
		if statistics(values).CoefficientOfVariation > maxCV {
			reasons = append(reasons, string(direction)+" goodput CV exceeds limit")
		}
	}
	return reasons
}

// DecideFleet proves the exact prerequisite-authorized fleet schedule and probe set.
func DecideFleet(inputs FleetInputs) Decision {
	decision := newFleetDecision(inputs)
	decision.Reasons = append(decision.Reasons, validateFleetBindings(inputs, decision.ManifestSHA256)...)
	bindFleetCandidate(inputs, &decision)
	validSamples := collectFleetSampleRefs(inputs.Samples, &decision)
	sortArtifactRefs(decision.SampleRefs)
	sortArtifactRefs(decision.FleetProbeRefs)
	decision.Reasons = append(decision.Reasons, validateFleetDecisionEvidence(inputs.EvidenceRoot, inputs.Manifest, decision, inputs.PrerequisiteRef)...)
	decision.Statistics = summarizeCandidates(inputs.Manifest, validSamples)
	sort.Strings(decision.Reasons)
	decision.Reasons = compactStrings(decision.Reasons)
	decision.Passed = len(decision.Reasons) == 0
	return decision
}

func newFleetDecision(inputs FleetInputs) Decision {
	decision := Decision{
		SchemaVersion: decisionSchemaVersion, Stage: StageFleet, PeakFrontier: []string{}, Reasons: []string{},
		InputDecisionRefs: []ArtifactRef{inputs.PrerequisiteRef}, SampleRefs: []ArtifactRef{},
		FleetProbeRefs: cloneArtifactRefs(inputs.ProbeRefs), Statistics: []CandidateStatistics{},
		MaterialEdges: []MaterialEdge{}, ClosedCandidates: []string{}, EvidenceRoot: inputs.EvidenceRoot,
	}
	decision.ManifestSHA256, _ = canonicalDigest(inputs.Manifest)
	return decision
}

func validateFleetBindings(inputs FleetInputs, manifestDigest SHA256Digest) []string {
	var reasons []string
	if err := ValidateManifest(inputs.Manifest); err != nil || inputs.Manifest.ManifestInput.Kind != ManifestProduction {
		reasons = append(reasons, "fleet requires a valid production manifest")
	}
	if err := validateArtifactRef(inputs.ManifestRef, "manifest"); err != nil || inputs.ManifestRef.SHA256 != manifestDigest {
		reasons = append(reasons, "fleet manifest reference does not identify exact production manifest")
	}
	if err := validateTypedDecisionRef(inputs.PrerequisiteRef, "prerequisite", inputs.Prerequisite); err != nil {
		reasons = append(reasons, err.Error())
	} else if err := verifyFleetAuthorization(inputs.Manifest, manifestDigest, inputs.Prerequisite, inputs.PrerequisiteRef.SHA256); err != nil {
		reasons = append(reasons, "fleet prerequisite proof: "+err.Error())
	}
	return reasons
}

func verifyFleetAuthorization(manifest Manifest, manifestDigest SHA256Digest, decision PrerequisiteDecision, decisionDigest SHA256Digest) error {
	if err := VerifyPrerequisite(manifest, manifestDigest, decision, decisionDigest, decision.BinarySet); err == nil {
		return nil
	}
	return verifyHardCeilingFleetAuthorization(manifest, manifestDigest, decision, decisionDigest)
}

func verifyHardCeilingFleetAuthorization(manifest Manifest, manifestDigest SHA256Digest, decision PrerequisiteDecision, decisionDigest SHA256Digest) error {
	if err := verifyManifestBinding(manifest, manifestDigest, decision.ManifestSHA256); err != nil {
		return err
	}
	wantDigest, err := canonicalDigest(decision)
	if err != nil || wantDigest != decisionDigest {
		return fmt.Errorf("fleet guard prerequisite digest binding mismatch")
	}
	decoded, err := reopenPrerequisiteDecision(decision, decisionDigest)
	if err != nil {
		return err
	}
	if decoded.Passed || !reflect.DeepEqual(decoded.Reasons, []string{"sample does not exceed 2.0 Gbps"}) {
		return fmt.Errorf("fleet guard requires the throughput threshold to be the only prerequisite failure")
	}
	if err := verifyPrerequisiteIdentity(manifest, decoded, decoded.BinarySet); err != nil {
		return err
	}
	samples, err := loadPrerequisiteSamples(decision.EvidenceRoot, decoded.Samples)
	if err != nil {
		return err
	}
	if recomputed := DecidePrerequisite(manifest, samples); !reflect.DeepEqual(recomputed, decoded) {
		return fmt.Errorf("fleet guard prerequisite does not replay from exact samples")
	}
	return nil
}

func loadPrerequisiteSamples(root string, refs []ArtifactRef) ([]Sample, error) {
	samples := make([]Sample, 0, len(refs))
	for _, ref := range refs {
		sample, err := LoadSampleArtifact(root, ref)
		if err != nil {
			return nil, fmt.Errorf("fleet guard prerequisite sample: %w", err)
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

func bindFleetCandidate(inputs FleetInputs, decision *Decision) {
	if len(inputs.Manifest.ManifestInput.Candidates) != 1 {
		decision.Reasons = append(decision.Reasons, "fleet production manifest must contain exactly one candidate")
		return
	}
	candidate := inputs.Manifest.ManifestInput.Candidates[0]
	decision.SelectedCandidate = candidate.ID
	decision.PeakFrontier = []string{candidate.ID}
	decision.BinarySet = BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}
	if inputs.Prerequisite.CandidateID != candidate.ID || inputs.Prerequisite.BinarySet != decision.BinarySet {
		decision.Reasons = append(decision.Reasons, "fleet prerequisite candidate or binaries differ from production manifest")
	}
}

func collectFleetSampleRefs(samples []Sample, decision *Decision) []Sample {
	valid := make([]Sample, 0, len(samples))
	for _, sample := range samples {
		ref, err := sampleArtifactRef(sample)
		if err != nil {
			decision.Reasons = append(decision.Reasons, "fleet sample artifact: "+err.Error())
			continue
		}
		decision.SampleRefs = append(decision.SampleRefs, ref)
		valid = append(valid, sample)
	}
	return valid
}

// DecideAcceptance evaluates the exact six-run 3 GiB acceptance gate.
func DecideAcceptance(inputs AcceptanceInputs) Decision {
	decision := newAcceptanceDecision(inputs.Manifest)
	candidate := validateAcceptanceInputs(inputs, &decision)
	validSamples, byDirection := collectAcceptanceSamples(inputs, candidate, &decision)
	sortArtifactRefs(decision.SampleRefs)
	decision.Statistics = summarizeCandidates(inputs.Manifest, validSamples)
	decision.Reasons = append(decision.Reasons, validateAcceptanceDirections(byDirection, inputs.Manifest.ManifestInput.Rules.MaxCV)...)
	sort.Strings(decision.Reasons)
	decision.Reasons = compactStrings(decision.Reasons)
	decision.Passed = len(decision.Reasons) == 0
	decision.AcceptanceMet = decision.Passed
	return decision
}

func newAcceptanceDecision(manifest Manifest) Decision {
	decision := Decision{
		SchemaVersion:     decisionSchemaVersion,
		Stage:             StageAcceptance,
		PeakFrontier:      []string{},
		Reasons:           []string{},
		InputDecisionRefs: []ArtifactRef{},
		SampleRefs:        []ArtifactRef{},
		FleetProbeRefs:    []ArtifactRef{},
		Statistics:        []CandidateStatistics{},
		MaterialEdges:     []MaterialEdge{},
		ClosedCandidates:  []string{},
	}
	manifestDigest, digestErr := canonicalDigest(manifest)
	decision.ManifestSHA256 = manifestDigest
	if digestErr != nil {
		decision.Reasons = append(decision.Reasons, digestErr.Error())
	}
	decision.InputDecisionRefs = cloneArtifactRefs(manifest.ManifestInput.ParentDecisionRefs)
	return decision
}

func validateAcceptanceInputs(inputs AcceptanceInputs, decision *Decision) CandidateIdentity {
	validateAcceptanceManifest(inputs, decision)
	validateAcceptanceParentRefs(inputs, decision)
	validateAcceptanceParentProofs(inputs, decision)
	return bindAcceptanceCandidate(inputs, decision)
}

func validateAcceptanceManifest(inputs AcceptanceInputs, decision *Decision) {
	if err := ValidateManifest(inputs.Manifest); err != nil || inputs.Manifest.ManifestInput.Kind != ManifestAcceptance {
		decision.Reasons = append(decision.Reasons, "acceptance requires a valid acceptance manifest")
	}
	if err := validateArtifactRef(inputs.ManifestRef, "manifest"); err != nil || inputs.ManifestRef.SHA256 != decision.ManifestSHA256 {
		decision.Reasons = append(decision.Reasons, "acceptance manifest reference does not identify typed manifest")
	}
	if _, err := verifyChildManifestAuthorization(inputs.Manifest, ManifestAcceptance); err != nil {
		decision.Reasons = append(decision.Reasons, "acceptance manifest authorization: "+err.Error())
	}
}

func validateAcceptanceParentRefs(inputs AcceptanceInputs, decision *Decision) {
	if err := validateTypedDecisionRef(inputs.PrerequisiteRef, "prerequisite", inputs.Prerequisite); err != nil {
		decision.Reasons = append(decision.Reasons, err.Error())
	}
	if err := validateTypedDecisionRef(inputs.FleetRef, "fleet", inputs.Fleet); err != nil {
		decision.Reasons = append(decision.Reasons, err.Error())
	}
	if !artifactRefInSlice(inputs.PrerequisiteRef, decision.InputDecisionRefs) {
		decision.Reasons = append(decision.Reasons, "prerequisite reference is not the exact manifest-bound decision")
	}
	if !artifactRefInSlice(inputs.FleetRef, decision.InputDecisionRefs) {
		decision.Reasons = append(decision.Reasons, "fleet reference is not the exact manifest-bound decision")
	}
	if _, err := reopenPrerequisiteDecision(inputs.Prerequisite, inputs.PrerequisiteRef.SHA256); err != nil {
		decision.Reasons = append(decision.Reasons, "acceptance prerequisite artifact: "+err.Error())
	}
	if err := verifyExactDecisionValue(inputs.Fleet, inputs.FleetRef, "fleet"); err != nil {
		decision.Reasons = append(decision.Reasons, "acceptance fleet artifact: "+err.Error())
	}
}

func verifyExactDecisionValue(decision Decision, ref ArtifactRef, role string) error {
	if decision.Artifact != ref {
		return fmt.Errorf("decision artifact reference mismatch")
	}
	var decoded Decision
	if err := verifyDecodeEvidence(decision.EvidenceRoot, ref, role, &decoded); err != nil {
		return err
	}
	want := decision
	want.Artifact = ArtifactRef{}
	want.EvidenceRoot = ""
	if !reflect.DeepEqual(decoded, want) {
		return fmt.Errorf("decision value differs from exact artifact")
	}
	return nil
}

func validateAcceptanceParentProofs(inputs AcceptanceInputs, decision *Decision) {
	decision.Reasons = append(decision.Reasons, validateAcceptancePrerequisiteParent(inputs)...)
	decision.Reasons = append(decision.Reasons, validateAcceptanceFleetParent(inputs)...)
	decision.Reasons = append(decision.Reasons, validateAcceptanceParentAncestry(inputs)...)
	decision.Reasons = append(decision.Reasons, validateFleetProbeProof(inputs)...)
}

func validateAcceptancePrerequisiteParent(inputs AcceptanceInputs) []string {
	if !inputs.Prerequisite.Passed || len(inputs.Prerequisite.Reasons) != 0 || len(inputs.Prerequisite.Samples) != 6 {
		return []string{"prerequisite decision did not prove exact six-run production gate"}
	}
	return nil
}

func validateAcceptanceFleetParent(inputs AcceptanceInputs) []string {
	var reasons []string
	if !inputs.Fleet.Passed || len(inputs.Fleet.Reasons) != 0 || inputs.Fleet.Stage != StageFleet {
		reasons = append(reasons, "fleet decision did not pass")
	}
	if !artifactRefInSlice(inputs.PrerequisiteRef, inputs.Fleet.InputDecisionRefs) {
		reasons = append(reasons, "fleet decision did not consume exact prerequisite")
	}
	return reasons
}

func validateAcceptanceParentAncestry(inputs AcceptanceInputs) []string {
	parent := inputs.Manifest.ManifestInput.ParentManifest
	if parent != nil && (inputs.Prerequisite.ManifestSHA256 != parent.SHA256 || inputs.Fleet.ManifestSHA256 != parent.SHA256) {
		return []string{"acceptance parent decision manifest ancestry mismatch"}
	}
	return nil
}

func validateFleetProbeProof(inputs AcceptanceInputs) []string {
	if inputs.Manifest.EvidenceRoot == "" || inputs.Manifest.ManifestInput.ParentManifest == nil {
		return []string{"acceptance production manifest evidence root is not bound"}
	}
	var production Manifest
	if err := verifyDecodeEvidence(inputs.Manifest.EvidenceRoot, *inputs.Manifest.ManifestInput.ParentManifest, "manifest", &production); err != nil {
		return []string{"acceptance production manifest artifact: " + err.Error()}
	}
	return replayFleetDecision(inputs.Manifest.EvidenceRoot, production, *inputs.Manifest.ManifestInput.ParentManifest, inputs.Fleet)
}

func replayFleetDecision(root string, production Manifest, productionRef ArtifactRef, fleet Decision) []string {
	production.EvidenceRoot = root
	prerequisiteRef := artifactRefByRole(fleet.InputDecisionRefs, "prerequisite")
	var prerequisite PrerequisiteDecision
	if err := verifyDecodeEvidence(root, prerequisiteRef, "prerequisite", &prerequisite); err != nil {
		return []string{"fleet prerequisite decision artifact: " + err.Error()}
	}
	prerequisite.Artifact = prerequisiteRef
	prerequisite.EvidenceRoot = root
	productionDigest, err := canonicalDigest(production)
	if err != nil {
		return []string{"fleet production manifest digest: " + err.Error()}
	}
	if err := verifyFleetAuthorization(production, productionDigest, prerequisite, prerequisiteRef.SHA256); err != nil {
		return []string{"fleet prerequisite proof: " + err.Error()}
	}
	samples := make([]Sample, 0, len(fleet.SampleRefs))
	for _, ref := range fleet.SampleRefs {
		sample, loadErr := LoadSampleArtifact(root, ref)
		if loadErr != nil {
			return []string{"fleet sample artifact: " + loadErr.Error()}
		}
		samples = append(samples, sample)
	}
	recomputed := DecideFleet(FleetInputs{
		Manifest: production, ManifestRef: productionRef, Prerequisite: prerequisite,
		PrerequisiteRef: prerequisiteRef, ProbeRefs: fleet.FleetProbeRefs,
		Samples: samples, EvidenceRoot: root,
	})
	recomputed.EvidenceRoot = ""
	want := fleet
	want.Artifact = ArtifactRef{}
	want.EvidenceRoot = ""
	if !reflect.DeepEqual(recomputed, want) {
		return []string{"fleet decision does not replay from exact prerequisite, probe, and sample artifacts"}
	}
	return nil
}

func validateFleetDecisionEvidence(root string, production Manifest, fleet Decision, prerequisiteRef ArtifactRef) []string {
	want := expectedFleetProbeStates(production)
	var reasons []string
	for _, ref := range fleet.FleetProbeRefs {
		reasons = append(reasons, applyFleetProbe(root, ref, want)...)
	}
	mandatoryHosts, completenessReasons := mandatoryFleetHosts(want)
	reasons = append(reasons, completenessReasons...)
	reasons = append(reasons, validateFleetSamples(root, production, fleet, prerequisiteRef, mandatoryHosts)...)
	return reasons
}

func expectedFleetProbeStates(production Manifest) map[string]*fleetProbeState {
	want := make(map[string]*fleetProbeState)
	for _, host := range production.ManifestInput.FleetInventory {
		if host.Role != HostRolePrimary {
			want[host.ID] = &fleetProbeState{seen: map[string]bool{"initial": false, "recheck": false}}
		}
	}
	return want
}

func applyFleetProbe(root string, ref ArtifactRef, want map[string]*fleetProbeState) []string {
	var record fleetProbeRecord
	if err := verifyDecodeEvidence(root, ref, "fleet-probe", &record); err != nil {
		return []string{"fleet probe artifact: " + err.Error()}
	}
	state, ok := want[record.HostID]
	validPhase := record.Phase == "initial" || record.Phase == "recheck"
	validIdentity := ok && validPhase && !state.seen[record.Phase] && record.SchemaVersion == 1 &&
		record.Kind == "fleet-probe" && validCanonicalTime(record.ObservedAtUTC)
	if !validIdentity {
		return []string{"fleet probe identity or phase mismatch"}
	}
	state.seen[record.Phase] = true
	state.available = state.available || record.Available
	return nil
}

func mandatoryFleetHosts(states map[string]*fleetProbeState) (map[string]bool, []string) {
	hosts := make(map[string]bool)
	var reasons []string
	for hostID, state := range states {
		if !state.seen["initial"] || !state.seen["recheck"] {
			reasons = append(reasons, "fleet probes incomplete for host "+hostID)
		}
		hosts[hostID] = state.available
	}
	return hosts, reasons
}

func validateFleetSamples(root string, production Manifest, fleet Decision, prerequisiteRef ArtifactRef, mandatoryHosts map[string]bool) []string {
	expected := expectedFleetRuns(production, mandatoryHosts)
	seen := make(map[string]bool)
	var reasons []string
	for _, ref := range fleet.SampleRefs {
		runID, sampleReasons := validateFleetSample(root, production, ref, prerequisiteRef, expected, seen)
		reasons = append(reasons, sampleReasons...)
		if len(sampleReasons) == 0 {
			delete(expected, runID)
		}
	}
	for runID := range expected {
		reasons = append(reasons, "missing mandatory frozen fleet sample "+runID)
	}
	reasons = append(reasons, validateFleetStability(root, fleet.SampleRefs, production.ManifestInput.Rules.MaxCV)...)
	return reasons
}

func expectedFleetRuns(production Manifest, mandatoryHosts map[string]bool) map[string]string {
	expected := make(map[string]string)
	for _, schedule := range production.ManifestInput.Schedules {
		if schedule.Stage != string(StageFleet) {
			continue
		}
		for index, runID := range schedule.RunIDs {
			hostID := schedule.HostOrder[index]
			if mandatoryHosts[hostID] {
				expected[runID] = hostID
			}
		}
	}
	return expected
}

func validateFleetSample(root string, production Manifest, ref, prerequisiteRef ArtifactRef, expected map[string]string, seen map[string]bool) (string, []string) {
	sample, err := LoadSampleArtifact(root, ref)
	if err != nil {
		return "", []string{"fleet sample artifact: " + err.Error()}
	}
	if seen[sample.Run.ID] {
		return "", []string{"duplicate or replacement fleet sample for run " + sample.Run.ID}
	}
	seen[sample.Run.ID] = true
	hostID, scheduled := expected[sample.Run.ID]
	if !scheduled || !fleetRunIdentityMatches(sample.Run, hostID) {
		return "", []string{"fleet sample does not belong to a mandatory frozen host run"}
	}
	if sample.Run.PriorDecisionRef != prerequisiteRef {
		return "", []string{"fleet sample prior decision reference mismatch"}
	}
	verdict := ValidateSample(production, sample)
	if verdict.Status != "valid" {
		return "", prefixReasons(sample.Run.ID, verdict.Reasons)
	}
	if reasons := validateFleetPerformance(production, sample); len(reasons) != 0 {
		return "", prefixReasons(sample.Run.ID, reasons)
	}
	return sample.Run.ID, nil
}

func validateFleetPerformance(manifest Manifest, sample Sample) []string {
	var reasons []string
	if !sample.Started || !finitePositive(sample.Capacity.Mbps) {
		reasons = append(reasons, "fleet sample lacks positive same-run capacity")
	}
	if sample.RecoveryRatio >= manifest.ManifestInput.Rules.MaxRecovery {
		reasons = append(reasons, "fleet recovery is not below limit")
	}
	if sample.Trace.Engine == "bulk-packets-v1" && sample.ScanPerPacket >= manifest.ManifestInput.Rules.MaxScanPerPacket {
		reasons = append(reasons, "fleet bulk scan work is not below limit")
	}
	if sample.FlatlineSeconds >= 1 {
		reasons = append(reasons, "fleet payload flatline is not below one second")
	}
	if cpuPerGiB(sample, manifest) >= manifest.ManifestInput.Rules.MaxCPUSecondsPerGiB {
		reasons = append(reasons, "fleet Hetzner-role CPU is not below limit")
	}
	return reasons
}

func validateFleetStability(root string, refs []ArtifactRef, maxCV float64) []string {
	groups := make(map[string][]float64)
	for _, ref := range refs {
		sample, err := LoadSampleArtifact(root, ref)
		if err != nil || !finitePositive(sample.Capacity.Mbps) {
			continue
		}
		key := sample.Run.HostID + "\x00" + string(sample.Run.Direction)
		groups[key] = append(groups[key], sample.GoodputMbps/sample.Capacity.Mbps)
	}
	var reasons []string
	for key, values := range groups {
		if len(values) != 3 || statistics(values).CoefficientOfVariation > maxCV {
			reasons = append(reasons, "fleet normalized stability failed for "+key)
		}
	}
	return reasons
}

func fleetRunIdentityMatches(run ScheduledRun, hostID string) bool {
	return run.HostID == hostID && run.Stage == StageFleet && run.Schedule == string(StageFleet)
}

func bindAcceptanceCandidate(inputs AcceptanceInputs, decision *Decision) CandidateIdentity {
	var candidate CandidateIdentity
	if len(inputs.Manifest.ManifestInput.Candidates) != 1 {
		decision.Reasons = append(decision.Reasons, "acceptance manifest must contain exactly one candidate")
		return CandidateIdentity{}
	}
	candidate = inputs.Manifest.ManifestInput.Candidates[0]
	decision.SelectedCandidate = candidate.ID
	decision.BinarySet = BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}
	decision.PeakFrontier = []string{candidate.ID}
	if !acceptancePriorIdentitiesMatch(inputs, candidate, decision.BinarySet) {
		decision.Reasons = append(decision.Reasons, "prior decision candidate or binary set does not match acceptance manifest")
	}
	return candidate
}

func acceptancePriorIdentitiesMatch(inputs AcceptanceInputs, candidate CandidateIdentity, binaries BinarySet) bool {
	return inputs.Prerequisite.CandidateID == candidate.ID && inputs.Prerequisite.BinarySet == binaries &&
		inputs.Fleet.SelectedCandidate == candidate.ID && inputs.Fleet.BinarySet == binaries
}

func collectAcceptanceSamples(inputs AcceptanceInputs, candidate CandidateIdentity, decision *Decision) ([]Sample, map[Direction][]float64) {
	if len(inputs.Samples) != 6 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("acceptance sample count = %d, want exactly 6", len(inputs.Samples)))
	}
	ordered := append([]Sample(nil), inputs.Samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Run.ID < ordered[j].Run.ID })
	seen := make(map[string]SHA256Digest, len(ordered))
	byDirection := map[Direction][]float64{DirectionLocalToRemote: {}, DirectionRemoteToLocal: {}}
	validSamples := make([]Sample, 0, len(ordered))
	for _, sample := range ordered {
		if !recordAcceptanceSample(inputs, candidate, sample, decision, seen, byDirection) {
			continue
		}
		validSamples = append(validSamples, sample)
	}
	return validSamples, byDirection
}

func recordAcceptanceSample(inputs AcceptanceInputs, candidate CandidateIdentity, sample Sample, decision *Decision, seen map[string]SHA256Digest, byDirection map[Direction][]float64) bool {
	ref, err := sampleArtifactRef(sample)
	if err != nil {
		decision.Reasons = append(decision.Reasons, "acceptance sample artifact: "+err.Error())
		return false
	}
	if prior, duplicate := seen[sample.Run.ID]; duplicate {
		decision.Reasons = append(decision.Reasons, duplicateAcceptanceReason(sample.Run.ID, prior, ref.SHA256))
		return false
	}
	seen[sample.Run.ID] = ref.SHA256
	decision.SampleRefs = append(decision.SampleRefs, ref)
	verdict := ValidateSample(inputs.Manifest, sample)
	if verdict.Status != "valid" {
		decision.Reasons = append(decision.Reasons, prefixReasons(sample.Run.ID, verdict.Reasons)...)
		return false
	}
	if !acceptanceSampleIdentityMatches(sample, candidate.ID, decision.BinarySet) {
		decision.Reasons = append(decision.Reasons, "acceptance sample identity does not match child manifest")
	}
	if sample.Run.PriorDecisionRef != inputs.FleetRef {
		decision.Reasons = append(decision.Reasons, "acceptance sample prior decision reference mismatch")
	}
	if sample.GoodputMbps <= inputs.Manifest.ManifestInput.Rules.FileMinimumMbps {
		decision.Reasons = append(decision.Reasons, "acceptance sample does not exceed 2.0 Gbps")
	}
	if reasons := validateAcceptancePerformance(inputs.Manifest, sample); len(reasons) != 0 {
		decision.Reasons = append(decision.Reasons, prefixReasons(sample.Run.ID, reasons)...)
	}
	byDirection[sample.Run.Direction] = append(byDirection[sample.Run.Direction], sample.GoodputMbps)
	return true
}

func validateAcceptancePerformance(manifest Manifest, sample Sample) []string {
	var reasons []string
	if !sample.Started || !sample.Capacity.Valid || sample.Capacity.Mbps < manifest.ManifestInput.Rules.CapacityMinimumMbps {
		reasons = append(reasons, "acceptance capacity gate failed")
	}
	if sample.RecoveryRatio >= manifest.ManifestInput.Rules.MaxRecovery {
		reasons = append(reasons, "acceptance recovery is not below limit")
	}
	if sample.Trace.Engine == "bulk-packets-v1" && sample.ScanPerPacket >= manifest.ManifestInput.Rules.MaxScanPerPacket {
		reasons = append(reasons, "acceptance bulk scan work is not below limit")
	}
	if sample.FlatlineSeconds >= 1 {
		reasons = append(reasons, "acceptance payload flatline is not below one second")
	}
	if cpuPerGiB(sample, manifest) >= manifest.ManifestInput.Rules.MaxCPUSecondsPerGiB {
		reasons = append(reasons, "acceptance Hetzner-role CPU is not below limit")
	}
	return reasons
}

func duplicateAcceptanceReason(runID string, prior, current SHA256Digest) string {
	if prior != current {
		return "replacement attempted for acceptance run " + runID
	}
	return "duplicate acceptance run " + runID
}

func acceptanceSampleIdentityMatches(sample Sample, candidateID string, binaries BinarySet) bool {
	return sample.Run.Stage == StageAcceptance && sample.Run.SizeBytes == 3*oneGiBBytes &&
		sample.CandidateID == candidateID && sample.BinarySet == binaries
}

func validateAcceptanceDirections(byDirection map[Direction][]float64, maxCV float64) []string {
	var reasons []string
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		values := byDirection[direction]
		if len(values) != 3 {
			reasons = append(reasons, fmt.Sprintf("acceptance %s sample count = %d, want 3", direction, len(values)))
			continue
		}
		if statistics(values).CoefficientOfVariation > maxCV {
			reasons = append(reasons, string(direction)+" acceptance CV exceeds limit")
		}
	}
	return reasons
}

func validateTypedDecisionRef(ref ArtifactRef, role string, value any) error {
	if err := validateArtifactRef(ref, role); err != nil {
		return fmt.Errorf("%s reference: %w", role, err)
	}
	digest, err := canonicalDigest(value)
	if err != nil {
		return err
	}
	if ref.SHA256 != digest {
		return fmt.Errorf("%s reference does not identify typed decision", role)
	}
	return nil
}

func artifactRefInSlice(want ArtifactRef, refs []ArtifactRef) bool {
	for _, ref := range refs {
		if ref == want {
			return true
		}
	}
	return false
}

// VerifyPrerequisite verifies exact manifest, decision, and binary identities.
func VerifyPrerequisite(manifest Manifest, manifestDigest SHA256Digest, decision PrerequisiteDecision, decisionDigest SHA256Digest, binaries BinarySet) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if err := verifyManifestBinding(manifest, manifestDigest, decision.ManifestSHA256); err != nil {
		return err
	}
	if err := verifyPrerequisiteDecisionBinding(decision, decisionDigest); err != nil {
		return err
	}
	decoded, err := reopenPrerequisiteDecision(decision, decisionDigest)
	if err != nil {
		return err
	}
	if err := verifyPrerequisiteIdentity(manifest, decoded, binaries); err != nil {
		return err
	}
	samples := make([]Sample, 0, len(decoded.Samples))
	for index, ref := range decoded.Samples {
		sample, openErr := LoadSampleArtifact(decision.EvidenceRoot, ref)
		if openErr != nil {
			return fmt.Errorf("prerequisite sample %d: %w", index+1, openErr)
		}
		samples = append(samples, sample)
	}
	recomputed := DecidePrerequisite(manifest, samples)
	if !reflect.DeepEqual(recomputed, decoded) {
		return fmt.Errorf("prerequisite decision does not replay from exact sample artifacts")
	}
	return nil
}

func reopenPrerequisiteDecision(decision PrerequisiteDecision, decisionDigest SHA256Digest) (PrerequisiteDecision, error) {
	if decision.Artifact.SHA256 != decisionDigest {
		return PrerequisiteDecision{}, fmt.Errorf("prerequisite decision artifact digest mismatch")
	}
	var decoded PrerequisiteDecision
	if err := verifyDecodeEvidence(decision.EvidenceRoot, decision.Artifact, "prerequisite", &decoded); err != nil {
		return PrerequisiteDecision{}, fmt.Errorf("prerequisite decision artifact: %w", err)
	}
	want := decision
	want.Artifact = ArtifactRef{}
	want.EvidenceRoot = ""
	if !reflect.DeepEqual(decoded, want) {
		return PrerequisiteDecision{}, fmt.Errorf("prerequisite decision value differs from exact artifact")
	}
	return decoded, nil
}

func verifyManifestBinding(manifest Manifest, manifestDigest, decisionManifestDigest SHA256Digest) error {
	wantManifest, err := canonicalDigest(manifest)
	if err != nil {
		return err
	}
	if err := validateSHA256Digest(manifestDigest); err != nil || manifestDigest != wantManifest || decisionManifestDigest != manifestDigest {
		return fmt.Errorf("manifest digest binding mismatch")
	}
	return nil
}

func verifyPrerequisiteDecisionBinding(decision PrerequisiteDecision, decisionDigest SHA256Digest) error {
	wantDecision, err := canonicalDigest(decision)
	if err != nil {
		return err
	}
	if err := validateSHA256Digest(decisionDigest); err != nil || decisionDigest != wantDecision {
		return fmt.Errorf("prerequisite decision digest binding mismatch")
	}
	if !decision.Passed || len(decision.Reasons) != 0 {
		return fmt.Errorf("prerequisite decision did not pass")
	}
	return nil
}

func verifyPrerequisiteIdentity(manifest Manifest, decision PrerequisiteDecision, binaries BinarySet) error {
	if decision.BinarySet != binaries {
		return fmt.Errorf("prerequisite binary set mismatch")
	}
	if len(manifest.ManifestInput.Candidates) != 1 {
		return fmt.Errorf("production manifest candidate count is not one")
	}
	candidate := manifest.ManifestInput.Candidates[0]
	if decision.CandidateID != candidate.ID || binaries != (BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}) {
		return fmt.Errorf("prerequisite binary identity does not match manifest candidate")
	}
	if len(decision.Samples) != 6 {
		return fmt.Errorf("prerequisite sample reference count = %d, want 6", len(decision.Samples))
	}
	return nil
}

func screeningEliminated(controlBefore, controlAfter float64, challenger, competitor screeningMetrics) bool {
	if !finitePositive(controlBefore) || !finitePositive(controlAfter) || math.Abs(controlAfter-controlBefore)/math.Min(controlBefore, controlAfter) > 0.03 {
		return false
	}
	return competitor.RawMbps > challenger.RawMbps*1.10 &&
		competitor.Normalized > challenger.Normalized*1.10 &&
		competitor.CPUEfficiency > challenger.CPUEfficiency*1.10
}

func sampleArtifactRef(sample Sample) (ArtifactRef, error) {
	if !validIdentifier(sample.Run.ID) {
		return ArtifactRef{}, fmt.Errorf("invalid sample run ID")
	}
	return exactSampleArtifact(sample)
}

func cpuPerGiB(sample Sample, manifest Manifest) float64 {
	seconds := sample.Resource.SenderUserSeconds + sample.Resource.SenderSystemSeconds
	if sample.Run.Direction == DirectionLocalToRemote {
		seconds = sample.Resource.ReceiverUserSeconds + sample.Resource.ReceiverSystemSeconds
	}
	gib := float64(manifest.ManifestInput.Payload.Bytes) / float64(oneGiBBytes)
	if gib <= 0 {
		return math.Inf(1)
	}
	return seconds / gib
}

func cloneArtifactRefs(input []ArtifactRef) []ArtifactRef {
	if input == nil {
		return []ArtifactRef{}
	}
	return append([]ArtifactRef(nil), input...)
}

func sortArtifactRefs(refs []ArtifactRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Role != refs[j].Role {
			return refs[i].Role < refs[j].Role
		}
		if refs[i].Path != refs[j].Path {
			return refs[i].Path < refs[j].Path
		}
		return refs[i].SHA256 < refs[j].SHA256
	})
}

func validDecisionStage(stage Stage) bool {
	switch stage {
	case StageScreening, StagePreliminary, StageFinalist, StageFinalistRerun, StageProduction, StageFleet, StageCeiling, StageAcceptance:
		return true
	default:
		return false
	}
}

func prefixReasons(runID string, reasons []string) []string {
	if len(reasons) == 0 {
		return []string{"run " + runID + " is invalid"}
	}
	result := make([]string, len(reasons))
	for index, reason := range reasons {
		result[index] = "run " + runID + ": " + reason
	}
	return result
}

func summarizeCandidates(manifest Manifest, samples []Sample) []CandidateStatistics {
	grouped := make(map[string]map[Direction][]Sample)
	for _, sample := range samples {
		if grouped[sample.CandidateID] == nil {
			grouped[sample.CandidateID] = make(map[Direction][]Sample)
		}
		grouped[sample.CandidateID][sample.Run.Direction] = append(grouped[sample.CandidateID][sample.Run.Direction], sample)
	}
	ids := make([]string, 0, len(grouped))
	for id := range grouped {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]CandidateStatistics, 0, len(ids))
	for _, id := range ids {
		summary := CandidateStatistics{CandidateID: id, Directions: []DirectionStatistics{}}
		summary.MaxHetzCPUPerGiB = 0
		for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
			directionSamples := grouped[id][direction]
			sort.Slice(directionSamples, func(i, j int) bool { return directionSamples[i].Run.ID < directionSamples[j].Run.ID })
			var raw, normalized, capacity, recovery, wall []float64
			for _, sample := range directionSamples {
				raw = append(raw, sample.GoodputMbps)
				normalized = append(normalized, sample.GoodputMbps/sample.Capacity.Mbps)
				capacity = append(capacity, sample.Capacity.Mbps)
				recovery = append(recovery, sample.RecoveryRatio)
				wall = append(wall, sample.WallGoodputMbps)
				summary.MaxHetzCPUPerGiB = math.Max(summary.MaxHetzCPUPerGiB, cpuPerGiB(sample, manifest))
			}
			directionSummary := DirectionStatistics{
				Direction:  direction,
				Raw:        statistics(raw),
				Normalized: statistics(normalized),
				Capacity:   statistics(capacity),
			}
			summary.Directions = append(summary.Directions, directionSummary)
			if len(recovery) != 0 {
				summary.RecoveryRatio = math.Max(summary.RecoveryRatio, statistics(recovery).Median)
			}
			if len(wall) != 0 {
				summary.WallGoodputMbps = math.Max(summary.WallGoodputMbps, statistics(wall).Median)
			}
		}
		if len(summary.Directions) == 2 {
			summary.RawBottleneck = math.Min(summary.Directions[0].Raw.Median, summary.Directions[1].Raw.Median)
			summary.NormalizedBottleneck = math.Min(summary.Directions[0].Normalized.Median, summary.Directions[1].Normalized.Median)
		}
		result = append(result, summary)
	}
	populateNearestTimeStatistics(result, samples)
	return result
}

func populateNearestTimeStatistics(summaries []CandidateStatistics, samples []Sample) {
	for candidateIndex := range summaries {
		for directionIndex := range summaries[candidateIndex].Directions {
			direction := summaries[candidateIndex].Directions[directionIndex].Direction
			for _, opponent := range summaries {
				if opponent.CandidateID == summaries[candidateIndex].CandidateID {
					continue
				}
				wins, matches := nearestTimeWins(
					timedMetrics(samples, summaries[candidateIndex].CandidateID, direction),
					timedMetrics(samples, opponent.CandidateID, direction),
				)
				summaries[candidateIndex].Directions[directionIndex].NearestTimeWins += wins
				summaries[candidateIndex].Directions[directionIndex].NearestTimeMatches += matches
			}
		}
	}
}

func selectPreliminaryCandidates(summaries []CandidateStatistics, delta float64) []string {
	ordered := append([]CandidateStatistics(nil), summaries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].CandidateID < ordered[j].CandidateID })
	leaders := preliminaryLeaders(ordered)
	selected := make(map[string]bool)
	for _, summary := range ordered {
		if summaryMeetsPreliminaryFrontier(summary, leaders, delta) {
			selected[summary.CandidateID] = true
		}
	}
	ranked := append([]CandidateStatistics(nil), ordered...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].RawBottleneck != ranked[j].RawBottleneck {
			return ranked[i].RawBottleneck > ranked[j].RawBottleneck
		}
		if ranked[i].NormalizedBottleneck != ranked[j].NormalizedBottleneck {
			return ranked[i].NormalizedBottleneck > ranked[j].NormalizedBottleneck
		}
		return ranked[i].CandidateID < ranked[j].CandidateID
	})
	for _, summary := range ranked {
		if len(selected) >= 2 {
			break
		}
		selected[summary.CandidateID] = true
	}
	result := make([]string, 0, len(selected))
	for _, summary := range ordered {
		if selected[summary.CandidateID] {
			result = append(result, summary.CandidateID)
		}
	}
	return result
}

type preliminaryLeaderSet struct {
	RawByDirection        map[Direction]float64
	NormalizedByDirection map[Direction]float64
	RawBottleneck         float64
	NormalizedBottleneck  float64
}

func preliminaryLeaders(summaries []CandidateStatistics) preliminaryLeaderSet {
	leaders := preliminaryLeaderSet{RawByDirection: make(map[Direction]float64), NormalizedByDirection: make(map[Direction]float64)}
	for _, summary := range summaries {
		leaders.RawBottleneck = math.Max(leaders.RawBottleneck, summary.RawBottleneck)
		leaders.NormalizedBottleneck = math.Max(leaders.NormalizedBottleneck, summary.NormalizedBottleneck)
		for _, direction := range summary.Directions {
			leaders.RawByDirection[direction.Direction] = math.Max(leaders.RawByDirection[direction.Direction], direction.Raw.Median)
			leaders.NormalizedByDirection[direction.Direction] = math.Max(leaders.NormalizedByDirection[direction.Direction], direction.Normalized.Median)
		}
	}
	return leaders
}

func summaryMeetsPreliminaryFrontier(summary CandidateStatistics, leaders preliminaryLeaderSet, delta float64) bool {
	if summary.RawBottleneck >= leaders.RawBottleneck*(1-delta) || summary.NormalizedBottleneck >= leaders.NormalizedBottleneck*(1-delta) {
		return true
	}
	for _, direction := range summary.Directions {
		if directionMeetsPreliminaryFrontier(direction, leaders, delta) {
			return true
		}
	}
	return false
}

func directionMeetsPreliminaryFrontier(direction DirectionStatistics, leaders preliminaryLeaderSet, delta float64) bool {
	return direction.Raw.Median >= leaders.RawByDirection[direction.Direction]*(1-delta) ||
		direction.Normalized.Median >= leaders.NormalizedByDirection[direction.Direction]*(1-delta)
}

func materialEdges(summaries []CandidateStatistics, samples []Sample, delta float64) []MaterialEdge {
	byID := make(map[string]CandidateStatistics, len(summaries))
	for _, summary := range summaries {
		byID[summary.CandidateID] = summary
	}
	var edges []MaterialEdge
	for _, from := range summaries {
		for _, to := range summaries {
			if from.CandidateID == to.CandidateID {
				continue
			}
			if materiallyBeats(from, to, samples, delta) {
				edges = append(edges, MaterialEdge{From: from.CandidateID, To: to.CandidateID})
			}
		}
	}
	return edges
}

func materiallyBeats(from, to CandidateStatistics, samples []Sample, delta float64) bool {
	if !(from.RawBottleneck > to.RawBottleneck*(1+delta) && from.NormalizedBottleneck > to.NormalizedBottleneck*(1+delta)) {
		return false
	}
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		fromDirection, fromOK := directionSummary(from, direction)
		toDirection, toOK := directionSummary(to, direction)
		if !fromOK || !toOK || fromDirection.Raw.Median < toDirection.Raw.Median*(1-delta) || fromDirection.Normalized.Median < toDirection.Normalized.Median*(1-delta) {
			return false
		}
		fromMetrics := timedMetrics(samples, from.CandidateID, direction)
		toMetrics := timedMetrics(samples, to.CandidateID, direction)
		wins, matches := nearestTimeWins(fromMetrics, toMetrics)
		requiredWins := (matches*2 + 2) / 3
		if matches < 6 || wins < requiredWins {
			return false
		}
	}
	return true
}

func directionSummary(candidate CandidateStatistics, direction Direction) (DirectionStatistics, bool) {
	for _, summary := range candidate.Directions {
		if summary.Direction == direction {
			return summary, true
		}
	}
	return DirectionStatistics{}, false
}

func timedMetrics(samples []Sample, candidate string, direction Direction) []timedMetric {
	var metrics []timedMetric
	for _, sample := range samples {
		if sample.CandidateID != candidate || sample.Run.Direction != direction {
			continue
		}
		observed, err := parseCanonicalUTCTime(sample.ObservedAtUTC)
		if err != nil {
			continue
		}
		metrics = append(metrics, timedMetric{
			ObservedAt: observed,
			Raw:        sample.GoodputMbps,
			Normalized: sample.GoodputMbps / sample.Capacity.Mbps,
			Block:      fmt.Sprintf("%s/%d", sample.Run.Schedule, sample.Run.Block),
		})
	}
	return metrics
}

func nearestTimeWins(left, right []timedMetric) (int, int) {
	left = append([]timedMetric(nil), left...)
	right = append([]timedMetric(nil), right...)
	sort.SliceStable(left, func(i, j int) bool { return left[i].ObservedAt.Before(left[j].ObservedAt) })
	sort.SliceStable(right, func(i, j int) bool { return right[i].ObservedAt.Before(right[j].ObservedAt) })
	used := make([]bool, len(right))
	wins, matches := 0, 0
	for _, candidate := range left {
		best := nearestUnusedMetric(candidate, right, used)
		if best == -1 {
			continue
		}
		used[best] = true
		matches++
		if candidate.Raw > right[best].Raw && candidate.Normalized > right[best].Normalized {
			wins++
		}
	}
	return wins, matches
}

func nearestUnusedMetric(candidate timedMetric, opponents []timedMetric, used []bool) int {
	best := -1
	var bestDistance time.Duration
	for index, opponent := range opponents {
		if used[index] || opponent.Block != candidate.Block {
			continue
		}
		distance := candidate.ObservedAt.Sub(opponent.ObservedAt)
		if distance < 0 {
			distance = -distance
		}
		if best == -1 || distance < bestDistance || distance == bestDistance && opponent.ObservedAt.Before(opponents[best].ObservedAt) {
			best, bestDistance = index, distance
		}
	}
	return best
}

func validateFinalistVariation(decision *Decision, manifest Manifest) {
	for _, candidate := range decision.Statistics {
		for _, direction := range candidate.Directions {
			if direction.Raw.Count == 0 || direction.Normalized.Count == 0 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("candidate %s lacks %s samples", candidate.CandidateID, direction.Direction))
				continue
			}
			rawUnstable := direction.Raw.CoefficientOfVariation > manifest.ManifestInput.Rules.MaxCV
			normalizedUnstableWithoutCapacityCause := direction.Normalized.CoefficientOfVariation > manifest.ManifestInput.Rules.MaxCV &&
				direction.Capacity.CoefficientOfVariation <= manifest.ManifestInput.Rules.MaxCV
			if rawUnstable || normalizedUnstableWithoutCapacityCause {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("candidate %s %s finalist CV exceeds limit", candidate.CandidateID, direction.Direction))
			}
		}
	}
}

func capacityVariationExceeds(summaries []CandidateStatistics, maxCV float64) bool {
	for _, candidate := range summaries {
		for _, direction := range candidate.Directions {
			if direction.Capacity.Count != 0 && direction.Capacity.CoefficientOfVariation > maxCV {
				return true
			}
		}
	}
	return false
}

func candidateIDsFromStatistics(summaries []CandidateStatistics) []string {
	ids := make([]string, len(summaries))
	for index, summary := range summaries {
		ids[index] = summary.CandidateID
	}
	sort.Strings(ids)
	return ids
}

func rankFrontier(frontier []string, summaries []CandidateStatistics) string {
	frontierSet := make(map[string]bool, len(frontier))
	for _, candidate := range frontier {
		frontierSet[candidate] = true
	}
	var ranked []CandidateStatistics
	for _, summary := range summaries {
		if frontierSet[summary.CandidateID] {
			ranked = append(ranked, summary)
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		left, right := ranked[i], ranked[j]
		if left.RawBottleneck != right.RawBottleneck {
			return left.RawBottleneck > right.RawBottleneck
		}
		if left.NormalizedBottleneck != right.NormalizedBottleneck {
			return left.NormalizedBottleneck > right.NormalizedBottleneck
		}
		if left.MaxHetzCPUPerGiB != right.MaxHetzCPUPerGiB {
			return left.MaxHetzCPUPerGiB < right.MaxHetzCPUPerGiB
		}
		if left.RecoveryRatio != right.RecoveryRatio {
			return left.RecoveryRatio < right.RecoveryRatio
		}
		if left.WallGoodputMbps != right.WallGoodputMbps {
			return left.WallGoodputMbps > right.WallGoodputMbps
		}
		return left.CandidateID < right.CandidateID
	})
	if len(ranked) == 0 {
		return ""
	}
	return ranked[0].CandidateID
}

func statistics(values []float64) Statistics {
	if len(values) == 0 {
		return Statistics{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	var sum float64
	for _, value := range sorted {
		sum += value
	}
	mean := sum / float64(len(sorted))
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	var squared float64
	for _, value := range sorted {
		delta := value - mean
		squared += delta * delta
	}
	stddev := math.Sqrt(squared / float64(len(sorted)))
	cv := math.Inf(1)
	if mean != 0 {
		cv = stddev / math.Abs(mean)
	}
	low, high := bootstrapMedianInterval(sorted)
	return Statistics{
		Count:                  len(sorted),
		Mean:                   mean,
		Median:                 median,
		Minimum:                sorted[0],
		Maximum:                sorted[len(sorted)-1],
		PopulationStdDev:       stddev,
		CoefficientOfVariation: cv,
		BootstrapLow:           low,
		BootstrapHigh:          high,
	}
}

func bootstrapMedianInterval(sorted []float64) (float64, float64) {
	if len(sorted) == 0 {
		return 0, 0
	}
	if len(sorted) == 1 {
		return sorted[0], sorted[0]
	}
	seed := uint64(0x9e3779b97f4a7c15)
	var encoded [8]byte
	for _, value := range sorted {
		binary.LittleEndian.PutUint64(encoded[:], math.Float64bits(value))
		for _, octet := range encoded {
			seed ^= uint64(octet)
			seed = bits.RotateLeft64(seed*0x100000001b3, 13)
		}
	}
	const iterations = 2048
	medians := make([]float64, iterations)
	resample := make([]float64, len(sorted))
	next := func() uint64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return seed
	}
	for iteration := range medians {
		for index := range resample {
			resample[index] = sorted[next()%uint64(len(sorted))]
		}
		sort.Float64s(resample)
		middle := resample[len(resample)/2]
		if len(resample)%2 == 0 {
			middle = (resample[len(resample)/2-1] + resample[len(resample)/2]) / 2
		}
		medians[iteration] = middle
	}
	sort.Float64s(medians)
	lowIndex := int(math.Floor(0.025 * float64(iterations-1)))
	highIndex := int(math.Floor(0.975 * float64(iterations-1)))
	return medians[lowIndex], medians[highIndex]
}

const oneGiBBytes = int64(1024 * 1024 * 1024)
