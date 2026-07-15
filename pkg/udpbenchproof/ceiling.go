// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"
)

type ceilingCapacityRecord struct {
	SchemaVersion   int       `json:"schema_version"`
	Kind            string    `json:"kind"`
	Phase           string    `json:"phase"`
	Direction       Direction `json:"direction"`
	Order           string    `json:"order"`
	OfferedGbps     float64   `json:"offered_gbps"`
	Mbps            float64   `json:"mbps"`
	TCPPort         int       `json:"tcp_port"`
	ParallelFlows   int       `json:"parallel_flows"`
	DurationSeconds int       `json:"duration_seconds"`
	ObservedAtUTC   string    `json:"observed_at_utc"`
}

type ceilingUDPResultRecord struct {
	SchemaVersion   int       `json:"schema_version"`
	Kind            string    `json:"kind"`
	Direction       Direction `json:"direction"`
	Order           string    `json:"order"`
	OfferedGbps     float64   `json:"offered_gbps"`
	DeliveredGbps   float64   `json:"delivered_gbps"`
	LossRatio       float64   `json:"loss_ratio"`
	QueuePressure   float64   `json:"queue_pressure"`
	DatagramBytes   int       `json:"datagram_bytes"`
	PublicUDP       bool      `json:"public_udp"`
	CounterFamilies []string  `json:"counter_families"`
}

type ceilingHealthRecord struct {
	SchemaVersion int       `json:"schema_version"`
	Kind          string    `json:"kind"`
	Direction     Direction `json:"direction"`
	Order         string    `json:"order"`
	OfferedGbps   float64   `json:"offered_gbps"`
	Healthy       bool      `json:"healthy"`
}

type ceilingProfileRecord struct {
	SchemaVersion              int         `json:"schema_version"`
	Kind                       string      `json:"kind"`
	RunID                      string      `json:"run_id"`
	HostID                     string      `json:"host_id"`
	CandidateID                string      `json:"candidate_id"`
	BinarySet                  BinarySet   `json:"binary_set"`
	ObservedAtUTC              string      `json:"observed_at_utc"`
	Direction                  Direction   `json:"direction"`
	OfferedGbps                float64     `json:"offered_gbps"`
	SweepPoint                 ArtifactRef `json:"sweep_point"`
	HetzCPUUtilization         float64     `json:"hetz_cpu_utilization"`
	KernelPacketCPUUtilization float64     `json:"kernel_packet_cpu_utilization"`
	LimitingMechanism          string      `json:"limiting_mechanism"`
	Independent                bool        `json:"independent"`
	CounterFamilies            []string    `json:"counter_families"`
}

type ceilingSweepPointRecord struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	Point         CeilingSweepPoint `json:"point"`
}

type ceilingSweepGroupKey struct {
	Direction Direction
	Order     string
}

type ceilingPlateauBand struct {
	Start float64
	End   float64
}

// LoadCeilingSweepArtifact opens one immutable typed sweep point.
func LoadCeilingSweepArtifact(root string, ref ArtifactRef) (CeilingSweepPoint, error) {
	var record ceilingSweepPointRecord
	if err := verifyDecodeEvidence(root, ref, "ceiling-sweep", &record); err != nil {
		return CeilingSweepPoint{}, err
	}
	if record.SchemaVersion != 1 || record.Kind != "ceiling-sweep" {
		return CeilingSweepPoint{}, fmt.Errorf("ceiling sweep artifact schema or kind mismatch")
	}
	record.Point.Artifact = ref
	return record.Point, nil
}

// LoadCeilingProfileArtifact opens one immutable typed profile point.
func LoadCeilingProfileArtifact(root string, ref ArtifactRef) (CeilingProfile, error) {
	var record ceilingProfileRecord
	if err := verifyDecodeEvidence(root, ref, "ceiling-profile", &record); err != nil {
		return CeilingProfile{}, err
	}
	if record.SchemaVersion != 1 || record.Kind != "ceiling-profile" {
		return CeilingProfile{}, fmt.Errorf("ceiling profile artifact schema or kind mismatch")
	}
	return CeilingProfile{
		RunID: record.RunID, HostID: record.HostID, CandidateID: record.CandidateID, BinarySet: record.BinarySet,
		ObservedAtUTC: record.ObservedAtUTC, Direction: record.Direction, OfferedGbps: record.OfferedGbps, SweepPoint: record.SweepPoint,
		Artifact: ref, HetzCPUUtilization: record.HetzCPUUtilization,
		KernelPacketCPUUtilization: record.KernelPacketCPUUtilization, LimitingMechanism: record.LimitingMechanism,
		Independent: record.Independent, CounterFamilies: append([]string(nil), record.CounterFamilies...),
	}, nil
}

func ceilingPlateau(offered, delivered, loss, queue []float64) (bool, float64, float64) {
	if !validPlateauSeries(offered, delivered, loss, queue) {
		return false, 0, 0
	}
	for start := 0; start < len(offered)-1; start++ {
		if offered[start] <= 0 || delivered[start] <= 0 {
			continue
		}
		for end := start + 1; end < len(offered); end++ {
			if plateauPairQualifies(start, end, offered, delivered, loss, queue) {
				return true, offered[start], offered[end]
			}
		}
	}
	return false, 0, 0
}

func validPlateauSeries(offered, delivered, loss, queue []float64) bool {
	return len(offered) >= 2 && len(offered) == len(delivered) && len(offered) == len(loss) &&
		(len(queue) == 0 || len(queue) == len(offered))
}

func plateauPairQualifies(start, end int, offered, delivered, loss, queue []float64) bool {
	if offered[end]+1e-12 < offered[start]*1.20 {
		return false
	}
	deliveredGain := (delivered[end] - delivered[start]) / delivered[start]
	pressureRises := loss[end] > loss[start]
	if len(queue) != 0 {
		pressureRises = pressureRises || queue[end] > queue[start]
	}
	return deliveredGain <= 0.03 && pressureRises
}

func ceilingMechanismAgreement(mechanisms []string, required float64) (bool, []string) {
	if len(mechanisms) == 0 || required != 1.0 {
		return false, []string{"profile mechanism agreement requirement is invalid"}
	}
	first := mechanisms[0]
	if first == "" {
		return false, []string{"profile limiting mechanism is empty"}
	}
	for _, mechanism := range mechanisms[1:] {
		if mechanism != first {
			return false, []string{"profile limiting mechanism mismatch"}
		}
	}
	return true, []string{}
}

// DecideCeiling evaluates the frozen diagnostic sweep and retained winner evidence.
func DecideCeiling(manifest Manifest, sweeps []CeilingSweepPoint, profiles []CeilingProfile, samples []Sample) CeilingDecision {
	decision := CeilingDecision{
		SchemaVersion:     decisionSchemaVersion,
		InputDecisionRefs: cloneArtifactRefs(manifest.ManifestInput.ParentDecisionRefs),
		SweepRefs:         []ArtifactRef{},
		ProfileRefs:       []ArtifactRef{},
		WinnerSampleRefs:  []ArtifactRef{},
		AcceptanceMet:     false,
		Reasons:           []string{},
	}
	decision.ManifestSHA256, _ = canonicalDigest(manifest)
	if err := ValidateManifest(manifest); err != nil || manifest.ManifestInput.Kind != ManifestCeiling {
		decision.Reasons = append(decision.Reasons, "ceiling requires valid ceiling manifest")
	}
	decision.Reasons = append(decision.Reasons, validateCeilingParentProofs(manifest)...)
	sweepRefs, groupPlateaus, start, end, sweepReasons := validateCeilingSweepSet(manifest.EvidenceRoot, manifest, sweeps, manifest.ManifestInput.Rules)
	decision.SweepRefs = sweepRefs
	decision.PlateauStartGbps = start
	decision.PlateauEndGbps = end
	decision.Reasons = append(decision.Reasons, sweepReasons...)
	profileRefs, mechanism, profileReasons := validateCeilingProfiles(manifest.EvidenceRoot, manifest, profiles, sweeps, groupPlateaus, manifest.ManifestInput.Rules)
	decision.ProfileRefs = profileRefs
	decision.LimitingMechanism = mechanism
	decision.Reasons = append(decision.Reasons, profileReasons...)
	winnerRefs, winnerReasons := validateCeilingWinnerSamples(manifest, samples)
	decision.WinnerSampleRefs = winnerRefs
	decision.Reasons = append(decision.Reasons, winnerReasons...)
	sort.Strings(decision.Reasons)
	decision.Reasons = compactStrings(decision.Reasons)
	decision.Passed = len(decision.Reasons) == 0
	decision.AcceptanceMet = false
	return decision
}

func validateCeilingParentProofs(manifest Manifest) []string {
	production, productionDigest, productionReasons := openCeilingProduction(manifest)
	if len(productionReasons) != 0 {
		return productionReasons
	}
	experiment, experimentReasons := openCeilingExperiment(manifest.EvidenceRoot, production)
	if len(experimentReasons) != 0 {
		return experimentReasons
	}
	var reasons []string
	peak, peakValid, peakReasons := openPassedCeilingDecision(manifest, "peak")
	reasons = append(reasons, peakReasons...)
	if peakValid {
		reasons = append(reasons, validateCeilingPeakParent(manifest.EvidenceRoot, experiment, peak)...)
	}
	fleet, fleetValid, fleetReasons := openPassedCeilingDecision(manifest, "fleet")
	reasons = append(reasons, fleetReasons...)
	if fleetValid {
		reasons = append(reasons, validateCeilingFleetParent(manifest, production, productionDigest, fleet)...)
		reasons = append(reasons, validateCeilingHardPrerequisite(manifest, production, productionDigest, fleet)...)
	}
	return reasons
}

func validateCeilingHardPrerequisite(manifest, production Manifest, productionDigest SHA256Digest, fleet Decision) []string {
	ref := artifactRefByRole(fleet.InputDecisionRefs, "prerequisite")
	var prerequisite PrerequisiteDecision
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, ref, "prerequisite", &prerequisite); err != nil {
		return []string{"ceiling prerequisite decision artifact: " + err.Error()}
	}
	prerequisite.Artifact = ref
	prerequisite.EvidenceRoot = manifest.EvidenceRoot
	if err := verifyHardCeilingFleetAuthorization(production, productionDigest, prerequisite, ref.SHA256); err != nil {
		return []string{"ceiling requires exact throughput-only failed prerequisite: " + err.Error()}
	}
	return nil
}

func openCeilingProduction(manifest Manifest) (Manifest, SHA256Digest, []string) {
	if manifest.EvidenceRoot == "" {
		return Manifest{}, "", []string{"ceiling evidence root is not bound"}
	}
	if manifest.ManifestInput.ParentManifest == nil {
		return Manifest{}, "", []string{"ceiling production parent manifest is missing"}
	}
	var production Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, *manifest.ManifestInput.ParentManifest, "manifest", &production); err != nil {
		return Manifest{}, "", []string{"ceiling production parent manifest: " + err.Error()}
	}
	digest, err := canonicalDigest(production)
	validAncestry := err == nil && digest == manifest.ManifestInput.ParentManifest.SHA256 && production.ManifestInput.Kind == ManifestProduction
	if !validAncestry {
		return Manifest{}, "", []string{"ceiling production parent manifest ancestry mismatch"}
	}
	production.EvidenceRoot = manifest.EvidenceRoot
	if _, err := verifyChildManifestAuthorization(manifest, ManifestCeiling); err != nil {
		return Manifest{}, "", []string{"ceiling manifest authorization: " + err.Error()}
	}
	if production.ManifestInput.ParentManifest == nil {
		return Manifest{}, "", []string{"ceiling production parent lacks experiment ancestry"}
	}
	return production, digest, nil
}

func openCeilingExperiment(root string, production Manifest) (Manifest, []string) {
	var experiment Manifest
	if err := verifyDecodeEvidence(root, *production.ManifestInput.ParentManifest, "manifest", &experiment); err != nil {
		return Manifest{}, []string{"ceiling experiment parent manifest: " + err.Error()}
	}
	return experiment, nil
}

func openPassedCeilingDecision(manifest Manifest, role string) (Decision, bool, []string) {
	ref := artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, role)
	var parent Decision
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, ref, role, &parent); err != nil {
		return Decision{}, false, []string{"ceiling " + role + " decision artifact: " + err.Error()}
	}
	if !parent.Passed || len(parent.Reasons) != 0 {
		return Decision{}, false, []string{"ceiling " + role + " decision did not pass"}
	}
	parent.Artifact = ref
	parent.EvidenceRoot = manifest.EvidenceRoot
	return parent, true, nil
}

func validateCeilingPeakParent(root string, experiment Manifest, peak Decision) []string {
	var reasons []string
	if peak.Stage != StageFinalist && peak.Stage != StageFinalistRerun {
		reasons = append(reasons, "ceiling peak decision is not finalist proof")
	}
	reasons = append(reasons, validateCeilingPeakClosure(experiment, peak)...)
	reasons = append(reasons, validateCeilingPeakReplay(root, experiment, peak)...)
	return reasons
}

func validateCeilingFleetParent(manifest Manifest, production Manifest, productionDigest SHA256Digest, fleet Decision) []string {
	var reasons []string
	if fleet.Stage != StageFleet || fleet.ManifestSHA256 != productionDigest {
		reasons = append(reasons, "ceiling fleet decision ancestry mismatch")
	}
	reasons = append(reasons, replayFleetDecision(manifest.EvidenceRoot, production, *manifest.ManifestInput.ParentManifest, fleet)...)
	return reasons
}

func validateCeilingPeakReplay(root string, experiment Manifest, peak Decision) []string {
	peak.EvidenceRoot = root
	if err := ReplayDecision(experiment, peak); err != nil {
		return []string{"ceiling peak replay: " + err.Error()}
	}
	return nil
}

func validateCeilingPeakClosure(experiment Manifest, peak Decision) []string {
	experimentDigest, err := canonicalDigest(experiment)
	if err != nil || peak.ManifestSHA256 != experimentDigest {
		return []string{"ceiling peak decision experiment ancestry mismatch"}
	}
	candidates, orderedCandidates := ceilingPeakCandidates(experiment)
	finalists, orderedFinalists, reasons := indexCeilingPeakFinalists(candidates, peak.FinalistCandidates)
	frontier, frontierReasons := indexCeilingPeakFrontier(finalists, peak.PeakFrontier)
	reasons = append(reasons, frontierReasons...)
	closed, closedReasons := indexCeilingPeakClosed(candidates, frontier, peak.ClosedCandidates)
	reasons = append(reasons, closedReasons...)
	reasons = append(reasons, validateCeilingPeakCoverage(orderedCandidates, frontier, closed, peak.SelectedCandidate)...)
	reasons = append(reasons, validateCeilingPeakEdges(finalists, peak.MaterialEdges)...)
	reasons = append(reasons, validateCeilingPeakFrontier(orderedFinalists, peak)...)
	return reasons
}

func ceilingPeakCandidates(experiment Manifest) (map[string]bool, []string) {
	candidates := make(map[string]bool, len(experiment.ManifestInput.Candidates))
	ordered := make([]string, 0, len(experiment.ManifestInput.Candidates))
	for _, candidate := range experiment.ManifestInput.Candidates {
		candidates[candidate.ID] = true
		ordered = append(ordered, candidate.ID)
	}
	return candidates, ordered
}

func indexCeilingPeakFinalists(candidates map[string]bool, values []string) (map[string]bool, []string, []string) {
	finalists := make(map[string]bool, len(values))
	var ordered []string
	var reasons []string
	if len(values) == 0 {
		reasons = append(reasons, "ceiling peak recorded finalist set is empty")
	}
	for _, candidate := range values {
		if !candidates[candidate] || finalists[candidate] {
			reasons = append(reasons, "ceiling peak recorded finalist set contains unknown or duplicate candidate")
			continue
		}
		finalists[candidate] = true
		ordered = append(ordered, candidate)
	}
	sort.Strings(ordered)
	return finalists, ordered, reasons
}

func indexCeilingPeakFrontier(candidates map[string]bool, values []string) (map[string]bool, []string) {
	frontier := make(map[string]bool, len(values))
	var reasons []string
	for _, candidate := range values {
		if !candidates[candidate] || frontier[candidate] {
			reasons = append(reasons, "ceiling peak frontier contains unknown or duplicate candidate")
		}
		frontier[candidate] = true
	}
	return frontier, reasons
}

func indexCeilingPeakClosed(candidates, frontier map[string]bool, values []string) (map[string]bool, []string) {
	closed := make(map[string]bool, len(values))
	var reasons []string
	for _, candidate := range values {
		if !candidates[candidate] || closed[candidate] || frontier[candidate] {
			reasons = append(reasons, "ceiling peak closed set contains unknown, duplicate, or frontier candidate")
		}
		closed[candidate] = true
	}
	return closed, reasons
}

func validateCeilingPeakCoverage(ordered []string, frontier, closed map[string]bool, selected string) []string {
	var reasons []string
	for _, candidate := range ordered {
		if !frontier[candidate] && !closed[candidate] {
			reasons = append(reasons, "ceiling peak left candidate unproved: "+candidate)
		}
	}
	if !frontier[selected] {
		reasons = append(reasons, "ceiling peak selected winner is outside frontier")
	}
	return reasons
}

func validateCeilingPeakEdges(candidates map[string]bool, edges []MaterialEdge) []string {
	var reasons []string
	for _, edge := range edges {
		if !candidates[edge.From] || !candidates[edge.To] || edge.From == edge.To {
			reasons = append(reasons, "ceiling peak material edge has invalid candidate identity")
		}
	}
	return reasons
}

func validateCeilingPeakFrontier(ordered []string, peak Decision) []string {
	want := PeakFrontier(ordered, peak.MaterialEdges)
	got := append([]string(nil), peak.PeakFrontier...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		return []string{"ceiling peak frontier is inconsistent with exact material proof"}
	}
	return nil
}

func validateCeilingProfiles(root string, manifest Manifest, profiles []CeilingProfile, sweeps []CeilingSweepPoint, groupPlateaus map[ceilingSweepGroupKey]ceilingPlateauBand, rules FrozenRules) ([]ArtifactRef, string, []string) {
	ordered := append([]CeilingProfile(nil), profiles...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Direction != ordered[j].Direction {
			return ordered[i].Direction < ordered[j].Direction
		}
		return ordered[i].Artifact.Path < ordered[j].Artifact.Path
	})
	state := newCeilingProfileValidationState()
	for _, profile := range ordered {
		state.record(root, manifest, profile, sweeps, groupPlateaus, rules)
	}
	state.reasons = append(state.reasons, validateCeilingProfileCounts(state.counts, rules.MinRepeatedCeilingProfiles)...)
	passed, agreementReasons := ceilingMechanismAgreement(state.mechanisms, rules.RequiredProfileAgreement)
	if !passed {
		state.reasons = append(state.reasons, agreementReasons...)
	}
	mechanism := ""
	if passed {
		mechanism = state.mechanisms[0]
	}
	sortArtifactRefs(state.refs)
	return state.refs, mechanism, state.reasons
}

type ceilingProfileValidationState struct {
	counts      map[Direction]int
	seen        map[string]bool
	seenRuns    map[string]bool
	seenDigests map[SHA256Digest]bool
	seenTimes   map[string]bool
	refs        []ArtifactRef
	mechanisms  []string
	reasons     []string
}

func newCeilingProfileValidationState() *ceilingProfileValidationState {
	return &ceilingProfileValidationState{
		counts: make(map[Direction]int), seen: make(map[string]bool), seenRuns: make(map[string]bool),
		seenDigests: make(map[SHA256Digest]bool), seenTimes: make(map[string]bool),
	}
}

func (state *ceilingProfileValidationState) record(root string, manifest Manifest, profile CeilingProfile, sweeps []CeilingSweepPoint, groupPlateaus map[ceilingSweepGroupKey]ceilingPlateauBand, rules FrozenRules) {
	state.counts[profile.Direction]++
	profileReasons := validateOneCeilingProfile(manifest, profile, sweeps, groupPlateaus, rules)
	if err := verifyCeilingProfileArtifact(root, profile); err != nil {
		profileReasons = append(profileReasons, "ceiling profile artifact: "+err.Error())
	}
	state.reasons = append(state.reasons, profileReasons...)
	identity := profile.Artifact.Path + "\x00" + string(profile.Artifact.SHA256)
	if state.seen[identity] {
		state.reasons = append(state.reasons, "duplicate ceiling profile reference")
	} else if validateArtifactRef(profile.Artifact, "ceiling-profile") == nil {
		state.seen[identity] = true
		state.refs = append(state.refs, profile.Artifact)
	}
	if state.seenDigests[profile.Artifact.SHA256] || state.seenTimes[profile.ObservedAtUTC] {
		state.reasons = append(state.reasons, "ceiling profiles are not independent immutable captures")
	}
	if state.seenRuns[profile.RunID] {
		state.reasons = append(state.reasons, "ceiling profiles repeat a frozen profile run")
	}
	state.seenRuns[profile.RunID] = true
	state.seenDigests[profile.Artifact.SHA256] = true
	state.seenTimes[profile.ObservedAtUTC] = true
	state.mechanisms = append(state.mechanisms, profile.LimitingMechanism)
}

func verifyCeilingProfileArtifact(root string, profile CeilingProfile) error {
	opened, err := LoadCeilingProfileArtifact(root, profile.Artifact)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(opened, profile) {
		return fmt.Errorf("profile semantic mismatch")
	}
	return nil
}

func validateOneCeilingProfile(manifest Manifest, profile CeilingProfile, sweeps []CeilingSweepPoint, groupPlateaus map[ceilingSweepGroupKey]ceilingPlateauBand, rules FrozenRules) []string {
	checks := []ceilingCheck{
		{profile.Independent, "ceiling profile is not an explicit independent capture"},
		{validDirectionValue(profile.Direction), "ceiling profile direction is invalid"},
		{validateArtifactRef(profile.Artifact, "ceiling-profile") == nil, "ceiling profile reference is invalid"},
		{validateFrozenCeilingProfileIdentity(manifest, profile) == nil, "ceiling profile does not bind exact frozen row identity"},
		{validCeilingProfileMeasurements(profile), "ceiling profile timestamp or utilization range is invalid"},
		{ceilingProfileMatchesPlateauSweep(profile, sweeps, groupPlateaus), "ceiling profile does not bind an exact matching sweep point at the proved plateau"},
		{ceilingProfileSaturated(profile, rules), "ceiling profile does not meet CPU saturation threshold"},
		{exactCounterFamilies(profile.CounterFamilies), "ceiling profile counter families are incomplete"},
	}
	return failedCeilingChecks(checks)
}

func ceilingProfileMatchesPlateauSweep(profile CeilingProfile, sweeps []CeilingSweepPoint, groupPlateaus map[ceilingSweepGroupKey]ceilingPlateauBand) bool {
	for _, point := range sweeps {
		if point.Artifact != profile.SweepPoint {
			continue
		}
		band, ok := groupPlateaus[ceilingSweepGroupKey{Direction: point.Direction, Order: point.Order}]
		return ok && ceilingProfileLoadAtPlateau(profile.OfferedGbps, band.Start, band.End) && ceilingSweepMatchesProfile(point, profile)
	}
	return false
}

func ceilingProfileLoadAtPlateau(offered, start, end float64) bool {
	return finitePositive(start) && end >= start && offered >= start && offered <= end
}

func ceilingSweepMatchesProfile(point CeilingSweepPoint, profile CeilingProfile) bool {
	identityMatches := point.OfferedGbps == profile.OfferedGbps && point.Direction == profile.Direction && point.HostID == profile.HostID &&
		point.CandidateID == profile.CandidateID && point.BinarySet == profile.BinarySet
	return identityMatches && point.ObservedAtUTC == profile.ObservedAtUTC && reflect.DeepEqual(point.CounterFamilies, profile.CounterFamilies)
}

func validCeilingProfileMeasurements(profile CeilingProfile) bool {
	return validCanonicalTime(profile.ObservedAtUTC) && profile.HetzCPUUtilization >= 0 && profile.HetzCPUUtilization <= 1 &&
		profile.KernelPacketCPUUtilization >= 0 && profile.KernelPacketCPUUtilization <= 1
}

func ceilingProfileSaturated(profile CeilingProfile, rules FrozenRules) bool {
	return profile.HetzCPUUtilization >= rules.MinCeilingCPUSaturation ||
		profile.KernelPacketCPUUtilization >= rules.MinCeilingKernelSaturation
}

type ceilingCheck struct {
	valid  bool
	reason string
}

func failedCeilingChecks(checks []ceilingCheck) []string {
	var reasons []string
	for _, check := range checks {
		if !check.valid {
			reasons = append(reasons, check.reason)
		}
	}
	return reasons
}

func validateCeilingProfileCounts(counts map[Direction]int, want int) []string {
	var reasons []string
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		if counts[direction] != want {
			reasons = append(reasons, fmt.Sprintf("%s ceiling profile count = %d, want %d", direction, counts[direction], want))
		}
	}
	return reasons
}

func validateFrozenCeilingProfileIdentity(manifest Manifest, profile CeilingProfile) error {
	for _, schedule := range manifest.ManifestInput.Schedules {
		if schedule.Stage != "ceiling-profile" {
			continue
		}
		for index, runID := range schedule.RunIDs {
			if runID != profile.RunID {
				continue
			}
			candidate, ok := manifestCandidate(manifest, schedule.CandidateOrder[index])
			if !ok || profile.HostID != schedule.HostOrder[index] || profile.CandidateID != candidate.ID ||
				profile.BinarySet != (BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}) ||
				profile.Direction != manifestDirection(schedule.DirectionOrder[index]) {
				return fmt.Errorf("ceiling profile does not bind exact frozen row identity")
			}
			return nil
		}
	}
	return fmt.Errorf("ceiling profile run ID is not a frozen profile row")
}

func validateFrozenCeilingSweepIdentity(manifest Manifest, point CeilingSweepPoint, direction Direction, order string, sequence int) error {
	schedule, index, err := frozenCeilingSweepRow(manifest, direction, order, sequence)
	if err != nil {
		return err
	}
	candidate, ok := manifestCandidate(manifest, schedule.CandidateOrder[index])
	if !ok || !ceilingSweepIdentityMatches(point, schedule, index, candidate) {
		return fmt.Errorf("ceiling sweep does not bind exact frozen row identity")
	}
	return nil
}

func frozenCeilingSweepRow(manifest Manifest, direction Direction, order string, sequence int) (FrozenSchedule, int, error) {
	directionName := "hetz-to-mac"
	if direction == DirectionLocalToRemote {
		directionName = "mac-to-hetz"
	}
	stage := "ceiling-sweep-" + order + "-" + directionName
	for _, schedule := range manifest.ManifestInput.Schedules {
		if schedule.Stage == stage && sequence >= 1 && sequence <= len(schedule.RunIDs) {
			return schedule, sequence - 1, nil
		}
	}
	return FrozenSchedule{}, 0, fmt.Errorf("ceiling sweep does not identify a frozen schedule row")
}

func ceilingSweepIdentityMatches(point CeilingSweepPoint, schedule FrozenSchedule, index int, candidate CandidateIdentity) bool {
	return point.RunID == schedule.RunIDs[index] && point.HostID == schedule.HostOrder[index] &&
		point.CandidateID == candidate.ID && point.BinarySet == (BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}) &&
		point.OfferedGbps*1000 == schedule.OfferedLoadMbps[index]
}

type ceilingWinnerAncestry struct {
	production       Manifest
	experiment       Manifest
	productionDigest SHA256Digest
	experimentDigest SHA256Digest
	peakWinner       string
	peak             Decision
	prerequisite     PrerequisiteDecision
	requiredRefs     []ArtifactRef
	requiredStages   map[string]int
	requiredByDir    map[Direction]int
}

func validateCeilingWinnerSamples(manifest Manifest, samples []Sample) ([]ArtifactRef, []string) {
	ordered := append([]Sample(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Run.ID < ordered[j].Run.ID })
	ancestry, reasons := loadCeilingWinnerAncestry(manifest)
	if len(ordered) != len(ancestry.requiredRefs) {
		reasons = append(reasons, fmt.Sprintf("winner sample count = %d, want exactly %d", len(ordered), len(ancestry.requiredRefs)))
	}
	seen := make(map[string]SHA256Digest)
	providedRefs := make(map[ArtifactRef]bool, len(ordered))
	byDirection := map[Direction][]float64{DirectionLocalToRemote: {}, DirectionRemoteToLocal: {}}
	stageCounts := make(map[string]int)
	var refs []ArtifactRef
	for _, sample := range ordered {
		ref, refReasons, valid := recordCeilingWinnerRef(sample, seen)
		reasons = append(reasons, refReasons...)
		if !valid {
			continue
		}
		refs = append(refs, ref)
		providedRefs[ref] = true
		reasons = append(reasons, validateCeilingWinnerIdentity(sample, ancestry, manifest.ManifestInput.Rules)...)
		recordCeilingWinnerDirection(sample, byDirection, stageCounts)
	}
	if !exactCeilingWinnerRefSet(ancestry.requiredRefs, providedRefs) {
		reasons = append(reasons, "winner sample references differ from exact replayed peak and prerequisite set")
	}
	reasons = append(reasons, validateCeilingWinnerStageCounts(stageCounts, ancestry.requiredStages)...)
	reasons = append(reasons, validateCeilingWinnerDirections(byDirection, ancestry.requiredByDir, manifest.ManifestInput.Rules.MaxCV)...)
	sortArtifactRefs(refs)
	return refs, reasons
}

func loadCeilingWinnerAncestry(manifest Manifest) (ceilingWinnerAncestry, []string) {
	ancestry := ceilingWinnerAncestry{
		requiredStages: make(map[string]int),
		requiredByDir:  make(map[Direction]int),
	}
	var reasons []string
	var peak Decision
	peakRef := artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, "peak")
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, peakRef, "peak", &peak); err != nil {
		reasons = append(reasons, "winner peak decision artifact: "+err.Error())
	} else {
		peak.Artifact = peakRef
		peak.EvidenceRoot = manifest.EvidenceRoot
		ancestry.peakWinner = peak.SelectedCandidate
		ancestry.peak = peak
	}
	production, productionDigest, productionReasons := loadCeilingWinnerProduction(manifest)
	ancestry.production = production
	ancestry.productionDigest = productionDigest
	reasons = append(reasons, productionReasons...)
	if len(productionReasons) != 0 || manifest.ManifestInput.ParentManifest == nil {
		return ancestry, reasons
	}
	experiment, experimentDigest, experimentReasons := loadCeilingWinnerExperiment(manifest, production, productionDigest)
	ancestry.experiment = experiment
	ancestry.experimentDigest = experimentDigest
	reasons = append(reasons, experimentReasons...)
	reasons = append(reasons, loadCeilingWinnerRequiredRefs(manifest, &ancestry)...)
	return ancestry, reasons
}

func loadCeilingWinnerRequiredRefs(manifest Manifest, ancestry *ceilingWinnerAncestry) []string {
	fleetRef := artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, "fleet")
	var fleet Decision
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, fleetRef, "fleet", &fleet); err != nil {
		return []string{"winner fleet decision artifact: " + err.Error()}
	}
	prerequisiteRef := artifactRefByRole(fleet.InputDecisionRefs, "prerequisite")
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, prerequisiteRef, "prerequisite", &ancestry.prerequisite); err != nil {
		return []string{"winner prerequisite decision artifact: " + err.Error()}
	}
	ancestry.prerequisite.Artifact = prerequisiteRef
	ancestry.prerequisite.EvidenceRoot = manifest.EvidenceRoot

	refs := append([]ArtifactRef(nil), ancestry.prerequisite.Samples...)
	for _, ref := range ancestry.peak.SampleRefs {
		sample, err := LoadSampleArtifact(manifest.EvidenceRoot, ref)
		if err != nil {
			return []string{"winner peak sample artifact: " + err.Error()}
		}
		if sample.Run.CandidateID == ancestry.peakWinner {
			refs = append(refs, ref)
		}
	}
	seen := make(map[ArtifactRef]bool, len(refs))
	for _, ref := range refs {
		if seen[ref] {
			return []string{"winner replayed evidence contains a duplicate sample reference"}
		}
		seen[ref] = true
		sample, err := LoadSampleArtifact(manifest.EvidenceRoot, ref)
		if err != nil {
			return []string{"winner required sample artifact: " + err.Error()}
		}
		ancestry.requiredStages[string(sample.Run.Direction)+"\x00"+string(sample.Run.Stage)]++
		ancestry.requiredByDir[sample.Run.Direction]++
	}
	ancestry.requiredRefs = refs
	return nil
}

func exactCeilingWinnerRefSet(required []ArtifactRef, provided map[ArtifactRef]bool) bool {
	if len(required) != len(provided) {
		return false
	}
	for _, ref := range required {
		if !provided[ref] {
			return false
		}
	}
	return true
}

func loadCeilingWinnerProduction(manifest Manifest) (Manifest, SHA256Digest, []string) {
	if manifest.ManifestInput.ParentManifest == nil {
		return Manifest{}, "", nil
	}
	ref := *manifest.ManifestInput.ParentManifest
	var production Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, ref, "manifest", &production); err != nil {
		return Manifest{}, ref.SHA256, []string{"winner production manifest artifact: " + err.Error()}
	}
	if production.ManifestInput.ParentManifest == nil {
		return production, ref.SHA256, []string{"winner production manifest lacks experiment ancestry"}
	}
	return production, ref.SHA256, nil
}

func loadCeilingWinnerExperiment(manifest, production Manifest, productionDigest SHA256Digest) (Manifest, SHA256Digest, []string) {
	ref := *production.ManifestInput.ParentManifest
	var experiment Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, ref, "manifest", &experiment); err != nil {
		return Manifest{}, ref.SHA256, []string{"winner experiment manifest artifact: " + err.Error()}
	}
	var reasons []string
	if err := VerifyManifestTransition(experiment, ref.SHA256, production); err != nil {
		reasons = append(reasons, "winner experiment-production transition: "+err.Error())
	}
	if err := VerifyManifestTransition(production, productionDigest, manifest); err != nil {
		reasons = append(reasons, "winner production-ceiling transition: "+err.Error())
	}
	return experiment, ref.SHA256, reasons
}

func recordCeilingWinnerRef(sample Sample, seen map[string]SHA256Digest) (ArtifactRef, []string, bool) {
	ref, err := sampleArtifactRef(sample)
	if err != nil {
		return ArtifactRef{}, []string{"winner sample reference: " + err.Error()}, false
	}
	prior, duplicate := seen[sample.Run.ID]
	if duplicate && prior != ref.SHA256 {
		return ArtifactRef{}, []string{"replacement attempted for winner run " + sample.Run.ID}, false
	}
	if duplicate {
		return ArtifactRef{}, []string{"duplicate winner run " + sample.Run.ID}, false
	}
	seen[sample.Run.ID] = ref.SHA256
	return ref, nil, true
}

func validateCeilingWinnerIdentity(sample Sample, ancestry ceilingWinnerAncestry, rules FrozenRules) []string {
	reasons := validateCeilingWinnerSample(sample, ancestry.experimentDigest, ancestry.productionDigest, rules)
	reasons = append(reasons, validateCeilingWinnerCandidate(sample, ancestry)...)
	reasons = append(reasons, validateCeilingWinnerPrior(sample, ancestry)...)
	verdict := ValidateSample(ceilingWinnerSampleManifest(sample, ancestry), sample)
	if verdict.Status != "valid" {
		reasons = append(reasons, prefixReasons(sample.Run.ID, verdict.Reasons)...)
	}
	return reasons
}

func validateCeilingWinnerPrior(sample Sample, ancestry ceilingWinnerAncestry) []string {
	var want ArtifactRef
	switch sample.Run.Stage {
	case StagePreliminary:
		want = artifactRefByRole(ancestry.peak.InputDecisionRefs, string(StageScreening))
	case StageFinalist:
		want = artifactRefByRole(ancestry.peak.InputDecisionRefs, string(StagePreliminary))
	case StageFinalistRerun:
		want = artifactRefByRole(ancestry.peak.InputDecisionRefs, string(StageFinalist))
	case StageProduction:
		want = artifactRefByRole(ancestry.production.ManifestInput.ParentDecisionRefs, "finalist")
	default:
		return nil
	}
	if want == (ArtifactRef{}) || sample.Run.PriorDecisionRef != want {
		return []string{"winner sample prior decision reference mismatch"}
	}
	return nil
}

func validateCeilingWinnerCandidate(sample Sample, ancestry ceilingWinnerAncestry) []string {
	if isExperimentWinnerStage(sample.Run.Stage) && sample.CandidateID != ancestry.peakWinner {
		return []string{"winner experiment sample candidate differs from exact peak winner"}
	}
	if sample.Run.Stage == StageProduction && !productionCandidateMatches(ancestry.production, sample.CandidateID) {
		return []string{"winner production sample candidate differs from production manifest"}
	}
	return nil
}

func productionCandidateMatches(production Manifest, candidateID string) bool {
	return len(production.ManifestInput.Candidates) == 1 && candidateID == production.ManifestInput.Candidates[0].ID
}

func ceilingWinnerSampleManifest(sample Sample, ancestry ceilingWinnerAncestry) Manifest {
	if isExperimentWinnerStage(sample.Run.Stage) {
		return ancestry.experiment
	}
	return ancestry.production
}

func recordCeilingWinnerDirection(sample Sample, byDirection map[Direction][]float64, stageCounts map[string]int) {
	if !validDirectionValue(sample.Run.Direction) {
		return
	}
	byDirection[sample.Run.Direction] = append(byDirection[sample.Run.Direction], sample.GoodputMbps)
	stageCounts[string(sample.Run.Direction)+"\x00"+string(sample.Run.Stage)]++
}

func validateCeilingWinnerStageCounts(stageCounts, required map[string]int) []string {
	var reasons []string
	for key, count := range required {
		if stageCounts[key] != count {
			reasons = append(reasons, "winner stage counts differ from exact replayed evidence")
			break
		}
	}
	return reasons
}

func validateCeilingWinnerSample(sample Sample, experimentDigest, productionDigest SHA256Digest, rules FrozenRules) []string {
	var reasons []string
	wantDigest := productionDigest
	if isExperimentWinnerStage(sample.Run.Stage) {
		wantDigest = experimentDigest
	} else if sample.Run.Stage != StageProduction {
		reasons = append(reasons, "winner sample stage is neither finalist nor production")
	}
	if wantDigest == "" || sample.ManifestSHA256 != wantDigest {
		reasons = append(reasons, "winner sample lacks exact production manifest ancestry")
	}
	if !validWinnerCapacity(sample, rules) {
		reasons = append(reasons, "winner sample capacity is invalid")
	}
	if !validWinnerTrace(sample.Trace) {
		reasons = append(reasons, "winner sample route or trace is invalid")
	}
	if !validWinnerHealth(sample) {
		reasons = append(reasons, "winner sample health or cleanup is invalid")
	}
	if !finitePositive(sample.GoodputMbps) {
		reasons = append(reasons, "winner sample goodput is invalid")
	}
	return reasons
}

func isExperimentWinnerStage(stage Stage) bool {
	switch stage {
	case StagePreliminary, StageFinalist, StageFinalistRerun:
		return true
	default:
		return false
	}
}

func validWinnerCapacity(sample Sample, rules FrozenRules) bool {
	return sample.Started && sample.Capacity.Valid && sample.Capacity.Mbps >= rules.CapacityMinimumMbps &&
		sample.Capacity.Direction == sample.Run.Direction
}

func validWinnerTrace(trace TraceEvidence) bool {
	return trace.PublicUDP && trace.StrictValid && (trace.Engine == "bulk-packets-v1" || trace.Engine == "quic-blocks-v1")
}

func validWinnerHealth(sample Sample) bool {
	return sample.Health.Healthy && sample.Cleanup.ScopedRootRemoved && sample.Cleanup.ProcessesRemoved &&
		sample.Cleanup.SocketsRemoved && sample.Cleanup.PayloadsRemoved
}

func validateCeilingWinnerDirections(byDirection map[Direction][]float64, required map[Direction]int, maxCV float64) []string {
	var reasons []string
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		values := byDirection[direction]
		if len(values) != required[direction] {
			reasons = append(reasons, fmt.Sprintf("%s winner sample count = %d, want %d", direction, len(values), required[direction]))
			continue
		}
		if statistics(values).CoefficientOfVariation > maxCV {
			reasons = append(reasons, string(direction)+" winner sample CV exceeds limit")
		}
	}
	return reasons
}

func validateCeilingSweepSet(root string, manifest Manifest, sweeps []CeilingSweepPoint, rules FrozenRules) ([]ArtifactRef, map[ceilingSweepGroupKey]ceilingPlateauBand, float64, float64, []string) {
	wantLoads := []float64{1.2, 1.5, 1.8, 2.1, 2.4}
	var refs []ArtifactRef
	var reasons []string
	if len(sweeps) != 20 {
		reasons = append(reasons, fmt.Sprintf("ceiling sweep point count = %d, want exactly 20", len(sweeps)))
	}
	seenRefs := make(map[string]bool)
	groupPlateaus := make(map[ceilingSweepGroupKey]ceilingPlateauBand, 4)
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		for _, order := range []string{"ascending", "descending"} {
			expectedLoads := append([]float64(nil), wantLoads...)
			if order == "descending" {
				reverseFloats(expectedLoads)
			}
			groupRefs, start, end, groupReasons := validateCeilingSweepGroup(root, manifest, sweeps, direction, order, expectedLoads, rules, seenRefs)
			refs = append(refs, groupRefs...)
			reasons = append(reasons, groupReasons...)
			if start != 0 {
				groupPlateaus[ceilingSweepGroupKey{Direction: direction, Order: order}] = ceilingPlateauBand{Start: start, End: end}
			}
		}
	}
	plateauStart, plateauEnd, common := commonCeilingPlateau(groupPlateaus)
	if len(groupPlateaus) == 4 && !common {
		reasons = append(reasons, "ceiling sweep group plateaus have no common intersection")
	}
	reasons = append(reasons, validateGlobalCeilingSweepCaptureOrder(root, manifest, sweeps)...)
	sortArtifactRefs(refs)
	return refs, groupPlateaus, plateauStart, plateauEnd, reasons
}

func commonCeilingPlateau(groups map[ceilingSweepGroupKey]ceilingPlateauBand) (float64, float64, bool) {
	if len(groups) != 4 {
		return 0, 0, false
	}
	start, end := 0.0, math.Inf(1)
	for _, band := range groups {
		start = math.Max(start, band.Start)
		end = math.Min(end, band.End)
	}
	if !finitePositive(start) || math.IsInf(end, 0) || start > end {
		return 0, 0, false
	}
	return start, end, true
}

func validateGlobalCeilingSweepCaptureOrder(root string, manifest Manifest, sweeps []CeilingSweepPoint) []string {
	points, err := orderedFrozenCeilingSweepPoints(manifest, sweeps)
	if err != nil {
		return []string{err.Error()}
	}
	var previousAfter time.Time
	for _, point := range points {
		beforeTime, afterTime, bracketErr := loadCeilingCapacityBracket(root, point)
		if bracketErr != nil {
			return []string{"global ceiling sweep capture order cannot be replayed"}
		}
		if !previousAfter.IsZero() && !previousAfter.Before(beforeTime) {
			return []string{"global ceiling sweep capture order overlaps or regresses"}
		}
		previousAfter = afterTime
	}
	return nil
}

func orderedFrozenCeilingSweepPoints(manifest Manifest, sweeps []CeilingSweepPoint) ([]CeilingSweepPoint, error) {
	byRunID := make(map[string]CeilingSweepPoint, len(sweeps))
	for _, point := range sweeps {
		byRunID[point.RunID] = point
	}
	var ordered []CeilingSweepPoint
	for _, schedule := range manifest.ManifestInput.Schedules {
		if !strings.HasPrefix(schedule.Stage, "ceiling-sweep-") {
			continue
		}
		for _, runID := range schedule.RunIDs {
			point, ok := byRunID[runID]
			if !ok {
				return nil, fmt.Errorf("global ceiling sweep capture order is incomplete")
			}
			ordered = append(ordered, point)
		}
	}
	return ordered, nil
}

func loadCeilingCapacityBracket(root string, point CeilingSweepPoint) (time.Time, time.Time, error) {
	var before, after ceilingCapacityRecord
	if err := verifyDecodeEvidence(root, point.Capacity, "capacity", &before); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if err := verifyDecodeEvidence(root, point.CapacityAfter, "capacity", &after); err != nil {
		return time.Time{}, time.Time{}, err
	}
	beforeTime, beforeErr := parseCanonicalUTCTime(before.ObservedAtUTC)
	afterTime, afterErr := parseCanonicalUTCTime(after.ObservedAtUTC)
	return beforeTime, afterTime, errors.Join(beforeErr, afterErr)
}

func validateCeilingSweepGroup(root string, manifest Manifest, sweeps []CeilingSweepPoint, direction Direction, order string, wantLoads []float64, rules FrozenRules, seenRefs map[string]bool) ([]ArtifactRef, float64, float64, []string) {
	points := ceilingSweepGroup(sweeps, direction, order)
	if len(points) != len(wantLoads) {
		return nil, 0, 0, []string{fmt.Sprintf("%s %s sweep point count = %d, want 5", direction, order, len(points))}
	}
	offered := make([]float64, len(points))
	delivered := make([]float64, len(points))
	loss := make([]float64, len(points))
	queue := make([]float64, len(points))
	var refs []ArtifactRef
	var reasons []string
	for index, point := range points {
		offered[index], delivered[index], loss[index], queue[index] = point.OfferedGbps, point.DeliveredGbps, point.LossRatio, point.QueuePressure
		reasons = append(reasons, validateCeilingSweepPoint(manifest, point, direction, order, index+1, wantLoads[index], rules)...)
		pointRefs, refReasons := collectCeilingSweepRefs(root, point, seenRefs)
		refs = append(refs, pointRefs...)
		reasons = append(reasons, refReasons...)
	}
	if order == "descending" {
		reverseFloats(offered)
		reverseFloats(delivered)
		reverseFloats(loss)
		reverseFloats(queue)
	}
	passed, start, end := ceilingPlateau(offered, delivered, loss, queue)
	if !passed {
		reasons = append(reasons, fmt.Sprintf("%s %s sweep does not prove plateau", direction, order))
		return refs, 0, 0, reasons
	}
	return refs, start, end, reasons
}

func ceilingSweepGroup(sweeps []CeilingSweepPoint, direction Direction, order string) []CeilingSweepPoint {
	var points []CeilingSweepPoint
	for _, point := range sweeps {
		if point.Direction == direction && point.Order == order {
			points = append(points, point)
		}
	}
	return points
}

func reverseFloats(values []float64) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func validateCeilingSweepPoint(manifest Manifest, point CeilingSweepPoint, direction Direction, order string, sequence int, wantLoad float64, rules FrozenRules) []string {
	prefix := fmt.Sprintf("%s %s", direction, order)
	checks := []ceilingCheck{
		{point.OfferedGbps == wantLoad, prefix + " sweep offered loads are not frozen"},
		{point.Sequence == sequence && validCanonicalTime(point.ObservedAtUTC), prefix + " sweep execution order or timestamp is invalid"},
		{validateFrozenCeilingSweepIdentity(manifest, point, direction, order, sequence) == nil, "ceiling sweep does not bind exact frozen row identity"},
		{qualifyingCeilingPoint(point, rules), fmt.Sprintf("%s %.1f Gbps point lacks qualifying capacity, route, datagram, or health", prefix, point.OfferedGbps)},
		{validCeilingCapacityControl(manifest, point), "ceiling capacity control is not TCP port 8123 with 8 flows for 20 seconds"},
		{validPhysicalCeilingUDP(point), "ceiling UDP result is outside physical ranges"},
		{exactCounterFamilies(point.CounterFamilies), fmt.Sprintf("%s %.1f Gbps point lacks counter families", prefix, point.OfferedGbps)},
	}
	return failedCeilingChecks(checks)
}

func qualifyingCeilingPoint(point CeilingSweepPoint, rules FrozenRules) bool {
	return point.CapacityMbps >= rules.CapacityMinimumMbps && point.DatagramBytes == 1400 && point.PublicUDP && point.Healthy
}

func validCeilingCapacityControl(manifest Manifest, point CeilingSweepPoint) bool {
	return point.CapacityTCPPort == manifest.ManifestInput.CapacityTCPPort && point.CapacityParallelFlows == 8 && point.CapacityDurationSeconds == 20
}

func validPhysicalCeilingUDP(point CeilingSweepPoint) bool {
	return finitePositive(point.OfferedGbps) && finitePositive(point.DeliveredGbps) && point.DeliveredGbps <= point.OfferedGbps &&
		validUnitInterval(point.LossRatio) && finiteNonnegative(point.QueuePressure)
}

func validUnitInterval(value float64) bool {
	return finiteNonnegative(value) && value <= 1
}

func finiteNonnegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func collectCeilingSweepRefs(root string, point CeilingSweepPoint, seenRefs map[string]bool) ([]ArtifactRef, []string) {
	entries := []struct {
		role string
		ref  ArtifactRef
	}{
		{role: "capacity", ref: point.Capacity},
		{role: "capacity", ref: point.CapacityAfter},
		{role: "udp-result", ref: point.UDPResult},
		{role: "health", ref: point.Health},
	}
	var refs []ArtifactRef
	var reasons []string
	if err := verifyCeilingSweepPointArtifact(root, point); err != nil {
		reasons = append(reasons, "ceiling sweep point artifact: "+err.Error())
	} else if identity := point.Artifact.Path + "\x00" + string(point.Artifact.SHA256); seenRefs[identity] {
		reasons = append(reasons, "duplicate ceiling sweep point reference")
	} else {
		seenRefs[identity] = true
		refs = append(refs, point.Artifact)
	}
	if err := verifyCeilingSweepArtifacts(root, point); err != nil {
		reasons = append(reasons, "ceiling sweep artifact semantic validation: "+err.Error())
	}
	for _, entry := range entries {
		if err := validateArtifactRef(entry.ref, entry.role); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s sweep reference: %v", entry.role, err))
			continue
		}
		identity := entry.ref.Path + "\x00" + string(entry.ref.SHA256)
		if seenRefs[identity] {
			reasons = append(reasons, "duplicate ceiling sweep reference")
			continue
		}
		seenRefs[identity] = true
	}
	return refs, reasons
}

func verifyCeilingSweepPointArtifact(root string, point CeilingSweepPoint) error {
	opened, err := LoadCeilingSweepArtifact(root, point.Artifact)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(opened, point) {
		return fmt.Errorf("sweep point semantic mismatch")
	}
	return nil
}

func verifyCeilingSweepArtifacts(root string, point CeilingSweepPoint) error {
	if err := verifyCeilingCapacityArtifacts(root, point); err != nil {
		return err
	}
	if err := verifyCeilingUDPArtifact(root, point); err != nil {
		return err
	}
	return verifyCeilingHealthArtifact(root, point)
}

func verifyCeilingCapacityArtifacts(root string, point CeilingSweepPoint) error {
	var before ceilingCapacityRecord
	if err := verifyDecodeEvidence(root, point.Capacity, "capacity", &before); err != nil {
		return err
	}
	var after ceilingCapacityRecord
	if err := verifyDecodeEvidence(root, point.CapacityAfter, "capacity", &after); err != nil {
		return err
	}
	wantBefore := ceilingCapacityRecord{1, "capacity", "before", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps, point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, before.ObservedAtUTC}
	wantAfter := ceilingCapacityRecord{1, "capacity", "after", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps, point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, after.ObservedAtUTC}
	beforeTime, beforeErr := parseCanonicalUTCTime(before.ObservedAtUTC)
	pointTime, pointErr := parseCanonicalUTCTime(point.ObservedAtUTC)
	afterTime, afterErr := parseCanonicalUTCTime(after.ObservedAtUTC)
	if !ceilingCapacitySemanticsMatch(before, wantBefore, after, wantAfter, beforeTime, pointTime, afterTime, beforeErr, pointErr, afterErr) {
		return fmt.Errorf("capacity semantic mismatch")
	}
	return nil
}

func ceilingCapacitySemanticsMatch(before, wantBefore, after, wantAfter ceilingCapacityRecord, beforeTime, pointTime, afterTime time.Time, beforeErr, pointErr, afterErr error) bool {
	return before == wantBefore && after == wantAfter && beforeErr == nil && pointErr == nil && afterErr == nil &&
		beforeTime.Before(pointTime) && pointTime.Before(afterTime)
}

func verifyCeilingUDPArtifact(root string, point CeilingSweepPoint) error {
	var udpResult ceilingUDPResultRecord
	if err := verifyDecodeEvidence(root, point.UDPResult, "udp-result", &udpResult); err != nil {
		return err
	}
	wantUDP := ceilingUDPResultRecord{1, "udp-result", point.Direction, point.Order, point.OfferedGbps, point.DeliveredGbps, point.LossRatio, point.QueuePressure, point.DatagramBytes, point.PublicUDP, point.CounterFamilies}
	if !reflect.DeepEqual(udpResult, wantUDP) {
		return fmt.Errorf("UDP result semantic mismatch")
	}
	return nil
}

func verifyCeilingHealthArtifact(root string, point CeilingSweepPoint) error {
	var health ceilingHealthRecord
	if err := verifyDecodeEvidence(root, point.Health, "health", &health); err != nil {
		return err
	}
	wantHealth := ceilingHealthRecord{1, "health", point.Direction, point.Order, point.OfferedGbps, point.Healthy}
	if health != wantHealth {
		return fmt.Errorf("health semantic mismatch")
	}
	return nil
}

func exactCounterFamilies(input []string) bool {
	want := []string{"cpu", "interface", "softnet", "udp"}
	got := append([]string(nil), input...)
	sort.Strings(got)
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
