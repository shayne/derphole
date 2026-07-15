// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"fmt"
	"reflect"
	"sort"
)

// BuildSchedule creates a deterministic schedule bound to a validated manifest.
func BuildSchedule(manifest Manifest, stage Stage, authorization ScheduleAuthorization) ([]ScheduledRun, error) {
	if err := validateScheduleAuthorization(manifest, stage, authorization); err != nil {
		return nil, err
	}
	prior := authorization.Peak
	switch stage {
	case StageFleet:
		return frozenRuns(manifest, string(stage), stage, nil, authorization.Prerequisite.Artifact)
	case StageAcceptance, StageCeiling:
		return buildAuthorizedSchedule(manifest, stage, authorization.Fleet)
	default:
		return buildAuthorizedSchedule(manifest, stage, prior)
	}
}

func validateScheduleAuthorization(manifest Manifest, stage Stage, authorization ScheduleAuthorization) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	validators := map[Stage]func() error{
		StageScreening: func() error {
			if !reflect.DeepEqual(authorization, ScheduleAuthorization{}) {
				return fmt.Errorf("screening schedule must not consume prior authorization")
			}
			return nil
		},
		StagePreliminary:   func() error { return validatePriorDecisionArtifact(manifest, stage, authorization.Peak) },
		StageFinalist:      func() error { return validatePriorDecisionArtifact(manifest, stage, authorization.Peak) },
		StageFinalistRerun: func() error { return validatePriorDecisionArtifact(manifest, stage, authorization.Peak) },
		StageProduction:    func() error { return validatePriorDecisionArtifact(manifest, stage, authorization.Peak) },
		StageFleet:         func() error { return validateFleetScheduleAuthorization(manifest, authorization.Prerequisite) },
		StageAcceptance:    func() error { return validateChildScheduleAuthorization(manifest, authorization, ManifestAcceptance) },
		StageCeiling:       func() error { return validateChildScheduleAuthorization(manifest, authorization, ManifestCeiling) },
	}
	validate, ok := validators[stage]
	if !ok {
		return fmt.Errorf("unsupported schedule stage %q", stage)
	}
	return validate()
}

func validateFleetScheduleAuthorization(production Manifest, prerequisite PrerequisiteDecision) error {
	manifestDigest, err := canonicalDigest(production)
	if err != nil {
		return err
	}
	if err := verifyFleetAuthorization(production, manifestDigest, prerequisite, prerequisite.Artifact.SHA256); err != nil {
		return fmt.Errorf("fleet schedule prerequisite: %w", err)
	}
	return nil
}

func validateChildScheduleAuthorization(child Manifest, authorization ScheduleAuthorization, kind ManifestKind) error {
	production, err := verifyChildManifestAuthorization(child, kind)
	if err != nil {
		return err
	}
	prerequisiteRef, _, err := validateChildScheduleDecisionRefs(child, production, authorization, kind)
	if err != nil {
		return err
	}
	return replayChildScheduleAuthorization(child, production, authorization, kind, prerequisiteRef)
}

func validateChildScheduleDecisionRefs(child, production Manifest, authorization ScheduleAuthorization, kind ManifestKind) (ArtifactRef, ArtifactRef, error) {
	prerequisiteRef := artifactRefByRole(child.ManifestInput.ParentDecisionRefs, "prerequisite")
	fleetRef := artifactRefByRole(child.ManifestInput.ParentDecisionRefs, "fleet")
	if kind == ManifestCeiling {
		if err := validateCeilingSchedulePeak(child, production, authorization.Peak); err != nil {
			return ArtifactRef{}, ArtifactRef{}, err
		}
		prerequisiteRef = artifactRefByRole(authorization.Fleet.InputDecisionRefs, "prerequisite")
	}
	if authorization.Prerequisite.Artifact != prerequisiteRef || authorization.Fleet.Artifact != fleetRef {
		return ArtifactRef{}, ArtifactRef{}, fmt.Errorf("%s schedule proofs are not exact manifest-bound decisions", kind)
	}
	return prerequisiteRef, fleetRef, nil
}

func replayChildScheduleAuthorization(child, production Manifest, authorization ScheduleAuthorization, kind ManifestKind, prerequisiteRef ArtifactRef) error {
	productionDigest, _ := canonicalDigest(production)
	if err := verifyChildSchedulePrerequisite(production, productionDigest, authorization.Prerequisite, prerequisiteRef.SHA256, kind); err != nil {
		return err
	}
	if reasons := replayFleetDecision(child.EvidenceRoot, production, *child.ManifestInput.ParentManifest, authorization.Fleet); len(reasons) != 0 {
		return fmt.Errorf("%s schedule fleet replay: %s", kind, reasons[0])
	}
	if kind == ManifestAcceptance && !authorization.Prerequisite.Passed {
		return fmt.Errorf("acceptance schedule requires passed >2 Gbps prerequisite")
	}
	return nil
}

func verifyChildSchedulePrerequisite(production Manifest, productionDigest SHA256Digest, prerequisite PrerequisiteDecision, prerequisiteDigest SHA256Digest, kind ManifestKind) error {
	if kind == ManifestCeiling {
		if err := verifyHardCeilingFleetAuthorization(production, productionDigest, prerequisite, prerequisiteDigest); err != nil {
			return fmt.Errorf("ceiling schedule requires exact throughput-only failed prerequisite: %w", err)
		}
		return nil
	}
	return verifyFleetAuthorization(production, productionDigest, prerequisite, prerequisiteDigest)
}

func validateCeilingSchedulePeak(child, production Manifest, peak Decision) error {
	peakRef := artifactRefByRole(child.ManifestInput.ParentDecisionRefs, "peak")
	if peak.Artifact != peakRef {
		return fmt.Errorf("ceiling schedule peak is not exact manifest-bound decision")
	}
	var experiment Manifest
	if err := verifyDecodeEvidence(child.EvidenceRoot, *production.ManifestInput.ParentManifest, "manifest", &experiment); err != nil {
		return err
	}
	return ReplayDecision(experiment, peak)
}

func buildAuthorizedSchedule(manifest Manifest, stage Stage, prior Decision) ([]ScheduledRun, error) {
	switch stage {
	case StageScreening:
		return frozenRuns(manifest, "screening", stage, nil, ArtifactRef{})
	case StageProduction, StageAcceptance, StageFleet:
		return frozenRuns(manifest, string(stage), stage, nil, prior.Artifact)
	case StagePreliminary, StageFinalist, StageFinalistRerun:
		candidates, err := scheduleCandidates(manifest, stage, prior)
		if err != nil {
			return nil, err
		}
		return frozenRuns(manifest, string(stage), stage, candidates, prior.Artifact)
	case StageCeiling:
		return frozenCeilingRuns(manifest, prior.Artifact)
	default:
		return nil, fmt.Errorf("unsupported schedule stage %q", stage)
	}
}

func validateScheduleInputs(manifest Manifest, stage Stage, prior Decision) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if stage == StageScreening {
		if !reflect.DeepEqual(prior, Decision{}) {
			return fmt.Errorf("screening schedule must not consume a prior decision")
		}
		return nil
	}
	return validatePriorDecisionArtifact(manifest, stage, prior)
}

func validatePriorDecisionArtifact(manifest Manifest, stage Stage, prior Decision) error {
	expectedStage, err := expectedPriorStage(stage)
	if err != nil {
		return err
	}
	expectedStage = effectivePriorStage(stage, prior.Stage, expectedStage)
	if !prior.Passed || prior.Stage != expectedStage {
		return fmt.Errorf("%s schedule requires passed %s decision", stage, expectedStage)
	}
	if stage == StageFinalistRerun && !prior.RerunRequired {
		return fmt.Errorf("finalist rerun was not authorized by capacity variation")
	}
	if err := ReplayDecision(manifestForPriorReplay(manifest, stage), prior); err != nil {
		return fmt.Errorf("%s prior decision replay: %w", stage, err)
	}
	if err := validatePriorManifestAncestry(manifest, stage, prior); err != nil {
		return err
	}
	return validateProductionScheduleTransition(manifest, stage)
}

func effectivePriorStage(stage, priorStage, expected Stage) Stage {
	if stage == StageProduction && priorStage == StageFinalistRerun {
		return StageFinalistRerun
	}
	return expected
}

func validateProductionScheduleTransition(manifest Manifest, stage Stage) error {
	if stage != StageProduction {
		return nil
	}
	return replayProductionTransition(manifest)
}

func manifestForPriorReplay(manifest Manifest, stage Stage) Manifest {
	if stage != StageProduction || manifest.ManifestInput.ParentManifest == nil {
		return manifest
	}
	var parent Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, *manifest.ManifestInput.ParentManifest, "manifest", &parent); err != nil {
		return manifest
	}
	parent.EvidenceRoot = manifest.EvidenceRoot
	return parent
}

func replayProductionTransition(manifest Manifest) error {
	if manifest.ManifestInput.ParentManifest == nil {
		return fmt.Errorf("production schedule is missing experiment parent")
	}
	var parent Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, *manifest.ManifestInput.ParentManifest, "manifest", &parent); err != nil {
		return fmt.Errorf("production parent manifest replay: %w", err)
	}
	parent.EvidenceRoot = manifest.EvidenceRoot
	if err := VerifyManifestTransition(parent, manifest.ManifestInput.ParentManifest.SHA256, manifest); err != nil {
		return fmt.Errorf("production manifest transition replay: %w", err)
	}
	return nil
}

func expectedPriorStage(stage Stage) (Stage, error) {
	switch stage {
	case StagePreliminary:
		return StageScreening, nil
	case StageFinalist:
		return StagePreliminary, nil
	case StageFinalistRerun:
		return StageFinalist, nil
	case StageProduction:
		return StageFinalist, nil
	case StageFleet:
		return StageProduction, nil
	case StageAcceptance:
		return StageFleet, nil
	case StageCeiling:
		return StageFinalist, nil
	default:
		return "", fmt.Errorf("unsupported dependent schedule stage %q", stage)
	}
}

func validatePriorManifestAncestry(manifest Manifest, stage Stage, prior Decision) error {
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return err
	}
	wantManifest := manifestDigest
	if stage == StageProduction && manifest.ManifestInput.ParentManifest != nil {
		wantManifest = manifest.ManifestInput.ParentManifest.SHA256
		if !artifactRefInSlice(prior.Artifact, manifest.ManifestInput.ParentDecisionRefs) {
			return fmt.Errorf("production schedule prior is not exact manifest-bound finalist decision")
		}
	}
	if prior.ManifestSHA256 != wantManifest {
		return fmt.Errorf("%s prior decision has wrong manifest ancestry", stage)
	}
	return nil
}

func scheduleCandidates(manifest Manifest, stage Stage, prior Decision) ([]string, error) {
	candidates := append([]string(nil), prior.PeakFrontier...)
	if stage == StageFinalistRerun {
		candidates = append([]string(nil), prior.FinalistCandidates...)
	}
	if len(candidates) == 0 && prior.SelectedCandidate != "" && stage != StageFinalistRerun {
		candidates = []string{prior.SelectedCandidate}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%s schedule has no prior candidates", stage)
	}
	for _, candidate := range candidates {
		if _, ok := manifestCandidate(manifest, candidate); !ok {
			return nil, fmt.Errorf("%s schedule references candidate %q outside manifest", stage, candidate)
		}
	}
	ordered := append([]string(nil), candidates...)
	sort.Strings(ordered)
	if !reflect.DeepEqual(ordered, compactStrings(ordered)) {
		return nil, fmt.Errorf("%s schedule contains duplicate prior candidates", stage)
	}
	candidates = ordered
	return candidates, nil
}

func frozenRuns(manifest Manifest, frozenStage string, stage Stage, candidates []string, priorRef ArtifactRef) ([]ScheduledRun, error) {
	allowed := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		allowed[candidate] = true
	}
	for _, schedule := range manifest.ManifestInput.Schedules {
		if schedule.Stage != frozenStage {
			continue
		}
		runs := make([]ScheduledRun, 0, len(schedule.RunIDs))
		for index := range schedule.RunIDs {
			if len(allowed) != 0 && !allowed[schedule.CandidateOrder[index]] {
				continue
			}
			runs = append(runs, ScheduledRun{
				ID:               schedule.RunIDs[index],
				Stage:            stage,
				CandidateID:      schedule.CandidateOrder[index],
				HostID:           schedule.HostOrder[index],
				Direction:        manifestDirection(schedule.DirectionOrder[index]),
				SizeBytes:        manifest.ManifestInput.Payload.Bytes,
				Order:            index + 1,
				CapacityRequired: true,
				Block:            schedule.BlockOrder[index],
				Schedule:         schedule.Stage,
				Role:             schedule.RunRoles[index],
				PriorDecisionRef: priorRef,
			})
		}
		return runs, nil
	}
	return nil, fmt.Errorf("manifest has no frozen %s schedule", frozenStage)
}

func frozenCeilingRuns(manifest Manifest, priorRef ArtifactRef) ([]ScheduledRun, error) {
	var runs []ScheduledRun
	for _, schedule := range manifest.ManifestInput.Schedules {
		stageRuns, err := frozenRuns(manifest, schedule.Stage, StageCeiling, nil, priorRef)
		if err != nil {
			return nil, err
		}
		runs = append(runs, stageRuns...)
	}
	return runs, nil
}

func finalistRotation(input []string) [][]string {
	candidates := append([]string(nil), input...)
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return [][]string{}
	}
	if len(candidates) == 3 {
		return [][]string{
			{candidates[0], candidates[1], candidates[2]},
			{candidates[2], candidates[1], candidates[0]},
			{candidates[1], candidates[2], candidates[0]},
		}
	}
	rotations := make([][]string, 3)
	for block := range rotations {
		rotation := make([]string, len(candidates))
		for index := range candidates {
			rotation[index] = candidates[(index+block)%len(candidates)]
		}
		rotations[block] = rotation
	}
	return rotations
}
