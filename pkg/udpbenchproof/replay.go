// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"fmt"
	"reflect"
)

// ReplayDecision reopens and recomputes a generic authorization decision and
// every decision that authorized it. Passed is never itself authorization.
func ReplayDecision(manifest Manifest, decision Decision) error {
	state := &decisionReplayState{
		visiting: make(map[ArtifactRef]bool),
		done:     make(map[ArtifactRef]bool),
		runs:     make(map[string]ArtifactRef),
	}
	return state.replay(manifest, decision)
}

type decisionReplayState struct {
	visiting map[ArtifactRef]bool
	done     map[ArtifactRef]bool
	runs     map[string]ArtifactRef
}

func (state *decisionReplayState) replay(manifest Manifest, decision Decision) error {
	ref := decision.Artifact
	if err := validateReplayDecisionRef(ref, decision.Stage); err != nil {
		return err
	}
	if state.done[ref] {
		return nil
	}
	if state.visiting[ref] {
		return fmt.Errorf("decision authorization cycle at %s", ref.Path)
	}
	state.visiting[ref] = true
	defer delete(state.visiting, ref)

	decoded, err := openReplayDecision(manifest, decision)
	if err != nil {
		return err
	}
	prior, err := state.replayPrior(manifest, decoded, decision.EvidenceRoot)
	if err != nil {
		return err
	}
	samples, err := state.loadReplaySamples(decision.EvidenceRoot, decoded)
	if err != nil {
		return err
	}
	recomputed, err := evaluateAuthorized(manifest, samples, decoded.Stage, prior)
	if err != nil {
		return fmt.Errorf("recompute %s decision: %w", decoded.Stage, err)
	}
	if !reflect.DeepEqual(recomputed, decoded) {
		return fmt.Errorf("%s decision does not replay from exact authorization and sample artifacts", decoded.Stage)
	}
	state.done[ref] = true
	return nil
}

func openReplayDecision(manifest Manifest, decision Decision) (Decision, error) {
	ref := decision.Artifact
	var decoded Decision
	if err := verifyDecodeEvidence(decision.EvidenceRoot, ref, ref.Role, &decoded); err != nil {
		return Decision{}, fmt.Errorf("open %s decision: %w", decision.Stage, err)
	}
	want := decision
	want.Artifact = ArtifactRef{}
	want.EvidenceRoot = ""
	if !reflect.DeepEqual(decoded, want) {
		return Decision{}, fmt.Errorf("%s decision value differs from exact artifact", decision.Stage)
	}
	if !decoded.Passed || len(decoded.Reasons) != 0 {
		return Decision{}, fmt.Errorf("%s decision did not pass", decoded.Stage)
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil || decoded.ManifestSHA256 != manifestDigest {
		return Decision{}, fmt.Errorf("%s decision has wrong manifest ancestry", decoded.Stage)
	}
	return decoded, nil
}

func (state *decisionReplayState) loadReplaySamples(root string, decision Decision) ([]Sample, error) {
	samples := make([]Sample, 0, len(decision.SampleRefs))
	for _, sampleRef := range decision.SampleRefs {
		sample, loadErr := LoadSampleArtifact(root, sampleRef)
		if loadErr != nil {
			return nil, fmt.Errorf("%s sample replay: %w", decision.Stage, loadErr)
		}
		if previous, exists := state.runs[sample.Run.ID]; exists && previous != sampleRef {
			return nil, fmt.Errorf("replacement sample attempted for scheduled run %s", sample.Run.ID)
		}
		state.runs[sample.Run.ID] = sampleRef
		samples = append(samples, sample)
	}
	return samples, nil
}

func (state *decisionReplayState) replayPrior(manifest Manifest, decision Decision, root string) (Decision, error) {
	if decision.Stage == StageScreening {
		if len(decision.InputDecisionRefs) != 0 {
			return Decision{}, fmt.Errorf("screening decision must be an authorization root")
		}
		return Decision{}, nil
	}
	priorStage, err := replayPriorStage(decision.Stage)
	if err != nil {
		return Decision{}, err
	}
	priorRef := artifactRefByRole(decision.InputDecisionRefs, string(priorStage))
	if priorRef == (ArtifactRef{}) {
		return Decision{}, fmt.Errorf("%s decision is missing exact %s authorization", decision.Stage, priorStage)
	}
	var prior Decision
	if err := verifyDecodeEvidence(root, priorRef, string(priorStage), &prior); err != nil {
		return Decision{}, fmt.Errorf("open %s authorization: %w", priorStage, err)
	}
	prior.Artifact = priorRef
	prior.EvidenceRoot = root
	if err := state.replay(manifest, prior); err != nil {
		return Decision{}, err
	}
	return prior, nil
}

func replayPriorStage(stage Stage) (Stage, error) {
	switch stage {
	case StagePreliminary:
		return StageScreening, nil
	case StageFinalist:
		return StagePreliminary, nil
	case StageFinalistRerun:
		return StageFinalist, nil
	default:
		return "", fmt.Errorf("stage %s is not a replayable generic decision", stage)
	}
}

func validateReplayDecisionRef(ref ArtifactRef, stage Stage) error {
	wantRole := string(stage)
	if stage == StageFinalist && ref.Role == "peak" {
		wantRole = "peak"
	}
	if stage == StageFinalistRerun && (ref.Role == "finalist" || ref.Role == "peak") {
		wantRole = ref.Role
	}
	if err := validateArtifactRef(ref, wantRole); err != nil {
		return fmt.Errorf("%s decision artifact: %w", stage, err)
	}
	return nil
}

func verifyProductionAuthorization(production Manifest) error {
	if production.ManifestInput.Kind != ManifestProduction || production.EvidenceRoot == "" || production.ManifestInput.ParentManifest == nil {
		return fmt.Errorf("production authorization lacks bound experiment ancestry")
	}
	parentRef := *production.ManifestInput.ParentManifest
	var experiment Manifest
	if err := verifyDecodeEvidence(production.EvidenceRoot, parentRef, "manifest", &experiment); err != nil {
		return fmt.Errorf("production experiment manifest: %w", err)
	}
	experiment.EvidenceRoot = production.EvidenceRoot
	if err := VerifyManifestTransition(experiment, parentRef.SHA256, production); err != nil {
		return fmt.Errorf("experiment-production transition: %w", err)
	}
	peakRef := artifactRefByRole(production.ManifestInput.ParentDecisionRefs, "finalist")
	var peak Decision
	if err := verifyDecodeEvidence(production.EvidenceRoot, peakRef, "finalist", &peak); err != nil {
		return fmt.Errorf("production finalist decision: %w", err)
	}
	if peak.Stage != StageFinalist && peak.Stage != StageFinalistRerun {
		return fmt.Errorf("production finalist authorization has stage %s", peak.Stage)
	}
	peak.Artifact = peakRef
	peak.EvidenceRoot = production.EvidenceRoot
	if err := ReplayDecision(experiment, peak); err != nil {
		return fmt.Errorf("production finalist authorization: %w", err)
	}
	return nil
}

func verifyChildManifestAuthorization(child Manifest, wantKind ManifestKind) (Manifest, error) {
	if child.ManifestInput.Kind != wantKind || child.EvidenceRoot == "" || child.ManifestInput.ParentManifest == nil {
		return Manifest{}, fmt.Errorf("%s authorization lacks bound production ancestry", wantKind)
	}
	parentRef := *child.ManifestInput.ParentManifest
	var production Manifest
	if err := verifyDecodeEvidence(child.EvidenceRoot, parentRef, "manifest", &production); err != nil {
		return Manifest{}, fmt.Errorf("%s production manifest: %w", wantKind, err)
	}
	production.EvidenceRoot = child.EvidenceRoot
	if err := VerifyManifestTransition(production, parentRef.SHA256, child); err != nil {
		return Manifest{}, fmt.Errorf("production-%s transition: %w", wantKind, err)
	}
	if err := verifyProductionAuthorization(production); err != nil {
		return Manifest{}, err
	}
	return production, nil
}
