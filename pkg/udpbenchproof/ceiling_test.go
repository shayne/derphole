// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type ceilingFixture struct {
	OfferedGbps    []float64 `json:"offered_gbps"`
	DeliveredGbps  []float64 `json:"delivered_gbps"`
	LossRatio      []float64 `json:"loss_ratio"`
	ExpectedPassed bool      `json:"expected_passed"`
	ExpectedStart  float64   `json:"expected_start_gbps"`
	ExpectedEnd    float64   `json:"expected_end_gbps"`
	ExpectedReason string    `json:"expected_reason"`
}

func TestCeilingPlateauRequiresOfferedGrowthWithoutDeliveredScaling(t *testing.T) {
	for _, name := range []string{"ceiling-plateau-pass.json", "ceiling-offered-load-still-scales.json"} {
		t.Run(name, func(t *testing.T) {
			fixture := loadFixtureTwice[ceilingFixture](t, name)
			experiment := mustManifest(t, validExperimentInput())
			production := mustManifest(t, validProductionInput(t, experiment))
			ceiling := boundCeilingManifest(t, production, experiment)
			sweeps := ceilingSweepFixture(fixture)
			profiles := ceilingProfileFixture("kernel-packet-processing")
			bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
			samples := ceilingWinnerSamples(t, ceiling, 1400)
			first := DecideCeiling(ceiling, sweeps, profiles, samples)
			second := DecideCeiling(ceiling, sweeps, profiles, samples)
			assertByteIdenticalJSON(t, first, second)
			if first.Passed != fixture.ExpectedPassed || first.PlateauStartGbps != fixture.ExpectedStart || first.PlateauEndGbps != fixture.ExpectedEnd {
				t.Fatalf("%s public ceiling decision = %#v", name, first)
			}
			if !fixture.ExpectedPassed && !containsReason(first.Reasons, fixture.ExpectedReason) {
				t.Fatalf("%s reasons = %v, want %q", name, first.Reasons, fixture.ExpectedReason)
			}
		})
	}
}

func TestCeilingReportsOnlyCommonSweepGroupPlateauIntersection(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	setCeilingSweepGroupSeries(t, sweeps, DirectionLocalToRemote, "ascending",
		[]float64{1.0, 1.1, 1.02, 1.5, 1.6}, []float64{0.01, 0.01, 0.10, 0.11, 0.12})
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)

	decision := DecideCeiling(ceiling, sweeps, profiles, ceilingWinnerSamples(t, ceiling, 1400))
	if !decision.Passed || decision.PlateauStartGbps != 1.5 || decision.PlateauEndGbps != 1.8 {
		t.Fatalf("common plateau = %.1f..%.1f passed=%t reasons=%v, want proved intersection 1.5..1.8", decision.PlateauStartGbps, decision.PlateauEndGbps, decision.Passed, decision.Reasons)
	}
}

func TestCeilingRejectsDisjointSweepGroupPlateaus(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	setCeilingSweepGroupSeries(t, sweeps, DirectionLocalToRemote, "descending",
		[]float64{1.0, 1.02, 1.4, 1.5, 1.6}, []float64{0.01, 0.10, 0.11, 0.12, 0.13})
	setCeilingSweepGroupSeries(t, sweeps, DirectionRemoteToLocal, "descending",
		[]float64{1.0, 1.2, 1.5, 1.6, 1.54}, []float64{0.01, 0.02, 0.03, 0.04, 0.20})
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)

	decision := DecideCeiling(ceiling, sweeps, profiles, ceilingWinnerSamples(t, ceiling, 1400))
	if decision.Passed || !containsReason(decision.Reasons, "common intersection") {
		t.Fatalf("ceiling accepted disjoint group plateaus: %#v", decision)
	}
}

func TestCeilingProfileMustMatchReferencedSweepGroupPlateau(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	setCeilingSweepGroupSeries(t, sweeps, DirectionLocalToRemote, "ascending",
		[]float64{1.0, 1.2, 1.5, 1.6, 1.54}, []float64{0.01, 0.02, 0.03, 0.04, 0.20})
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)

	decision := DecideCeiling(ceiling, sweeps, profiles, ceilingWinnerSamples(t, ceiling, 1400))
	if decision.Passed || !containsReason(decision.Reasons, "profile does not bind an exact matching sweep point at the proved plateau") {
		t.Fatalf("ceiling accepted profile inside another group band but outside its referenced group: %#v", decision)
	}
}

type profileMismatchFixture struct {
	Mechanisms     []string `json:"mechanisms"`
	ExpectedPassed bool     `json:"expected_passed"`
	ExpectedReason string   `json:"expected_reason"`
}

func TestCeilingProfilesRequireMechanismAgreement(t *testing.T) {
	fixture := loadFixtureTwice[profileMismatchFixture](t, "ceiling-profile-mechanism-mismatch.json")
	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	plateau := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(plateau)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	if len(fixture.Mechanisms) == 0 {
		t.Fatal("profile fixture has no mechanisms")
	}
	for index := range profiles {
		profiles[index].LimitingMechanism = fixture.Mechanisms[index%len(fixture.Mechanisms)]
	}
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	samples := ceilingWinnerSamples(t, ceiling, 1400)
	first := DecideCeiling(ceiling, sweeps, profiles, samples)
	second := DecideCeiling(ceiling, sweeps, profiles, samples)
	assertByteIdenticalJSON(t, first, second)
	if first.Passed != fixture.ExpectedPassed || !containsReason(first.Reasons, fixture.ExpectedReason) {
		t.Fatalf("public profile decision = %#v", first)
	}
}

func TestCeilingProfileRequiresExplicitIndependentCapture(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	profiles[0].Independent = false
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	if decision := DecideCeiling(ceiling, sweeps, profiles, ceilingWinnerSamples(t, ceiling, 1400)); decision.Passed {
		t.Fatal("ceiling accepted a profile not marked as an independent capture")
	}
}

func TestCeilingProfilesBindExactPlateauSweepAndSweepsNeverOverlap(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (Manifest, []CeilingSweepPoint, []CeilingProfile, []Sample) {
		t.Helper()
		experiment := mustManifest(t, validExperimentInput())
		production := mustManifest(t, validProductionInput(t, experiment))
		ceiling := boundCeilingManifest(t, production, experiment)
		fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
		sweeps := ceilingSweepFixture(fixture)
		profiles := ceilingProfileFixture("kernel-packet-processing")
		bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
		return ceiling, sweeps, profiles, ceilingWinnerSamples(t, ceiling, 1400)
	}

	for name, mutate := range map[string]func(*testing.T, Manifest, []CeilingSweepPoint, []CeilingProfile){
		"offered load": func(t *testing.T, ceiling Manifest, _ []CeilingSweepPoint, profiles []CeilingProfile) {
			profiles[0].OfferedGbps += 0.1
			bindOneCeilingProfileArtifact(t, ceiling.EvidenceRoot, &profiles[0])
		},
		"sweep ref": func(t *testing.T, ceiling Manifest, sweeps []CeilingSweepPoint, profiles []CeilingProfile) {
			profiles[0].SweepPoint = sweeps[len(sweeps)-1].Artifact
			bindOneCeilingProfileArtifact(t, ceiling.EvidenceRoot, &profiles[0])
		},
		"timestamp": func(t *testing.T, ceiling Manifest, _ []CeilingSweepPoint, profiles []CeilingProfile) {
			observed, err := parseCanonicalUTCTime(profiles[0].ObservedAtUTC)
			if err != nil {
				t.Fatal(err)
			}
			profiles[0].ObservedAtUTC = observed.Add(time.Second).Format(time.RFC3339)
			bindOneCeilingProfileArtifact(t, ceiling.EvidenceRoot, &profiles[0])
		},
		"counters": func(t *testing.T, ceiling Manifest, _ []CeilingSweepPoint, profiles []CeilingProfile) {
			profiles[0].CounterFamilies[0], profiles[0].CounterFamilies[1] = profiles[0].CounterFamilies[1], profiles[0].CounterFamilies[0]
			bindOneCeilingProfileArtifact(t, ceiling.EvidenceRoot, &profiles[0])
		},
		"global overlap": func(t *testing.T, ceiling Manifest, sweeps []CeilingSweepPoint, profiles []CeilingProfile) {
			previousAt, err := parseCanonicalUTCTime(sweeps[0].ObservedAtUTC)
			if err != nil {
				t.Fatal(err)
			}
			point := &sweeps[1]
			oldPointRef := point.Artifact
			point.Capacity = writeEvidence(t, ceiling.EvidenceRoot, "capacity", point.Capacity.Path, ceilingCapacityRecord{
				1, "capacity", "before", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps,
				point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, previousAt.Add(time.Second).Format(time.RFC3339),
			})
			point.Artifact = writeEvidence(t, ceiling.EvidenceRoot, "ceiling-sweep", point.Artifact.Path, ceilingSweepPointRecord{1, "ceiling-sweep", *point})
			for index := range profiles {
				if profiles[index].SweepPoint == oldPointRef {
					profiles[index].SweepPoint = point.Artifact
					bindOneCeilingProfileArtifact(t, ceiling.EvidenceRoot, &profiles[index])
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ceiling, sweeps, profiles, samples := setup(t)
			mutate(t, ceiling, sweeps, profiles)
			decision := DecideCeiling(ceiling, sweeps, profiles, samples)
			if decision.Passed {
				t.Fatalf("ceiling accepted invalid %s profile/sweep provenance", name)
			}
			if name == "global overlap" && !containsReason(decision.Reasons, "global ceiling sweep capture order overlaps") {
				t.Fatalf("global overlap was not rejected explicitly: %v", decision.Reasons)
			}
		})
	}
}

func TestCeilingDecisionRequiresExactBidirectionalSweepProfilesAndWinnerEvidence(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	samples := ceilingWinnerSamples(t, ceiling, 1400)
	decision := DecideCeiling(ceiling, sweeps, profiles, samples)
	if !decision.Passed || decision.AcceptanceMet || decision.PlateauStartGbps != 1.5 || decision.PlateauEndGbps != 1.8 || decision.LimitingMechanism != "kernel-packet-processing" {
		t.Fatalf("ceiling decision = %#v", decision)
	}
	if len(decision.SweepRefs) != 20 || len(decision.ProfileRefs) != 4 || len(decision.WinnerSampleRefs) != 18 {
		t.Fatalf("ceiling refs = %d/%d/%d", len(decision.SweepRefs), len(decision.ProfileRefs), len(decision.WinnerSampleRefs))
	}
}

func TestCeilingRejectsFrozenRowCapacityPhysicalRangeAndCopiedProfiles(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func([]CeilingSweepPoint, []CeilingProfile){
		"frozen row":       func(sweeps []CeilingSweepPoint, _ []CeilingProfile) { sweeps[0].RunID = "substituted-run" },
		"capacity control": func(sweeps []CeilingSweepPoint, _ []CeilingProfile) { sweeps[0].CapacityTCPPort = 9999 },
		"physical range": func(sweeps []CeilingSweepPoint, _ []CeilingProfile) {
			sweeps[0].DeliveredGbps = sweeps[0].OfferedGbps + 0.1
		},
		"copied profile": func(_ []CeilingSweepPoint, profiles []CeilingProfile) {
			path := profiles[1].Artifact.Path
			profiles[1] = profiles[0]
			profiles[1].Artifact.Path = path
		},
	} {
		t.Run(name, func(t *testing.T) {
			experiment := mustManifest(t, validExperimentInput())
			production := mustManifest(t, validProductionInput(t, experiment))
			ceiling := boundCeilingManifest(t, production, experiment)
			fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
			sweeps := ceilingSweepFixture(fixture)
			profiles := ceilingProfileFixture("kernel-packet-processing")
			mutate(sweeps, profiles)
			bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
			decision := DecideCeiling(ceiling, sweeps, profiles, ceilingWinnerSamples(t, ceiling, 1400))
			if decision.Passed {
				t.Fatalf("%s substitution passed physical ceiling proof", name)
			}
		})
	}
}

func TestCeilingRejectsFabricatedParentsAndNonexistentEvidenceArtifacts(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	decision := DecideCeiling(
		ceiling,
		ceilingSweepFixture(fixture),
		ceilingProfileFixture("kernel-packet-processing"),
		ceilingWinnerSamples(t, ceiling, 1400),
	)
	if decision.Passed {
		t.Fatal("ceiling trusted fabricated parent decisions and nonexistent sweep/profile evidence")
	}
}

func TestCeilingRejectsAllProductionWinnerSamples(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	samples := ceilingWinnerSamples(t, ceiling, 1400)
	for index := range samples {
		samples[index].Run.Stage = StageProduction
		samples[index].ManifestSHA256 = ceiling.ManifestInput.ParentManifest.SHA256
		bindSampleArtifact(t, &samples[index], "all-production-"+samples[index].Run.ID+".json")
	}
	if decision := DecideCeiling(ceiling, sweeps, profiles, samples); decision.Passed {
		t.Fatal("ceiling accepted eighteen production samples without six finalist samples per direction")
	}
}

func TestCeilingRejectsUnclosedCandidateAndInconsistentPeakFrontier(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*Decision){
		"missing exact sample replay": func(peak *Decision) {
			peak.SampleRefs = nil
			peak.InputDecisionRefs = nil
		},
		"unclosed candidate": func(peak *Decision) { peak.ClosedCandidates = nil },
		"frontier outside material peak": func(peak *Decision) {
			peak.PeakFrontier = []string{"challenger", "control"}
			peak.ClosedCandidates = nil
		},
		"selected winner outside frontier": func(peak *Decision) { peak.SelectedCandidate = "control" },
	} {
		t.Run(name, func(t *testing.T) {
			experiment := mustManifest(t, validExperimentInput())
			production := mustManifest(t, validProductionInput(t, experiment))
			ceiling := boundCeilingManifest(t, production, experiment)
			peak := loadCeilingParentDecision(t, ceiling, "peak")
			mutate(&peak)
			replaceCeilingParentDecision(t, &ceiling, "peak", peak)
			if reasons := validateCeilingParentProofs(ceiling); len(reasons) == 0 {
				t.Fatal("ceiling accepted incomplete or inconsistent exact peak proof")
			}
		})
	}
}

func TestCeilingRejectsFleetDecisionThatDoesNotReplay(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fleet := loadCeilingParentDecision(t, ceiling, "fleet")
	fleet.SelectedCandidate = "fabricated"
	replaceCeilingParentDecision(t, &ceiling, "fleet", fleet)
	if reasons := validateCeilingParentProofs(ceiling); len(reasons) == 0 {
		t.Fatal("ceiling accepted an exact fleet artifact that does not replay through DecideFleet")
	}
}

func TestCeilingWinnerSamplesMustMatchExactPeakWinner(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	wrongWinner := ceilingWinnerSamplesForCandidate(t, ceiling, 1400, "control")
	if decision := DecideCeiling(ceiling, sweeps, profiles, wrongWinner); decision.Passed {
		t.Fatal("ceiling accepted winner samples for a candidate inconsistent with the exact peak decision")
	}
}

func TestCeilingWinnerRefsRequireExactReplayedSet(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	samples := exactCeilingWinnerSamples(t, ceiling)
	if decision := DecideCeiling(ceiling, sweeps, profiles, samples); !decision.Passed {
		t.Fatalf("exact replayed winner set did not pass: %#v", decision)
	}

	alternate := func(name string, mutate func(*Sample)) Sample {
		replacement := samples[0]
		replacement.Artifact = ArtifactRef{}
		replacement.artifactVerified = false
		mutate(&replacement)
		path := filepath.ToSlash(filepath.Join("samples", name+"-"+replacement.Run.ID+".json"))
		replacement.Artifact = ArtifactRef{
			Role:   "sample",
			Path:   path,
			SHA256: writeFixtureCanonicalJSON(t, filepath.Join(ceiling.EvidenceRoot, filepath.FromSlash(path)), replacement),
		}
		return replacement
	}
	for name, invalid := range map[string][]Sample{
		"missing":                append([]Sample(nil), samples[1:]...),
		"extra":                  append(append([]Sample(nil), samples...), samples[0]),
		"alternate path":         append([]Sample{alternate("alternate-path", func(*Sample) {})}, samples[1:]...),
		"same RunID replacement": append([]Sample{alternate("alternate-digest", func(sample *Sample) { sample.GoodputMbps++ })}, samples[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			decision := DecideCeiling(ceiling, sweeps, profiles, invalid)
			if decision.Passed {
				t.Fatalf("ceiling accepted %s winner reference set", name)
			}
		})
	}
}

func TestCeilingRequiresFailedThroughputOnlyPrerequisite(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	ceiling := boundCeilingManifestWithPrerequisiteGoodput(t, experiment, 2100)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	decision := DecideCeiling(ceiling, sweeps, profiles, exactCeilingWinnerSamples(t, ceiling))
	if decision.Passed {
		t.Fatal("hard-ceiling decision accepted a passed production prerequisite")
	}
}

func TestCeilingConsumesRerunPeakAndCompleteExactEvidence(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	ceiling := boundCeilingManifestWithPeakStage(t, experiment, StageFinalistRerun, 1900)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	samples := exactCeilingWinnerSamples(t, ceiling)
	if len(samples) <= 18 {
		t.Fatalf("rerun winner evidence count = %d, want larger than normal 18-ref set", len(samples))
	}
	foundRerun := false
	for _, sample := range samples {
		foundRerun = foundRerun || sample.Run.Stage == StageFinalistRerun
	}
	if !foundRerun {
		t.Fatal("rerun winner evidence did not preserve exact finalist-rerun samples")
	}
	if decision := DecideCeiling(ceiling, sweeps, profiles, samples); !decision.Passed {
		t.Fatalf("ceiling rejected exact rerun peak and complete evidence: %#v", decision)
	}
}

func TestCeilingWinnerRejectsPriorDecisionReferenceSubstitution(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	fixture := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	sweeps := ceilingSweepFixture(fixture)
	profiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, sweeps, profiles)
	samples := ceilingWinnerSamples(t, ceiling, 1400)
	samples[0].Run.PriorDecisionRef = ArtifactRef{}
	bindSampleArtifact(t, &samples[0], "wrong-prior-"+samples[0].Run.ID+".json")
	decision := DecideCeiling(ceiling, sweeps, profiles, samples)
	if decision.Passed || !containsReason(decision.Reasons, "prior decision reference mismatch") {
		t.Fatalf("ceiling winner prior substitution was not rejected explicitly: %#v", decision)
	}
}

func TestCeilingDecisionRejectsScalingMechanismMismatchMissingEvidenceAndWinnerInstability(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	ceiling := boundCeilingManifest(t, production, experiment)
	plateau := loadFixtureTwice[ceilingFixture](t, "ceiling-plateau-pass.json")
	scaling := loadFixtureTwice[ceilingFixture](t, "ceiling-offered-load-still-scales.json")
	baseSweeps := ceilingSweepFixture(plateau)
	baseProfiles := ceilingProfileFixture("kernel-packet-processing")
	bindCeilingRawArtifacts(t, ceiling.EvidenceRoot, baseSweeps, baseProfiles)
	baseSamples := ceilingWinnerSamples(t, ceiling, 1400)
	for name, inputs := range map[string]struct {
		sweeps   []CeilingSweepPoint
		profiles []CeilingProfile
		samples  []Sample
	}{
		"still scales":       {ceilingSweepFixture(scaling), baseProfiles, baseSamples},
		"mechanism mismatch": {baseSweeps, append(ceilingProfileFixture("kernel-packet-processing")[:3], ceilingProfileFixture("userspace-encryption")[3]), baseSamples},
		"missing sweep":      {baseSweeps[:19], baseProfiles, baseSamples},
		"missing profile":    {baseSweeps, baseProfiles[:3], baseSamples},
		"missing winner":     {baseSweeps, baseProfiles, baseSamples[:17]},
		"replaced sweep summary": func() struct {
			sweeps   []CeilingSweepPoint
			profiles []CeilingProfile
			samples  []Sample
		} {
			sweeps := append([]CeilingSweepPoint(nil), baseSweeps...)
			sweeps[0].DeliveredGbps += 0.1
			return struct {
				sweeps   []CeilingSweepPoint
				profiles []CeilingProfile
				samples  []Sample
			}{sweeps, baseProfiles, baseSamples}
		}(),
		"winner CV": func() struct {
			sweeps   []CeilingSweepPoint
			profiles []CeilingProfile
			samples  []Sample
		} {
			samples := append([]Sample(nil), baseSamples...)
			samples[0].GoodputMbps = 2200
			return struct {
				sweeps   []CeilingSweepPoint
				profiles []CeilingProfile
				samples  []Sample
			}{baseSweeps, baseProfiles, samples}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			decision := DecideCeiling(ceiling, inputs.sweeps, inputs.profiles, inputs.samples)
			if decision.Passed || decision.AcceptanceMet {
				t.Fatalf("invalid ceiling passed: %#v", decision)
			}
		})
	}
}

func boundCeilingManifest(t *testing.T, _ Manifest, experiment Manifest) Manifest {
	t.Helper()
	return boundCeilingManifestWithPrerequisiteGoodput(t, experiment, 1900)
}

func boundCeilingManifestWithPrerequisiteGoodput(t *testing.T, experiment Manifest, prerequisiteGoodput float64) Manifest {
	t.Helper()
	return boundCeilingManifestWithPeakStage(t, experiment, StageFinalist, prerequisiteGoodput)
}

func boundCeilingManifestWithPeakStage(t *testing.T, experiment Manifest, peakStage Stage, prerequisiteGoodput float64) Manifest {
	t.Helper()
	root := t.TempDir()
	production := authorizedProductionManifestWithPeakStage(t, experiment, root, peakStage)
	input := validCeilingInput(t, production)
	var peak Decision
	if err := verifyDecodeEvidence(root, production.ManifestInput.ParentDecisionRefs[0], "finalist", &peak); err != nil {
		t.Fatal(err)
	}
	fleet := buildBoundFleetProof(t, root, production, prerequisiteGoodput)
	input.ParentDecisionRefs[0].SHA256 = mustCanonicalDigest(t, peak)
	input.ParentDecisionRefs[1].SHA256 = mustCanonicalDigest(t, fleet)
	ceiling := mustManifest(t, input)
	ceiling.EvidenceRoot = root
	writeBoundJSON(t, root, *input.ParentManifest, production)
	writeBoundJSON(t, root, input.ParentDecisionRefs[0], peak)
	writeBoundJSON(t, root, input.ParentDecisionRefs[1], fleet)
	return ceiling
}

func buildBoundFleetProof(t *testing.T, root string, production Manifest, prerequisiteGoodput float64) Decision {
	t.Helper()
	productionRef := ArtifactRef{Role: "manifest", Path: "production-manifest.json", SHA256: canonicalManifestDigest(t, production)}
	productionSchedule := production.ManifestInput.Schedules[0]
	productionSamples := make([]Sample, len(productionSchedule.RunIDs))
	for index := range productionSamples {
		productionSamples[index] = validEvidenceSample(t, production, index, prerequisiteGoodput)
		relocateSampleEvidence(t, &productionSamples[index], root)
	}
	prerequisite := DecidePrerequisite(production, productionSamples)
	wantPassed := prerequisiteGoodput > production.ManifestInput.Rules.FileMinimumMbps
	if prerequisite.Passed != wantPassed {
		t.Fatalf("generated ceiling prerequisite = %#v, want passed=%t", prerequisite, wantPassed)
	}
	prerequisiteRef := writePrerequisiteArtifactAtRoot(t, root, prerequisite)
	prerequisite.Artifact = prerequisiteRef
	prerequisite.EvidenceRoot = root

	if err := os.MkdirAll(filepath.Join(root, "probes"), 0o700); err != nil {
		t.Fatal(err)
	}
	var probeRefs []ArtifactRef
	for _, host := range production.ManifestInput.FleetInventory {
		if host.Role == HostRolePrimary {
			continue
		}
		for phaseIndex, phase := range []string{"initial", "recheck"} {
			path := filepath.ToSlash(filepath.Join("probes", host.ID+"-"+phase+".json"))
			probeRefs = append(probeRefs, writeEvidence(t, root, "fleet-probe", path, fleetProbeRecord{
				1, "fleet-probe", host.ID, phase, true,
				time.Date(2026, 7, 16, 2, phaseIndex, 0, 0, time.UTC).Format(time.RFC3339),
			}))
		}
	}
	fleetSchedule := production.ManifestInput.Schedules[1]
	fleetSamples := make([]Sample, 0, len(fleetSchedule.RunIDs))
	for index := range fleetSchedule.RunIDs {
		sample := validEvidenceSample(t, production, index%len(productionSchedule.RunIDs), 2100)
		bindSampleToFrozenSchedule(t, production, &sample, fleetSchedule, index)
		sample.Run.PriorDecisionRef = prerequisiteRef
		bindSampleArtifact(t, &sample, "fleet-prior-"+sample.Run.ID+".json")
		relocateSampleEvidence(t, &sample, root)
		fleetSamples = append(fleetSamples, sample)
	}
	fleet := DecideFleet(FleetInputs{
		Manifest: production, ManifestRef: productionRef, Prerequisite: prerequisite,
		PrerequisiteRef: prerequisiteRef, ProbeRefs: probeRefs, Samples: fleetSamples, EvidenceRoot: root,
	})
	if !fleet.Passed {
		t.Fatalf("generated ceiling fleet = %#v", fleet)
	}
	return fleet
}

func writePrerequisiteArtifactAtRoot(t *testing.T, root string, decision PrerequisiteDecision) ArtifactRef {
	t.Helper()
	ref := ArtifactRef{Role: "prerequisite", Path: filepath.ToSlash(filepath.Join("decisions", "prerequisite.json"))}
	absolute := filepath.Join(root, filepath.FromSlash(ref.Path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := writeFixtureCanonicalJSON(t, absolute, decision)
	ref.SHA256 = digest
	return ref
}

func loadCeilingParentDecision(t *testing.T, ceiling Manifest, role string) Decision {
	t.Helper()
	ref := artifactRefByRole(ceiling.ManifestInput.ParentDecisionRefs, role)
	var decision Decision
	if err := verifyDecodeEvidence(ceiling.EvidenceRoot, ref, role, &decision); err != nil {
		t.Fatal(err)
	}
	return decision
}

func replaceCeilingParentDecision(t *testing.T, ceiling *Manifest, role string, decision Decision) {
	t.Helper()
	for index := range ceiling.ManifestInput.ParentDecisionRefs {
		ref := &ceiling.ManifestInput.ParentDecisionRefs[index]
		if ref.Role != role {
			continue
		}
		absolute := filepath.Join(ceiling.EvidenceRoot, filepath.FromSlash(ref.Path))
		if err := os.Remove(absolute); err != nil {
			t.Fatal(err)
		}
		digest := writeFixtureCanonicalJSON(t, absolute, decision)
		ref.SHA256 = digest
		return
	}
	t.Fatalf("missing ceiling parent role %q", role)
}

func writeBoundJSON(t *testing.T, root string, ref ArtifactRef, value any) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(ref.Path))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if digest := writeFixtureCanonicalJSON(t, path, value); digest != ref.SHA256 {
		t.Fatalf("write %s: digest=%s want=%s", ref.Path, digest, ref.SHA256)
	}
}

func bindCeilingRawArtifacts(t *testing.T, root string, sweeps []CeilingSweepPoint, profiles []CeilingProfile) {
	t.Helper()
	for index := range sweeps {
		point := &sweeps[index]
		pointTime, err := parseCanonicalUTCTime(point.ObservedAtUTC)
		if err != nil {
			t.Fatal(err)
		}
		point.Capacity = writeEvidence(t, root, "capacity", point.Capacity.Path, ceilingCapacityRecord{1, "capacity", "before", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps, point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, pointTime.Add(-time.Second).Format(time.RFC3339)})
		point.CapacityAfter = writeEvidence(t, root, "capacity", point.CapacityAfter.Path, ceilingCapacityRecord{1, "capacity", "after", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps, point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, pointTime.Add(time.Second).Format(time.RFC3339)})
		point.UDPResult = writeEvidence(t, root, "udp-result", point.UDPResult.Path, ceilingUDPResultRecord{1, "udp-result", point.Direction, point.Order, point.OfferedGbps, point.DeliveredGbps, point.LossRatio, point.QueuePressure, point.DatagramBytes, point.PublicUDP, point.CounterFamilies})
		point.Health = writeEvidence(t, root, "health", point.Health.Path, ceilingHealthRecord{1, "health", point.Direction, point.Order, point.OfferedGbps, point.Healthy})
		point.Artifact = writeEvidence(t, root, "ceiling-sweep", fmt.Sprintf("sweep-point-%d.json", index+1), ceilingSweepPointRecord{1, "ceiling-sweep", *point})
	}
	for index := range profiles {
		profile := &profiles[index]
		if profile.SweepPoint == (ArtifactRef{}) {
			bindCeilingProfileToSweep(t, profile, sweeps, index%2)
		}
		bindOneCeilingProfileArtifact(t, root, profile)
	}
}

func bindOneCeilingProfileArtifact(t *testing.T, root string, profile *CeilingProfile) {
	t.Helper()
	profile.Artifact = writeEvidence(t, root, "ceiling-profile", profile.Artifact.Path, ceilingProfileRecord{
		SchemaVersion: 1, Kind: "ceiling-profile", RunID: profile.RunID, HostID: profile.HostID, CandidateID: profile.CandidateID,
		BinarySet: profile.BinarySet, ObservedAtUTC: profile.ObservedAtUTC, Direction: profile.Direction, OfferedGbps: profile.OfferedGbps,
		SweepPoint: profile.SweepPoint, HetzCPUUtilization: profile.HetzCPUUtilization, KernelPacketCPUUtilization: profile.KernelPacketCPUUtilization,
		LimitingMechanism: profile.LimitingMechanism, Independent: profile.Independent, CounterFamilies: profile.CounterFamilies,
	})
}

func bindCeilingProfileToSweep(t *testing.T, profile *CeilingProfile, sweeps []CeilingSweepPoint, repetition int) {
	t.Helper()
	wantLoad := []float64{1.5, 1.8}[repetition]
	for _, point := range sweeps {
		if point.Direction != profile.Direction || point.Order != "ascending" || point.OfferedGbps != wantLoad {
			continue
		}
		profile.HostID = point.HostID
		profile.CandidateID = point.CandidateID
		profile.BinarySet = point.BinarySet
		profile.ObservedAtUTC = point.ObservedAtUTC
		profile.OfferedGbps = point.OfferedGbps
		profile.SweepPoint = point.Artifact
		profile.CounterFamilies = append([]string(nil), point.CounterFamilies...)
		return
	}
	t.Fatalf("no %.1f Gbps plateau sweep point for profile direction %s", wantLoad, profile.Direction)
}

func ceilingSweepFixture(fixture ceilingFixture) []CeilingSweepPoint {
	var result []CeilingSweepPoint
	refIndex := 1
	diagnostic := testCandidate("diagnostic", 'a', 'b', 'c')
	for _, direction := range []Direction{DirectionRemoteToLocal, DirectionLocalToRemote} {
		for _, order := range []string{"ascending", "descending"} {
			for index := range fixture.OfferedGbps {
				pointIndex := index
				if order == "descending" {
					pointIndex = len(fixture.OfferedGbps) - 1 - index
				}
				point := CeilingSweepPoint{
					RunID:                   fmt.Sprintf("ceiling-sweep-%s-%s-%c", order, map[Direction]string{DirectionRemoteToLocal: "hetz-to-mac", DirectionLocalToRemote: "mac-to-hetz"}[direction], rune('1'+index)),
					HostID:                  "primary",
					CandidateID:             diagnostic.ID,
					BinarySet:               BinarySet{Darwin: diagnostic.Darwin, Linux: diagnostic.Linux},
					Direction:               direction,
					Order:                   order,
					Sequence:                index + 1,
					ObservedAtUTC:           time.Date(2026, 7, 16, 3, 0, refIndex*3, 0, time.UTC).Format(time.RFC3339),
					OfferedGbps:             fixture.OfferedGbps[pointIndex],
					DeliveredGbps:           fixture.DeliveredGbps[pointIndex],
					LossRatio:               fixture.LossRatio[pointIndex],
					QueuePressure:           fixture.LossRatio[pointIndex],
					CapacityMbps:            2200,
					CapacityTCPPort:         8123,
					CapacityParallelFlows:   8,
					CapacityDurationSeconds: 20,
					DatagramBytes:           1400,
					PublicUDP:               true,
					Healthy:                 true,
					CounterFamilies:         []string{"cpu", "interface", "softnet", "udp"},
					Capacity:                numberedRef("capacity", fmt.Sprintf("capacity-before-%d.json", refIndex), refIndex),
					CapacityAfter:           numberedRef("capacity", fmt.Sprintf("capacity-after-%d.json", refIndex), refIndex+1000),
					UDPResult:               numberedRef("udp-result", fmt.Sprintf("udp-%d.json", refIndex), refIndex+100),
					Health:                  numberedRef("health", fmt.Sprintf("health-%d.json", refIndex), refIndex+200),
				}
				result = append(result, point)
				refIndex++
			}
		}
	}
	return result
}

func setCeilingSweepGroupSeries(t *testing.T, sweeps []CeilingSweepPoint, direction Direction, order string, delivered, loss []float64) {
	t.Helper()
	loads := []float64{1.2, 1.5, 1.8, 2.1, 2.4}
	if len(delivered) != len(loads) || len(loss) != len(loads) {
		t.Fatal("ceiling group series must provide all five frozen loads")
	}
	seen := 0
	for index := range sweeps {
		point := &sweeps[index]
		if point.Direction != direction || point.Order != order {
			continue
		}
		loadIndex := -1
		for candidateIndex, load := range loads {
			if point.OfferedGbps == load {
				loadIndex = candidateIndex
				break
			}
		}
		if loadIndex < 0 {
			t.Fatalf("unexpected frozen offered load %.1f", point.OfferedGbps)
		}
		point.DeliveredGbps = delivered[loadIndex]
		point.LossRatio = loss[loadIndex]
		point.QueuePressure = loss[loadIndex]
		seen++
	}
	if seen != len(loads) {
		t.Fatalf("ceiling group %s/%s has %d points, want %d", direction, order, seen, len(loads))
	}
}

func ceilingProfileFixture(mechanism string) []CeilingProfile {
	var profiles []CeilingProfile
	index := 400
	diagnostic := testCandidate("diagnostic", 'a', 'b', 'c')
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		for repetition := range 2 {
			directionName := "m2h"
			if direction == DirectionRemoteToLocal {
				directionName = "h2m"
			}
			profiles = append(profiles, CeilingProfile{
				RunID:                      fmt.Sprintf("profile-%s-%d", directionName, repetition+1),
				HostID:                     "primary",
				CandidateID:                diagnostic.ID,
				BinarySet:                  BinarySet{Darwin: diagnostic.Darwin, Linux: diagnostic.Linux},
				ObservedAtUTC:              time.Date(2026, 7, 16, 4, 0, index-399, 0, time.UTC).Format(time.RFC3339),
				Direction:                  direction,
				Artifact:                   numberedRef("ceiling-profile", fmt.Sprintf("profile-%d.json", index), index),
				HetzCPUUtilization:         0.95,
				KernelPacketCPUUtilization: 0.92,
				LimitingMechanism:          mechanism,
				Independent:                true,
				CounterFamilies:            []string{"cpu", "interface", "softnet", "udp"},
			})
			index++
		}
	}
	return profiles
}

func ceilingWinnerSamples(t *testing.T, manifest Manifest, goodput float64) []Sample {
	t.Helper()
	_ = goodput
	return exactCeilingWinnerSamples(t, manifest)
}

func ceilingWinnerSamplesForCandidate(t *testing.T, manifest Manifest, goodput float64, selected string) []Sample {
	t.Helper()
	var samples []Sample
	var production Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, *manifest.ManifestInput.ParentManifest, "manifest", &production); err != nil {
		t.Fatal(err)
	}
	var experiment Manifest
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, *production.ManifestInput.ParentManifest, "manifest", &experiment); err != nil {
		t.Fatal(err)
	}
	var peak Decision
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, "peak"), "peak", &peak); err != nil {
		t.Fatal(err)
	}
	for _, schedule := range experiment.ManifestInput.Schedules[1:3] {
		for index, candidateID := range schedule.CandidateOrder {
			if candidateID != selected {
				continue
			}
			sample := validEvidenceSample(t, experiment, index%len(experiment.ManifestInput.Schedules[0].RunIDs), goodput)
			bindSampleToFrozenSchedule(t, experiment, &sample, schedule, index)
			if schedule.Stage == string(StagePreliminary) {
				sample.Run.PriorDecisionRef = artifactRefByRole(peak.InputDecisionRefs, string(StageScreening))
			} else {
				sample.Run.PriorDecisionRef = artifactRefByRole(peak.InputDecisionRefs, string(StagePreliminary))
			}
			bindSampleArtifact(t, &sample, "winner-prior-"+sample.Run.ID+".json")
			samples = append(samples, sample)
		}
	}
	for index := range production.ManifestInput.Schedules[0].RunIDs {
		sample := validEvidenceSample(t, production, index, goodput)
		sample.Run.PriorDecisionRef = artifactRefByRole(production.ManifestInput.ParentDecisionRefs, "finalist")
		bindSampleArtifact(t, &sample, "winner-prior-"+sample.Run.ID+".json")
		samples = append(samples, sample)
	}
	return samples
}

func exactCeilingWinnerSamples(t *testing.T, manifest Manifest) []Sample {
	t.Helper()
	peak := loadCeilingParentDecision(t, manifest, "peak")
	fleet := loadCeilingParentDecision(t, manifest, "fleet")
	prerequisiteRef := artifactRefByRole(fleet.InputDecisionRefs, "prerequisite")
	var prerequisite PrerequisiteDecision
	if err := verifyDecodeEvidence(manifest.EvidenceRoot, prerequisiteRef, "prerequisite", &prerequisite); err != nil {
		t.Fatal(err)
	}

	refs := append([]ArtifactRef(nil), prerequisite.Samples...)
	for _, ref := range peak.SampleRefs {
		sample, err := LoadSampleArtifact(manifest.EvidenceRoot, ref)
		if err != nil {
			t.Fatal(err)
		}
		if sample.Run.CandidateID == peak.SelectedCandidate {
			refs = append(refs, ref)
		}
	}
	samples := make([]Sample, 0, len(refs))
	for _, ref := range refs {
		sample, err := LoadSampleArtifact(manifest.EvidenceRoot, ref)
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, sample)
	}
	return samples
}

func numberedRef(role, path string, number int) ArtifactRef {
	return ArtifactRef{Role: role, Path: path, SHA256: SHA256Digest(fmt.Sprintf("%064x", number))}
}
