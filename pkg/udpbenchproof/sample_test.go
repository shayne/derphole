// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type mutationFixture struct {
	Mutation       string `json:"mutation"`
	Value          any    `json:"value"`
	ExpectedStatus string `json:"expected_status"`
	ExpectedReason string `json:"expected_reason"`
}

func TestSampleFixtureRejectsMissingIndependentSHA(t *testing.T) {
	t.Parallel()

	fixture := loadFixtureTwice[mutationFixture](t, "sample-missing-sha.json")
	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	sample.Payload.SourceSHAReports = int(fixture.Value.(float64))
	sample.Payload.SourceHashArtifact = writeEvidence(t, sample.EvidenceRoot, "source-sha", sample.Payload.SourceHashArtifact.Path, hashEvidenceRecord{
		SchemaVersion: 1, Kind: "hash-observation", RunID: sample.Run.ID, ObserverHostID: sourceObserverHost(sample), ObserverRole: "source",
		SHA256: sample.Payload.SourceSHA256, Reports: sample.Payload.SourceSHAReports,
	})
	verdict := ValidateSample(manifest, sample)
	if verdict.Status != fixture.ExpectedStatus || !containsReason(verdict.Reasons, fixture.ExpectedReason) {
		t.Fatalf("verdict = %#v", verdict)
	}
}

func TestSampleCapacityInvalidBeforeStartIsPostponed(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	setPostponedSample(t, &sample, 1)
	verdict := ValidateSample(manifest, sample)
	if verdict.Status != "postponed" {
		t.Fatalf("status = %q, want postponed", verdict.Status)
	}
}

func TestSampleCapacityValidStartedFailureIsRetained(t *testing.T) {
	t.Parallel()

	verdict := ValidateSample(Manifest{}, Sample{Started: true, Capacity: CapacityEvidence{Valid: true}})
	if verdict.Status != "failed" {
		t.Fatalf("status = %q, want failed", verdict.Status)
	}
}

func TestSampleOpensAndDigestVerifiesEveryEvidenceArtifact(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	if verdict := ValidateSample(manifest, sample); verdict.Status != "valid" {
		t.Fatalf("valid sample rejected: %#v", verdict)
	}
}

func TestSampleRejectsManifestPayloadSubstitutionAndScheduledIdentityMutation(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	for name, mutate := range map[string]func(*Sample){
		"payload SHA": func(sample *Sample) {
			sample.Payload.SourceSHA256 = hexDigest('f')
			sample.Payload.SinkSHA256 = hexDigest('f')
			rewriteHashEvidence(t, sample, sample.Payload.SourceHashArtifact, "source-sha", "source", sample.Payload.SourceSHA256)
			rewriteHashEvidence(t, sample, sample.Payload.SinkHashArtifact, "sink-sha", "sink", sample.Payload.SinkSHA256)
		},
		"run stage":  func(sample *Sample) { sample.Run.Stage = StageAcceptance },
		"run order":  func(sample *Sample) { sample.Run.Order++ },
		"binary set": func(sample *Sample) { sample.BinarySet.Linux.SHA256 = hexDigest('f') },
		"direction":  func(sample *Sample) { sample.Capacity.Direction = DirectionLocalToRemote },
	} {
		t.Run(name, func(t *testing.T) {
			sample := validEvidenceSample(t, manifest, 0, 2100)
			mutate(&sample)
			if verdict := ValidateSample(manifest, sample); verdict.Status == "valid" {
				t.Fatal("mutated sample accepted")
			}
		})
	}
}

func TestSampleStrictEvidenceDecodeRejectsMutationUnknownTrailingAndDuplicateData(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	for name, mutate := range map[string]func(*Sample){
		"digest mutation": func(sample *Sample) {
			path := filepath.Join(sample.EvidenceRoot, sample.Payload.SourceHashArtifact.Path)
			if err := os.WriteFile(path, []byte("mutated\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unknown field": func(sample *Sample) {
			writeRawEvidence(t, sample, &sample.Payload.SourceHashArtifact, `{"schema_version":1,"kind":"sha256","run_id":"screen-1","sha256":"`+string(manifest.ManifestInput.Payload.SHA256)+`","reports":1,"independent":true,"unknown":true}`+"\n")
		},
		"trailing value": func(sample *Sample) {
			path := filepath.Join(sample.EvidenceRoot, sample.Payload.SourceHashArtifact.Path)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			writeRawEvidence(t, sample, &sample.Payload.SourceHashArtifact, string(data)+"{}\n")
		},
		"duplicate field": func(sample *Sample) {
			writeRawEvidence(t, sample, &sample.Payload.SourceHashArtifact, `{"schema_version":1,"kind":"sha256","run_id":"screen-1","sha256":"`+string(manifest.ManifestInput.Payload.SHA256)+`","reports":1,"reports":1,"independent":true}`+"\n")
		},
	} {
		t.Run(name, func(t *testing.T) {
			sample := validEvidenceSample(t, manifest, 0, 2100)
			mutate(&sample)
			if verdict := ValidateSample(manifest, sample); verdict.Status == "valid" {
				t.Fatal("invalid raw evidence accepted")
			}
		})
	}
}

func TestEvidenceHashAndDecodeUseTheSameSingleRead(t *testing.T) {
	t.Parallel()

	record := sizeEvidenceRecord{SchemaVersion: 1, Kind: "size", RunID: "run-1", SizeBytes: 1234}
	first, err := canonicalJSONBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	second := []byte(`{"schema_version":1,"kind":"size","run_id":"run-1","size_bytes":9999}` + "\n")
	ref := ArtifactRef{Role: "sink-size", Path: "size.json", SHA256: DigestBytes(first)}
	reads := 0
	reader := func(string) ([]byte, error) {
		reads++
		if reads == 1 {
			return first, nil
		}
		return second, nil
	}
	var decoded sizeEvidenceRecord
	if err := verifyDecodeEvidenceWithReader("unused", ref, "sink-size", &decoded, reader); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || decoded != record {
		t.Fatalf("reads=%d decoded=%#v, want one read of %#v", reads, decoded, record)
	}
}

func TestValidateSampleRejectsForgedSummaryMetrics(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	sample.GoodputMbps = 900000
	sample.WallGoodputMbps = 800000
	sample.RecoveryRatio = 0
	sample.ScanPerPacket = 0
	sample.FlatlineSeconds = 0
	if verdict := ValidateSample(manifest, sample); verdict.Status == "valid" {
		t.Fatal("sample trusted forged duplicated summary metrics instead of receiver raw evidence")
	}
}

func TestValidateSampleDerivesCapacityValidityFromThreshold(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	sample.Capacity.Mbps = 1
	sample.Capacity.Valid = true
	sample.Capacity.Artifact = writeEvidence(t, sample.EvidenceRoot, "capacity", sample.Capacity.Artifact.Path, capacityEvidenceRecord{
		SchemaVersion: 1,
		Kind:          "capacity",
		RunID:         sample.Run.ID,
		Direction:     sample.Run.Direction,
		Mbps:          1,
		Valid:         true,
	})
	if verdict := ValidateSample(manifest, sample); verdict.Status == "valid" {
		t.Fatal("1 Mbps capacity was accepted because its raw record asserted valid=true")
	}
}

func TestPostponedSampleStillValidatesCapacityArtifact(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	setPostponedSample(t, &sample, 1)
	sample.Capacity.Artifact.SHA256 = hexDigest('f')
	verdict := ValidateSample(manifest, sample)
	if verdict.Status == "postponed" {
		t.Fatalf("invalid capacity artifact bypassed validation as postponed: %#v", verdict)
	}
}

func setPostponedSample(t *testing.T, sample *Sample, capacityMbps float64) {
	t.Helper()
	sample.Started = false
	sample.Capacity.Mbps = capacityMbps
	sample.Capacity.Valid = false
	sample.Capacity.Artifact = writeEvidence(t, sample.EvidenceRoot, "capacity", sample.Capacity.Artifact.Path, capacityEvidenceRecord{
		SchemaVersion: 1, Kind: "capacity", RunID: sample.Run.ID, Direction: sample.Run.Direction, Mbps: capacityMbps, Valid: false,
	})
	sample.ReceiverResult = writeEvidence(t, sample.EvidenceRoot, "receiver-result", sample.ReceiverResult.Path, receiverResultRecord{
		SchemaVersion: 1, Kind: "file-result", RunID: sample.Run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(*sample),
		CommittedBytes: 0, PayloadSeconds: 1, WallSeconds: 1, MaxFlatlineSeconds: 0,
		Started: false, ObservedAtUTC: sample.ObservedAtUTC,
	})
}

func TestHashObservationsRequireDifferentApprovedObservers(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validExperimentInput())
	sample := validEvidenceSample(t, manifest, 0, 2100)
	writeObservers := func(sourceHost, sourceRole, sinkHost, sinkRole string) {
		sample.Payload.SourceHashArtifact = writeEvidence(t, sample.EvidenceRoot, "source-sha", sample.Payload.SourceHashArtifact.Path, hashEvidenceRecord{
			SchemaVersion: 1, Kind: "hash-observation", RunID: sample.Run.ID, ObserverHostID: sourceHost,
			ObserverRole: sourceRole, SHA256: sample.Payload.SourceSHA256, Reports: 1,
		})
		sample.Payload.SinkHashArtifact = writeEvidence(t, sample.EvidenceRoot, "sink-sha", sample.Payload.SinkHashArtifact.Path, hashEvidenceRecord{
			SchemaVersion: 1, Kind: "hash-observation", RunID: sample.Run.ID, ObserverHostID: sinkHost,
			ObserverRole: sinkRole, SHA256: sample.Payload.SinkSHA256, Reports: 1,
		})
	}
	writeObservers("primary", "source", "local-mac", "sink")
	if verdict := ValidateSample(manifest, sample); verdict.Status != "valid" {
		t.Fatalf("different approved observers rejected: %#v", verdict)
	}
	writeObservers("primary", "source", "primary", "source")
	if verdict := ValidateSample(manifest, sample); verdict.Status == "valid" {
		t.Fatal("same observer supplied both source and sink hash observations")
	}
}

func TestPrerequisiteRequiresExactSixFreshSamplesAndVerifiesDecisionAndBinaries(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	evidenceRoot := t.TempDir()
	production := authorizedProductionManifest(t, experiment, evidenceRoot)
	samples := make([]Sample, 6)
	for index := range samples {
		samples[index] = validEvidenceSample(t, production, index, 2100+float64(index%3)*10)
		relocateSampleEvidence(t, &samples[index], evidenceRoot)
	}
	decision := DecidePrerequisite(production, samples)
	if !decision.Passed || len(decision.Samples) != 6 {
		t.Fatalf("prerequisite decision = %#v", decision)
	}
	manifestDigest, err := canonicalDigest(production)
	if err != nil {
		t.Fatal(err)
	}
	decisionPath := filepath.Join(evidenceRoot, "decisions", "prerequisite.json")
	if err := os.MkdirAll(filepath.Dir(decisionPath), 0o700); err != nil {
		t.Fatal(err)
	}
	decisionDigest := writeFixtureCanonicalJSON(t, decisionPath, decision)
	decision.Artifact = ArtifactRef{Role: "prerequisite", Path: "decisions/prerequisite.json", SHA256: decisionDigest}
	decision.EvidenceRoot = evidenceRoot
	if err := VerifyPrerequisite(production, manifestDigest, decision, decisionDigest, decision.BinarySet); err != nil {
		t.Fatalf("valid prerequisite rejected: %v", err)
	}
	wrong := decision.BinarySet
	wrong.Linux.SHA256 = hexDigest('f')
	if err := VerifyPrerequisite(production, manifestDigest, decision, decisionDigest, wrong); err == nil {
		t.Fatal("wrong binary set accepted")
	}
}

func relocateSampleEvidence(t *testing.T, sample *Sample, evidenceRoot string) {
	t.Helper()
	oldRoot := sample.EvidenceRoot
	prefix := filepath.ToSlash(filepath.Join("runs", sample.Run.ID))
	refs := []*ArtifactRef{
		&sample.Payload.SourceHashArtifact, &sample.Payload.SinkHashArtifact, &sample.Payload.SinkSizeArtifact,
		&sample.Capacity.Artifact, &sample.Trace.Sender, &sample.Trace.Receiver,
		&sample.Resource.Sender, &sample.Resource.Receiver, &sample.Health.Before, &sample.Health.After,
		&sample.Cleanup.Artifact, &sample.ReceiverResult, &sample.MechanismResult,
	}
	for _, ref := range refs {
		data, err := os.ReadFile(filepath.Join(oldRoot, filepath.FromSlash(ref.Path)))
		if err != nil {
			t.Fatal(err)
		}
		newPath := filepath.ToSlash(filepath.Join(prefix, ref.Path))
		absolute := filepath.Join(evidenceRoot, filepath.FromSlash(newPath))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFixtureBytes(t, absolute, data)
		ref.Path = newPath
	}
	sample.Artifact = ArtifactRef{}
	sample.EvidenceRoot = evidenceRoot
	sample.artifactVerified = false
	bindSampleArtifact(t, sample, "campaign-"+sample.Run.ID+".json")
}

func TestPrerequisiteRejectsOmissionReplacementThresholdAndCV(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := authorizedProductionManifest(t, experiment, t.TempDir())
	makeSamples := func() []Sample {
		samples := make([]Sample, 6)
		for index := range samples {
			samples[index] = validEvidenceSample(t, production, index, 2100)
		}
		return samples
	}
	for name, mutate := range map[string]func([]Sample) []Sample{
		"omission": func(samples []Sample) []Sample { return samples[:5] },
		"replacement": func(samples []Sample) []Sample {
			samples[1].Run.ID = samples[0].Run.ID
			return samples
		},
		"threshold": func(samples []Sample) []Sample {
			samples[0].GoodputMbps = 2000
			return samples
		},
		"CV": func(samples []Sample) []Sample {
			samples[0].GoodputMbps = 2800
			return samples
		},
	} {
		t.Run(name, func(t *testing.T) {
			if decision := DecidePrerequisite(production, mutate(makeSamples())); decision.Passed {
				t.Fatal("invalid prerequisite passed")
			}
		})
	}
}

func TestPrerequisiteRejectsStartedTransferWithoutMinimumCapacity(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := authorizedProductionManifest(t, experiment, t.TempDir())
	samples := make([]Sample, 6)
	for index := range samples {
		samples[index] = validEvidenceSample(t, production, index, 2100)
	}
	sample := &samples[0]
	sample.Capacity.Mbps = 1900
	sample.Capacity.Valid = false
	sample.Capacity.Artifact = writeEvidence(t, sample.EvidenceRoot, "capacity", sample.Capacity.Artifact.Path, capacityEvidenceRecord{
		SchemaVersion: 1, Kind: "capacity", RunID: sample.Run.ID, Direction: sample.Run.Direction, Mbps: 1900, Valid: false,
	})
	bindSampleArtifact(t, sample, "started-low-capacity-"+sample.Run.ID+".json")
	if decision := DecidePrerequisite(production, samples); decision.Passed {
		t.Fatalf("started production transfer passed without the frozen capacity gate: %#v", decision)
	}
}

func TestFleetAuthorizationAllowsOnlyHardCeilingThroughputFailure(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	root := t.TempDir()
	production := authorizedProductionManifest(t, experiment, root)
	samples := make([]Sample, 6)
	for index := range samples {
		samples[index] = validEvidenceSample(t, production, index, 1900)
		relocateSampleEvidence(t, &samples[index], root)
	}
	decision := DecidePrerequisite(production, samples)
	if decision.Passed || !reflect.DeepEqual(decision.Reasons, []string{"sample does not exceed 2.0 Gbps"}) {
		t.Fatalf("hard-ceiling prerequisite = %#v", decision)
	}
	ref := ArtifactRef{Role: "prerequisite", Path: "decisions/prerequisite.json"}
	if err := os.MkdirAll(filepath.Join(root, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	ref.SHA256 = writeFixtureCanonicalJSON(t, filepath.Join(root, filepath.FromSlash(ref.Path)), decision)
	decision.Artifact = ref
	decision.EvidenceRoot = root
	if err := verifyFleetAuthorization(production, canonicalManifestDigest(t, production), decision, ref.SHA256); err != nil {
		t.Fatalf("hard-ceiling-only fleet guard rejected: %v", err)
	}

	badSamples := append([]Sample(nil), samples...)
	badSamples[0].FlatlineSeconds = 2
	bad := DecidePrerequisite(production, badSamples)
	if err := verifyFleetAuthorization(production, canonicalManifestDigest(t, production), bad, mustCanonicalDigest(t, bad)); err == nil {
		t.Fatal("fleet guard accepted a failure other than the hard throughput ceiling")
	}
}

func TestPrerequisiteRejectsEndpointVMAndFleetTransitionSubstitution(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*ManifestInput){
		"endpoint": func(input *ManifestInput) { input.LocalPublicIPv4 = "1.0.0.1" },
		"vm": func(input *ManifestInput) {
			input.RemoteBootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			input.BaselineHealthIdentity.BootID = input.RemoteBootID
		},
		"fleet": func(input *ManifestInput) { input.FleetInventory[1].PublicIPv4 = "208.67.222.222" },
	} {
		t.Run(name, func(t *testing.T) {
			experiment := mustManifest(t, validExperimentInput())
			root := t.TempDir()
			peak := bindDecisionArtifactAtRoot(t, experiment, Decision{Stage: StageFinalist}, root)
			input := validProductionInput(t, experiment)
			input.ParentDecisionRefs = []ArtifactRef{peak.Artifact}
			mutate(&input)
			bindBaselineHealthRecordDigest(t, &input)
			production := mustManifest(t, input)
			production.EvidenceRoot = root
			writeBoundJSON(t, root, *production.ManifestInput.ParentManifest, experiment)
			samples := make([]Sample, 6)
			for index := range samples {
				samples[index] = validEvidenceSample(t, production, index, 2100)
			}
			decision := DecidePrerequisite(production, samples)
			if decision.Passed || !containsReason(decision.Reasons, "substituted") {
				t.Fatalf("%s substitution was not rejected by transition replay: %#v", name, decision)
			}
		})
	}
}

func validEvidenceSample(t *testing.T, manifest Manifest, runIndex int, goodput float64) Sample {
	t.Helper()
	root := t.TempDir()
	var frozen FrozenSchedule
	for _, schedule := range manifest.ManifestInput.Schedules {
		if runIndex < len(schedule.RunIDs) && (schedule.Stage == string(manifest.ManifestInput.Kind) || manifest.ManifestInput.Kind == ManifestExperiment && schedule.Stage == "screening") {
			frozen = schedule
			break
		}
	}
	if len(frozen.RunIDs) <= runIndex {
		t.Fatalf("no frozen run at index %d for %s", runIndex, manifest.ManifestInput.Kind)
	}
	candidate, ok := manifestCandidate(manifest, frozen.CandidateOrder[runIndex])
	if !ok {
		t.Fatal("candidate missing")
	}
	run := ScheduledRun{
		ID:               frozen.RunIDs[runIndex],
		Stage:            stageForFrozenSchedule(frozen.Stage),
		CandidateID:      candidate.ID,
		HostID:           frozen.HostOrder[runIndex],
		Direction:        manifestDirection(frozen.DirectionOrder[runIndex]),
		SizeBytes:        manifest.ManifestInput.Payload.Bytes,
		Order:            runIndex + 1,
		CapacityRequired: true,
		Block:            frozen.BlockOrder[runIndex],
		Schedule:         frozen.Stage,
		Role:             frozen.RunRoles[runIndex],
	}
	if manifest.ManifestInput.Kind == ManifestProduction {
		run.PriorDecisionRef = artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, "finalist")
	}
	if manifest.ManifestInput.Kind == ManifestAcceptance {
		run.PriorDecisionRef = artifactRefByRole(manifest.ManifestInput.ParentDecisionRefs, "fleet")
	}
	sample := Sample{
		SchemaVersion:   sampleSchemaVersion,
		ManifestSHA256:  canonicalManifestDigest(t, manifest),
		CandidateID:     candidate.ID,
		BinarySet:       BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux},
		Run:             run,
		ObservedAtUTC:   "2026-07-16T01:00:00Z",
		GoodputMbps:     goodput,
		WallGoodputMbps: goodput - 10,
		RecoveryRatio:   0.01,
		ScanPerPacket:   1,
		FlatlineSeconds: 0.2,
		Started:         true,
		EvidenceRoot:    root,
	}
	sample.Payload = PayloadEvidence{
		SourceSHA256:     manifest.ManifestInput.Payload.SHA256,
		SinkSHA256:       manifest.ManifestInput.Payload.SHA256,
		SourceSHAReports: 1,
		SinkSHAReports:   1,
		SinkSizeBytes:    manifest.ManifestInput.Payload.Bytes,
	}
	sample.Payload.SourceHashArtifact = writeEvidence(t, root, "source-sha", "source.json", hashEvidenceRecord{
		SchemaVersion: 1, Kind: "hash-observation", RunID: run.ID, ObserverHostID: sourceObserverHost(sample), ObserverRole: "source",
		SHA256: sample.Payload.SourceSHA256, Reports: 1,
	})
	sample.Payload.SinkHashArtifact = writeEvidence(t, root, "sink-sha", "sink.json", hashEvidenceRecord{
		SchemaVersion: 1, Kind: "hash-observation", RunID: run.ID, ObserverHostID: receiverObserverHost(sample), ObserverRole: "sink",
		SHA256: sample.Payload.SinkSHA256, Reports: 1,
	})
	sample.Payload.SinkSizeArtifact = writeEvidence(t, root, "sink-size", "size.json", sizeEvidenceRecord{1, "size", run.ID, sample.Payload.SinkSizeBytes})
	sample.Capacity = CapacityEvidence{Direction: run.Direction, Mbps: 2200, Valid: true}
	sample.Capacity.Artifact = writeEvidence(t, root, "capacity", "capacity.json", capacityEvidenceRecord{1, "capacity", run.ID, run.Direction, 2200, true})
	sample.Trace = TraceEvidence{Engine: "bulk-packets-v1", PublicUDP: true, StrictValid: true}
	sample.Trace.Sender = writeEvidence(t, root, "trace-sender", "trace-sender.json", traceEvidenceRecord{1, "trace", run.ID, "sender", run.Direction, sample.Trace.Engine, true, true})
	sample.Trace.Receiver = writeEvidence(t, root, "trace-receiver", "trace-receiver.json", traceEvidenceRecord{1, "trace", run.ID, "receiver", run.Direction, sample.Trace.Engine, true, true})
	sample.Resource = ResourceEvidence{SenderUserSeconds: 2, SenderSystemSeconds: 2, ReceiverUserSeconds: 2, ReceiverSystemSeconds: 2}
	sample.Resource.Sender = writeEvidence(t, root, "resource-sender", "resource-sender.json", resourceEvidenceRecord{1, "resource", run.ID, "sender", 2, 2})
	sample.Resource.Receiver = writeEvidence(t, root, "resource-receiver", "resource-receiver.json", resourceEvidenceRecord{1, "resource", run.ID, "receiver", 2, 2})
	sample.Health = HealthEvidence{Healthy: true}
	sample.Health.Before = writeEvidence(t, root, "health-before", "health-before.json", healthEvidenceRecord{1, "health", run.ID, "before", true})
	sample.Health.After = writeEvidence(t, root, "health-after", "health-after.json", healthEvidenceRecord{1, "health", run.ID, "after", true})
	sample.Cleanup = CleanupEvidence{ScopedRootRemoved: true, ProcessesRemoved: true, SocketsRemoved: true, PayloadsRemoved: true}
	sample.Cleanup.Artifact = writeEvidence(t, root, "cleanup", "cleanup.json", cleanupEvidenceRecord{1, "cleanup", run.ID, true, true, true, true})
	sample.ReceiverResult = writeEvidence(t, root, "receiver-result", "receiver-result.json", receiverResultRecord{
		SchemaVersion: 1, Kind: "file-result", RunID: run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(sample),
		CommittedBytes: sample.Run.SizeBytes, PayloadSeconds: secondsForMbps(sample.Run.SizeBytes, sample.GoodputMbps),
		WallSeconds: secondsForMbps(sample.Run.SizeBytes, sample.WallGoodputMbps), MaxFlatlineSeconds: sample.FlatlineSeconds,
		Started: sample.Started, ObservedAtUTC: sample.ObservedAtUTC,
	})
	sample.MechanismResult = writeEvidence(t, root, "mechanism-result", "mechanism-result.json", mechanismResultRecord{
		SchemaVersion: 1, Kind: "mechanism-result", RunID: run.ID, ObserverRole: "receiver", ObserverHostID: receiverObserverHost(sample),
		Engine: sample.Trace.Engine, PublicUDP: sample.Trace.PublicUDP, StrictValid: sample.Trace.StrictValid,
		RecoveredUnits: 1, TotalUnits: 100, ScanChecks: 100, PayloadPackets: 100,
	})
	bindSampleArtifact(t, &sample, "initial-"+run.ID+".json")
	return sample
}

func secondsForMbps(sizeBytes int64, mbps float64) float64 {
	return float64(sizeBytes) * 8 / (mbps * 1e6)
}

func bindSampleArtifact(t *testing.T, sample *Sample, name string) {
	t.Helper()
	path := filepath.ToSlash(filepath.Join("samples", name))
	if err := os.MkdirAll(filepath.Join(sample.EvidenceRoot, "samples"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := writeFixtureCanonicalJSON(t, filepath.Join(sample.EvidenceRoot, filepath.FromSlash(path)), *sample)
	sample.Artifact = ArtifactRef{Role: "sample", Path: path, SHA256: digest}
	sample.artifactVerified = true
}

func writeFixtureCanonicalJSON(t *testing.T, path string, value any) SHA256Digest {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeFixtureBytes(t, path, append(data, '\n'))
}

func writeFixtureBytes(t *testing.T, path string, data []byte) SHA256Digest {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return DigestBytes(data)
}

func writeEvidence(t *testing.T, root, role, name string, value any) ArtifactRef {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return ArtifactRef{Role: role, Path: name, SHA256: DigestBytes(data)}
}

func rewriteHashEvidence(t *testing.T, sample *Sample, ref ArtifactRef, role, name string, digest SHA256Digest) {
	t.Helper()
	observerRole := "source"
	observerHost := sourceObserverHost(*sample)
	if name != "source" {
		observerRole = "sink"
		observerHost = receiverObserverHost(*sample)
	}
	updated := writeEvidence(t, sample.EvidenceRoot, role, ref.Path, hashEvidenceRecord{
		SchemaVersion: 1, Kind: "hash-observation", RunID: sample.Run.ID, ObserverHostID: observerHost,
		ObserverRole: observerRole, SHA256: digest, Reports: 1,
	})
	if name == "source" {
		sample.Payload.SourceHashArtifact = updated
	} else {
		sample.Payload.SinkHashArtifact = updated
	}
}

func writeRawEvidence(t *testing.T, sample *Sample, ref *ArtifactRef, raw string) {
	t.Helper()
	if !strings.HasSuffix(raw, "\n") {
		raw += "\n"
	}
	if err := os.WriteFile(filepath.Join(sample.EvidenceRoot, ref.Path), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	ref.SHA256 = DigestBytes([]byte(raw))
}

func loadFixtureTwice[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var first, second T
	for _, target := range []*T{&first, &second} {
		if err := decodeStrictEvidenceJSON(data, target); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
	}
	left, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("%s is nondeterministic", name)
	}
	return first
}

func assertByteIdenticalJSON(t *testing.T, first, second any) {
	t.Helper()
	left, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("public result JSON is nondeterministic:\n%s\n%s", left, right)
	}
}
