// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const sampleSchemaVersion = 1

type hashEvidenceRecord struct {
	SchemaVersion  int          `json:"schema_version"`
	Kind           string       `json:"kind"`
	RunID          string       `json:"run_id"`
	ObserverHostID string       `json:"observer_host_id"`
	ObserverRole   string       `json:"observer_role"`
	SHA256         SHA256Digest `json:"sha256"`
	Reports        int          `json:"reports"`
}

type sizeEvidenceRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	RunID         string `json:"run_id"`
	SizeBytes     int64  `json:"size_bytes"`
}

type capacityEvidenceRecord struct {
	SchemaVersion int       `json:"schema_version"`
	Kind          string    `json:"kind"`
	RunID         string    `json:"run_id"`
	Direction     Direction `json:"direction"`
	Mbps          float64   `json:"mbps"`
	Valid         bool      `json:"valid"`
}

type traceEvidenceRecord struct {
	SchemaVersion int       `json:"schema_version"`
	Kind          string    `json:"kind"`
	RunID         string    `json:"run_id"`
	Role          string    `json:"role"`
	Direction     Direction `json:"direction"`
	Engine        string    `json:"engine"`
	PublicUDP     bool      `json:"public_udp"`
	StrictValid   bool      `json:"strict_valid"`
}

type resourceEvidenceRecord struct {
	SchemaVersion int     `json:"schema_version"`
	Kind          string  `json:"kind"`
	RunID         string  `json:"run_id"`
	Role          string  `json:"role"`
	UserSeconds   float64 `json:"user_seconds"`
	SystemSeconds float64 `json:"system_seconds"`
}

type healthEvidenceRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	RunID         string `json:"run_id"`
	Phase         string `json:"phase"`
	Healthy       bool   `json:"healthy"`
}

type cleanupEvidenceRecord struct {
	SchemaVersion     int    `json:"schema_version"`
	Kind              string `json:"kind"`
	RunID             string `json:"run_id"`
	ScopedRootRemoved bool   `json:"scoped_root_removed"`
	ProcessesRemoved  bool   `json:"processes_removed"`
	SocketsRemoved    bool   `json:"sockets_removed"`
	PayloadsRemoved   bool   `json:"payloads_removed"`
}

type receiverResultRecord struct {
	SchemaVersion      int     `json:"schema_version"`
	Kind               string  `json:"kind"`
	RunID              string  `json:"run_id"`
	ObserverRole       string  `json:"observer_role"`
	ObserverHostID     string  `json:"observer_host_id"`
	CommittedBytes     int64   `json:"committed_bytes"`
	PayloadSeconds     float64 `json:"payload_seconds"`
	WallSeconds        float64 `json:"wall_seconds"`
	MaxFlatlineSeconds float64 `json:"max_flatline_seconds"`
	Started            bool    `json:"started"`
	ObservedAtUTC      string  `json:"observed_at_utc"`
}

type mechanismResultRecord struct {
	SchemaVersion  int    `json:"schema_version"`
	Kind           string `json:"kind"`
	RunID          string `json:"run_id"`
	ObserverRole   string `json:"observer_role"`
	ObserverHostID string `json:"observer_host_id"`
	Engine         string `json:"engine"`
	PublicUDP      bool   `json:"public_udp"`
	StrictValid    bool   `json:"strict_valid"`
	RecoveredUnits int64  `json:"recovered_units"`
	TotalUnits     int64  `json:"total_units"`
	ScanChecks     int64  `json:"scan_checks"`
	PayloadPackets int64  `json:"payload_packets"`
}

type derivedSampleMetrics struct {
	started         bool
	observedAtUTC   string
	committedBytes  int64
	goodputMbps     float64
	wallGoodputMbps float64
	recoveryRatio   float64
	scanPerPacket   float64
	flatlineSeconds float64
	engine          string
	publicUDP       bool
	strictValid     bool
}

// ValidateSample validates a sample and every referenced raw evidence artifact.
func ValidateSample(manifest Manifest, sample Sample) SampleVerdict {
	if err := ValidateManifest(manifest); err != nil {
		return SampleVerdict{Status: "failed", Reasons: []string{"manifest: " + err.Error()}}
	}
	reasons := validateSampleIdentity(manifest, sample)
	capacityValid, capacityReasons := validateCapacityEvidence(manifest, sample)
	reasons = append(reasons, capacityReasons...)
	derived, receiverReasons := deriveReceiverEvidence(sample)
	reasons = append(reasons, receiverReasons...)
	if len(reasons) != 0 {
		sort.Strings(reasons)
		return SampleVerdict{Status: "failed", Reasons: compactStrings(reasons)}
	}
	if !derived.started && !capacityValid {
		return SampleVerdict{Status: "postponed", Reasons: []string{"capacity below frozen threshold before start"}}
	}
	reasons = validateStartedSampleReasons(manifest, sample, derived)
	if len(reasons) != 0 {
		return SampleVerdict{Status: "failed", Reasons: reasons}
	}
	return SampleVerdict{Status: "valid", Reasons: []string{}}
}

// LoadSampleArtifact opens, verifies, and strict-decodes one immutable sample.
func LoadSampleArtifact(root string, ref ArtifactRef) (Sample, error) {
	var sample Sample
	if err := verifyDecodeEvidence(root, ref, "sample", &sample); err != nil {
		return Sample{}, err
	}
	sample.Artifact = ref
	sample.EvidenceRoot = root
	sample.artifactVerified = true
	return sample, nil
}

func exactSampleArtifact(sample Sample) (ArtifactRef, error) {
	if err := validateArtifactRef(sample.Artifact, "sample"); err != nil {
		return ArtifactRef{}, err
	}
	digest, err := canonicalDigest(sample)
	if err != nil {
		return ArtifactRef{}, err
	}
	if digest != sample.Artifact.SHA256 {
		return ArtifactRef{}, fmt.Errorf("sample value differs from immutable artifact digest")
	}
	if sample.artifactVerified {
		return sample.Artifact, nil
	}
	opened, err := LoadSampleArtifact(sampleEvidenceRoot(sample), sample.Artifact)
	if err != nil {
		return ArtifactRef{}, err
	}
	want := sample
	want.Artifact = ArtifactRef{}
	want.EvidenceRoot = ""
	want.artifactVerified = false
	opened.Artifact = ArtifactRef{}
	opened.EvidenceRoot = ""
	opened.artifactVerified = false
	if !reflect.DeepEqual(opened, want) {
		return ArtifactRef{}, fmt.Errorf("sample value differs from immutable artifact bytes")
	}
	return sample.Artifact, nil
}

func validateStartedSampleReasons(manifest Manifest, sample Sample, derived derivedSampleMetrics) []string {
	validators := []func() []string{
		func() []string { return validatePayloadEvidence(manifest, sample) },
		func() []string { return validateTraceEvidence(sample) },
		func() []string { return validateResourceEvidence(sample) },
		func() []string { return validateHealthEvidence(sample) },
		func() []string { return validateCleanupEvidence(sample) },
		func() []string { return validateDerivedSampleMeasurements(sample, derived) },
	}
	var reasons []string
	for _, validate := range validators {
		reasons = append(reasons, validate()...)
	}
	sort.Strings(reasons)
	return compactStrings(reasons)
}

func validateSampleIdentity(manifest Manifest, sample Sample) []string {
	var reasons []string
	if sample.SchemaVersion != sampleSchemaVersion {
		reasons = append(reasons, fmt.Sprintf("sample schema version = %d, want %d", sample.SchemaVersion, sampleSchemaVersion))
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil || sample.ManifestSHA256 != manifestDigest {
		reasons = append(reasons, "sample manifest digest does not identify current manifest")
	}
	candidate, ok := manifestCandidate(manifest, sample.CandidateID)
	if !ok {
		reasons = append(reasons, "candidate is not in manifest")
	} else if sample.BinarySet != (BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}) {
		reasons = append(reasons, "sample binary set does not match candidate")
	}
	if err := validateScheduledRun(manifest, sample); err != nil {
		reasons = append(reasons, err.Error())
	}
	return reasons
}

func validateDerivedSampleMeasurements(sample Sample, derived derivedSampleMetrics) []string {
	checks := []struct {
		valid  bool
		reason string
	}{
		{derived.started && sample.Started == derived.started, "started state differs from receiver result"},
		{derived.committedBytes == sample.Run.SizeBytes, "receiver committed bytes differ from scheduled size"},
		{sample.ObservedAtUTC == derived.observedAtUTC && validCanonicalTime(derived.observedAtUTC), "observed timestamp differs from receiver result"},
		{closeFloat(sample.GoodputMbps, derived.goodputMbps), "goodput differs from receiver result"},
		{closeFloat(sample.WallGoodputMbps, derived.wallGoodputMbps), "wall goodput differs from receiver result"},
		{closeFloat(sample.RecoveryRatio, derived.recoveryRatio), "recovery ratio differs from mechanism result"},
		{closeFloat(sample.ScanPerPacket, derived.scanPerPacket), "scan work differs from mechanism result"},
		{closeFloat(sample.FlatlineSeconds, derived.flatlineSeconds), "flatline differs from receiver result"},
		{sample.Trace.Engine == derived.engine && sample.Trace.PublicUDP == derived.publicUDP && sample.Trace.StrictValid == derived.strictValid, "trace summary differs from mechanism result"},
	}
	var reasons []string
	for _, check := range checks {
		if !check.valid {
			reasons = append(reasons, check.reason)
		}
	}
	return reasons
}

func deriveReceiverEvidence(sample Sample) (derivedSampleMetrics, []string) {
	root := sampleEvidenceRoot(sample)
	var result receiverResultRecord
	if err := verifyDecodeEvidence(root, sample.ReceiverResult, "receiver-result", &result); err != nil {
		return derivedSampleMetrics{}, []string{"receiver result artifact: " + err.Error()}
	}
	var mechanism mechanismResultRecord
	if err := verifyDecodeEvidence(root, sample.MechanismResult, "mechanism-result", &mechanism); err != nil {
		return derivedSampleMetrics{}, []string{"mechanism result artifact: " + err.Error()}
	}
	wantHost := receiverObserverHost(sample)
	if !receiverResultIdentityMatches(result, sample.Run.ID, wantHost) || !mechanismResultIdentityMatches(mechanism, sample.Run.ID, wantHost) {
		return derivedSampleMetrics{}, []string{"receiver result observer or run identity mismatch"}
	}
	if !validReceiverResultCounters(result) || !validMechanismResultCounters(mechanism) {
		return derivedSampleMetrics{}, []string{"receiver result contains invalid counters or timing"}
	}
	bitsCommitted := float64(result.CommittedBytes) * 8
	return derivedSampleMetrics{
		started:         result.Started,
		observedAtUTC:   result.ObservedAtUTC,
		committedBytes:  result.CommittedBytes,
		goodputMbps:     bitsCommitted / result.PayloadSeconds / 1e6,
		wallGoodputMbps: bitsCommitted / result.WallSeconds / 1e6,
		recoveryRatio:   float64(mechanism.RecoveredUnits) / float64(mechanism.TotalUnits),
		scanPerPacket:   float64(mechanism.ScanChecks) / float64(mechanism.PayloadPackets),
		flatlineSeconds: result.MaxFlatlineSeconds,
		engine:          mechanism.Engine,
		publicUDP:       mechanism.PublicUDP,
		strictValid:     mechanism.StrictValid,
	}, nil
}

func receiverResultIdentityMatches(result receiverResultRecord, runID, hostID string) bool {
	return result.SchemaVersion == 1 && result.Kind == "file-result" && result.RunID == runID &&
		result.ObserverRole == "receiver" && result.ObserverHostID == hostID
}

func mechanismResultIdentityMatches(result mechanismResultRecord, runID, hostID string) bool {
	return result.SchemaVersion == 1 && result.Kind == "mechanism-result" && result.RunID == runID &&
		result.ObserverRole == "receiver" && result.ObserverHostID == hostID
}

func validReceiverResultCounters(result receiverResultRecord) bool {
	return validCanonicalTime(result.ObservedAtUTC) && finitePositive(result.PayloadSeconds) && finitePositive(result.WallSeconds) &&
		finiteRange(result.MaxFlatlineSeconds, 0, math.MaxFloat64) && result.CommittedBytes >= 0
}

func validMechanismResultCounters(result mechanismResultRecord) bool {
	return result.TotalUnits > 0 && result.RecoveredUnits >= 0 && result.RecoveredUnits <= result.TotalUnits &&
		result.PayloadPackets > 0 && result.ScanChecks >= 0
}

func receiverObserverHost(sample Sample) string {
	if sample.Run.Direction == DirectionLocalToRemote {
		return sample.Run.HostID
	}
	return "local-mac"
}

func closeFloat(left, right float64) bool {
	if !finiteRange(left, 0, math.MaxFloat64) || !finiteRange(right, 0, math.MaxFloat64) {
		return false
	}
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= scale*1e-12
}

func validCanonicalTime(value string) bool {
	_, err := parseCanonicalUTCTime(value)
	return err == nil
}

func validateScheduledRun(manifest Manifest, sample Sample) error {
	run := sample.Run
	if err := validateScheduledRunShape(manifest, sample); err != nil {
		return err
	}
	frozen, index, ok := findFrozenRun(manifest, run.ID)
	if !ok {
		return fmt.Errorf("scheduled run is not frozen in manifest")
	}
	if !frozenRunMatches(run, frozen, index) {
		return fmt.Errorf("scheduled run identity differs from frozen manifest row")
	}
	return nil
}

func frozenRunMatches(run ScheduledRun, frozen FrozenSchedule, index int) bool {
	return run.Stage == stageForFrozenSchedule(frozen.Stage) && run.Order == index+1 && run.CandidateID == frozen.CandidateOrder[index] &&
		run.HostID == frozen.HostOrder[index] && run.Direction == manifestDirection(frozen.DirectionOrder[index]) &&
		run.Block == frozen.BlockOrder[index] && run.Schedule == frozen.Stage && run.Role == frozen.RunRoles[index]
}

func stageForFrozenSchedule(schedule string) Stage {
	switch {
	case schedule == string(StageFinalistRerun):
		return StageFinalistRerun
	case strings.HasPrefix(schedule, "ceiling-"):
		return StageCeiling
	default:
		return Stage(schedule)
	}
}

func validateScheduledRunShape(manifest Manifest, sample Sample) error {
	run := sample.Run
	if !validScheduledRunID(run.ID) {
		return fmt.Errorf("scheduled run ID is invalid")
	}
	if run.CandidateID != sample.CandidateID {
		return fmt.Errorf("scheduled run candidate does not match sample")
	}
	if run.SizeBytes != manifest.ManifestInput.Payload.Bytes {
		return fmt.Errorf("scheduled run size does not match manifest payload")
	}
	if !validScheduledRunPosition(run) {
		return fmt.Errorf("scheduled run order, block, or capacity requirement is invalid")
	}
	if !validDirectionValue(run.Direction) {
		return fmt.Errorf("scheduled run direction is invalid")
	}
	if !hostInManifest(manifest, run.HostID) {
		return fmt.Errorf("scheduled run host is not in manifest fleet")
	}
	return nil
}

func validScheduledRunID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && validIdentifier(value)
}

func validScheduledRunPosition(run ScheduledRun) bool {
	return run.Order > 0 && run.Block >= 0 && run.CapacityRequired
}

func findFrozenRun(manifest Manifest, runID string) (FrozenSchedule, int, bool) {
	for _, frozen := range manifest.ManifestInput.Schedules {
		for index, id := range frozen.RunIDs {
			if id == runID {
				return frozen, index, true
			}
		}
	}
	return FrozenSchedule{}, 0, false
}

func validatePayloadEvidence(manifest Manifest, sample Sample) []string {
	reasons := validatePayloadSummary(manifest, sample)
	root := sampleEvidenceRoot(sample)
	source, sourceReasons := loadHashEvidence(root, sample.Payload.SourceHashArtifact, "source-sha", sample.Run.ID, sample.Payload.SourceSHA256)
	sink, sinkReasons := loadHashEvidence(root, sample.Payload.SinkHashArtifact, "sink-sha", sample.Run.ID, sample.Payload.SinkSHA256)
	reasons = append(reasons, sourceReasons...)
	reasons = append(reasons, sinkReasons...)
	if len(sourceReasons) == 0 && len(sinkReasons) == 0 && !independentHashObservers(sample, source, sink) {
		reasons = append(reasons, "source and sink hash observations are not independent approved observers")
	}
	reasons = append(reasons, validateSizeEvidence(root, sample)...)
	return reasons
}

func validatePayloadSummary(manifest Manifest, sample Sample) []string {
	checks := []struct {
		valid  bool
		reason string
	}{
		{sample.Payload.SourceSHAReports == 1, "source SHA reports must equal one"},
		{sample.Payload.SinkSHAReports == 1, "sink SHA reports must equal one"},
		{validMatchingDigest(sample.Payload.SourceSHA256, sample.Payload.SinkSHA256), "source and sink SHA must be identical canonical digests"},
		{sample.Payload.SourceSHA256 == manifest.ManifestInput.Payload.SHA256, "payload SHA does not match manifest"},
		{sample.Payload.SinkSizeBytes == sample.Run.SizeBytes, "sink size does not match scheduled size"},
	}
	var reasons []string
	for _, check := range checks {
		if !check.valid {
			reasons = append(reasons, check.reason)
		}
	}
	return reasons
}

func validMatchingDigest(source, sink SHA256Digest) bool {
	return validateSHA256Digest(source) == nil && sink == source
}

func loadHashEvidence(root string, ref ArtifactRef, role, runID string, digest SHA256Digest) (hashEvidenceRecord, []string) {
	var record hashEvidenceRecord
	if err := verifyDecodeEvidence(root, ref, role, &record); err != nil {
		return hashEvidenceRecord{}, []string{role + " artifact: " + err.Error()}
	}
	if record.SchemaVersion != 1 || record.Kind != "hash-observation" || record.RunID != runID || record.SHA256 != digest || record.Reports != 1 {
		return hashEvidenceRecord{}, []string{role + " artifact semantic mismatch"}
	}
	return record, nil
}

func independentHashObservers(sample Sample, source, sink hashEvidenceRecord) bool {
	return source.ObserverRole == "source" && sink.ObserverRole == "sink" &&
		source.ObserverHostID == sourceObserverHost(sample) && sink.ObserverHostID == receiverObserverHost(sample) &&
		source.ObserverHostID != sink.ObserverHostID && source.ObserverRole != sink.ObserverRole
}

func sourceObserverHost(sample Sample) string {
	if sample.Run.Direction == DirectionLocalToRemote {
		return "local-mac"
	}
	return sample.Run.HostID
}

func validateSizeEvidence(root string, sample Sample) []string {
	var record sizeEvidenceRecord
	if err := verifyDecodeEvidence(root, sample.Payload.SinkSizeArtifact, "sink-size", &record); err != nil {
		return []string{"sink size artifact: " + err.Error()}
	}
	if record.SchemaVersion != 1 || record.Kind != "size" || record.RunID != sample.Run.ID || record.SizeBytes != sample.Payload.SinkSizeBytes {
		return []string{"sink size artifact semantic mismatch"}
	}
	return nil
}

func validateCapacityEvidence(manifest Manifest, sample Sample) (bool, []string) {
	var reasons []string
	if sample.Capacity.Direction != sample.Run.Direction {
		reasons = append(reasons, "capacity direction does not match run")
	}
	var record capacityEvidenceRecord
	if err := verifyDecodeEvidence(sampleEvidenceRoot(sample), sample.Capacity.Artifact, "capacity", &record); err != nil {
		reasons = append(reasons, "capacity artifact: "+err.Error())
		return false, reasons
	}
	derivedValid := finitePositive(record.Mbps) && record.Mbps >= manifest.ManifestInput.Rules.CapacityMinimumMbps
	if !capacityRecordMatches(record, sample, derivedValid) {
		reasons = append(reasons, "capacity artifact semantic mismatch")
	}
	return derivedValid, reasons
}

func capacityRecordMatches(record capacityEvidenceRecord, sample Sample, derivedValid bool) bool {
	return record.SchemaVersion == 1 && record.Kind == "capacity" && record.RunID == sample.Run.ID &&
		record.Direction == sample.Capacity.Direction && record.Mbps == sample.Capacity.Mbps &&
		record.Valid == derivedValid && sample.Capacity.Valid == derivedValid
}

func validateTraceEvidence(sample Sample) []string {
	var reasons []string
	if sample.Trace.Engine != "bulk-packets-v1" && sample.Trace.Engine != "quic-blocks-v1" {
		reasons = append(reasons, "selected engine is not an approved UDP file engine")
	}
	if !sample.Trace.PublicUDP || !sample.Trace.StrictValid {
		reasons = append(reasons, "paired trace is not strict public UDP")
	}
	reasons = append(reasons, validateOneTraceEvidence(sample, "sender", sample.Trace.Sender)...)
	reasons = append(reasons, validateOneTraceEvidence(sample, "receiver", sample.Trace.Receiver)...)
	return reasons
}

func validateOneTraceEvidence(sample Sample, role string, ref ArtifactRef) []string {
	var record traceEvidenceRecord
	if err := verifyDecodeEvidence(sampleEvidenceRoot(sample), ref, "trace-"+role, &record); err != nil {
		return []string{role + " trace artifact: " + err.Error()}
	}
	if record.SchemaVersion != 1 || record.Kind != "trace" || record.RunID != sample.Run.ID || record.Role != role || record.Direction != sample.Run.Direction || record.Engine != sample.Trace.Engine || record.PublicUDP != sample.Trace.PublicUDP || record.StrictValid != sample.Trace.StrictValid {
		return []string{role + " trace artifact semantic mismatch"}
	}
	return nil
}

func validateResourceEvidence(sample Sample) []string {
	var reasons []string
	for role, item := range map[string]struct {
		ref          ArtifactRef
		user, system float64
	}{
		"sender":   {sample.Resource.Sender, sample.Resource.SenderUserSeconds, sample.Resource.SenderSystemSeconds},
		"receiver": {sample.Resource.Receiver, sample.Resource.ReceiverUserSeconds, sample.Resource.ReceiverSystemSeconds},
	} {
		if !finiteRange(item.user, 0, math.MaxFloat64) || !finiteRange(item.system, 0, math.MaxFloat64) {
			reasons = append(reasons, role+" resource seconds are invalid")
		}
		reasons = append(reasons, validateOneResourceEvidence(sample, role, item.ref, item.user, item.system)...)
	}
	return reasons
}

func validateOneResourceEvidence(sample Sample, role string, ref ArtifactRef, user, system float64) []string {
	var record resourceEvidenceRecord
	if err := verifyDecodeEvidence(sampleEvidenceRoot(sample), ref, "resource-"+role, &record); err != nil {
		return []string{role + " resource artifact: " + err.Error()}
	}
	if record.SchemaVersion != 1 || record.Kind != "resource" || record.RunID != sample.Run.ID || record.Role != role || record.UserSeconds != user || record.SystemSeconds != system {
		return []string{role + " resource artifact semantic mismatch"}
	}
	return nil
}

func validateHealthEvidence(sample Sample) []string {
	var reasons []string
	if !sample.Health.Healthy {
		reasons = append(reasons, "health evidence is unhealthy")
	}
	for phase, ref := range map[string]ArtifactRef{"before": sample.Health.Before, "after": sample.Health.After} {
		var raw healthEvidenceRecord
		if err := verifyDecodeEvidence(sampleEvidenceRoot(sample), ref, "health-"+phase, &raw); err != nil {
			reasons = append(reasons, phase+" health artifact: "+err.Error())
			continue
		}
		if raw.SchemaVersion != 1 || raw.Kind != "health" || raw.RunID != sample.Run.ID || raw.Phase != phase || raw.Healthy != sample.Health.Healthy {
			reasons = append(reasons, phase+" health artifact semantic mismatch")
		}
	}
	return reasons
}

func validateCleanupEvidence(sample Sample) []string {
	cleanup := sample.Cleanup
	if !cleanupComplete(cleanup) {
		return []string{"cleanup evidence is incomplete"}
	}
	var raw cleanupEvidenceRecord
	if err := verifyDecodeEvidence(sampleEvidenceRoot(sample), cleanup.Artifact, "cleanup", &raw); err != nil {
		return []string{"cleanup artifact: " + err.Error()}
	}
	if raw.SchemaVersion != 1 || raw.Kind != "cleanup" || raw.RunID != sample.Run.ID || raw.ScopedRootRemoved != cleanup.ScopedRootRemoved || raw.ProcessesRemoved != cleanup.ProcessesRemoved || raw.SocketsRemoved != cleanup.SocketsRemoved || raw.PayloadsRemoved != cleanup.PayloadsRemoved {
		return []string{"cleanup artifact semantic mismatch"}
	}
	return nil
}

func cleanupComplete(cleanup CleanupEvidence) bool {
	return cleanup.ScopedRootRemoved && cleanup.ProcessesRemoved && cleanup.SocketsRemoved && cleanup.PayloadsRemoved
}

func verifyDecodeEvidence(root string, ref ArtifactRef, role string, target any) error {
	if err := validateArtifactRef(ref, role); err != nil {
		return err
	}
	rooted, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open evidence root: %w", err)
	}
	data, readErr := rooted.ReadFile(filepath.FromSlash(ref.Path))
	closeErr := rooted.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	return verifyDecodeEvidenceData(ref, target, data)
}

func verifyDecodeEvidenceWithReader(root string, ref ArtifactRef, role string, target any, readFile func(string) ([]byte, error)) error {
	if err := validateArtifactRef(ref, role); err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(ref.Path))
	data, err := readFile(path)
	if err != nil {
		return err
	}
	return verifyDecodeEvidenceData(ref, target, data)
}

func verifyDecodeEvidenceData(ref ArtifactRef, target any, data []byte) error {
	if got := DigestBytes(data); got != ref.SHA256 {
		return fmt.Errorf("artifact digest = %s, want %s", got, ref.SHA256)
	}
	if err := decodeStrictEvidenceJSON(data, target); err != nil {
		return err
	}
	canonical, err := canonicalJSONBytes(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("artifact bytes are not canonical JSON")
	}
	return nil
}

func decodeStrictEvidenceJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := requireEvidenceEOF(decoder); err != nil {
		return err
	}
	return nil
}

func requireEvidenceEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected trailing JSON value")
}

func sampleEvidenceRoot(sample Sample) string {
	if sample.EvidenceRoot == "" {
		return "."
	}
	return sample.EvidenceRoot
}

func manifestCandidate(manifest Manifest, id string) (CandidateIdentity, bool) {
	for _, candidate := range manifest.ManifestInput.Candidates {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return CandidateIdentity{}, false
}

func hostInManifest(manifest Manifest, id string) bool {
	for _, host := range manifest.ManifestInput.FleetInventory {
		if host.ID == id {
			return true
		}
	}
	return false
}

func manifestDirection(value string) Direction {
	if value == "mac-to-hetz" {
		return DirectionLocalToRemote
	}
	if value == "hetz-to-mac" {
		return DirectionRemoteToLocal
	}
	return ""
}

func validDirectionValue(direction Direction) bool {
	return direction == DirectionLocalToRemote || direction == DirectionRemoteToLocal
}

func canonicalDigest(value any) (SHA256Digest, error) {
	data, err := canonicalJSONBytes(value)
	if err != nil {
		return "", err
	}
	return DigestBytes(data), nil
}

func finitePositive(value float64) bool {
	return finiteRange(value, math.SmallestNonzeroFloat64, math.MaxFloat64)
}

func finiteRange(value, minimum, maximum float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= minimum && value <= maximum
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	output := values[:0]
	for _, value := range values {
		if len(output) == 0 || output[len(output)-1] != value {
			output = append(output, value)
		}
	}
	return output
}

func containsReason(reasons []string, fragment string) bool {
	fragment = strings.ToLower(fragment)
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), fragment) {
			return true
		}
	}
	return false
}
