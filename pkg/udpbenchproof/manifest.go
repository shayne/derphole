// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	manifestSchemaVersion             = 1
	baselineHealthRecordSchemaVersion = 1
	exactOneGiB                       = int64(1024 * 1024 * 1024)
	exactThreeGiB                     = int64(3 * 1024 * 1024 * 1024)
)

// BinaryIdentity binds one platform binary to its exact source revision.
type BinaryIdentity struct {
	Platform    string       `json:"platform"`
	SHA256      SHA256Digest `json:"sha256"`
	VCSRevision string       `json:"vcs_revision"`
}

// CandidateIdentity binds a predeclared candidate to both platform binaries.
type CandidateIdentity struct {
	ID     string            `json:"id"`
	Commit string            `json:"commit"`
	Darwin BinaryIdentity    `json:"darwin"`
	Linux  BinaryIdentity    `json:"linux"`
	Config map[string]string `json:"config"`
}

// ManifestKind is one typed proof stage.
type ManifestKind string

const (
	ManifestExperiment ManifestKind = "experiment"
	ManifestProduction ManifestKind = "production"
	ManifestAcceptance ManifestKind = "acceptance"
	ManifestCeiling    ManifestKind = "ceiling"
)

// ArtifactRef hash-binds an artifact and assigns its unambiguous proof role.
type ArtifactRef struct {
	Role   string       `json:"role"`
	Path   string       `json:"path"`
	SHA256 SHA256Digest `json:"sha256"`
}

// PayloadIdentity binds the exact ordinary file used by a stage.
type PayloadIdentity struct {
	Bytes  int64        `json:"bytes"`
	SHA256 SHA256Digest `json:"sha256"`
}

// FrozenSchedule predeclares every run and its exact ordering.
type FrozenSchedule struct {
	Stage           string    `json:"stage"`
	RunIDs          []string  `json:"run_ids"`
	CandidateOrder  []string  `json:"candidate_order"`
	HostOrder       []string  `json:"host_order"`
	DirectionOrder  []string  `json:"direction_order"`
	BlockOrder      []int     `json:"block_order"`
	RunRoles        []string  `json:"run_roles"`
	OfferedLoadMbps []float64 `json:"offered_load_mbps"`
	Repetitions     int       `json:"repetitions"`
}

// FrozenRules contains the immutable campaign gates.
type FrozenRules struct {
	CapacityMinimumMbps        float64 `json:"capacity_minimum_mbps"`
	FileMinimumMbps            float64 `json:"file_minimum_mbps"`
	MaxCV                      float64 `json:"max_cv"`
	MaterialDelta              float64 `json:"material_delta"`
	ScreenDominance            float64 `json:"screen_dominance"`
	FinalistDelta              float64 `json:"finalist_delta"`
	MaxRecovery                float64 `json:"max_recovery"`
	MaxScanPerPacket           float64 `json:"max_scan_per_packet"`
	MaxCPUSecondsPerGiB        float64 `json:"max_cpu_seconds_per_gib"`
	MinCeilingCPUSaturation    float64 `json:"min_ceiling_cpu_saturation"`
	MinCeilingKernelSaturation float64 `json:"min_ceiling_kernel_saturation"`
	RequiredProfileAgreement   float64 `json:"required_profile_agreement"`
	CapacityAttempts           int     `json:"capacity_attempts"`
	MinRepeatedCeilingProfiles int     `json:"min_repeated_ceiling_profiles"`
}

// HostIdentity is one canonical fleet member.
type HostIdentity struct {
	ID           string   `json:"id"`
	SSH          string   `json:"ssh"`
	PublicIPv4   string   `json:"public_ipv4"`
	Role         HostRole `json:"role"`
	EricWatchdog bool     `json:"eric_watchdog"`
}

// BaselineHealthIdentity hash-binds one stage's fresh remote health capture.
type BaselineHealthIdentity struct {
	Artifact      ArtifactRef `json:"artifact"`
	CapturedAtUTC string      `json:"captured_at_utc"`
	Sequence      uint64      `json:"sequence"`
	HostID        string      `json:"host_id"`
	BootID        string      `json:"boot_id"`
}

// BaselineHealthRecord is the canonical semantic content of one health artifact.
// It intentionally excludes the ArtifactRef that identifies its serialized bytes.
type BaselineHealthRecord struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          ManifestKind      `json:"kind"`
	CapturedAtUTC string            `json:"captured_at_utc"`
	Sequence      uint64            `json:"sequence"`
	HostID        string            `json:"host_id"`
	BootID        string            `json:"boot_id"`
	Counters      map[string]uint64 `json:"counters"`
}

// HostRole assigns an explicit proof role without inferring identity from names.
type HostRole string

const (
	HostRolePrimary  HostRole = "primary"
	HostRoleFleet    HostRole = "fleet"
	HostRoleWatchdog HostRole = "watchdog"
)

// ManifestInput is the complete immutable input to one proof stage.
type ManifestInput struct {
	Kind                   ManifestKind           `json:"kind"`
	ParentManifest         *ArtifactRef           `json:"parent_manifest"`
	ParentDecisionRefs     []ArtifactRef          `json:"parent_decision_refs"`
	LocalPublicIPv4        string                 `json:"local_public_ipv4"`
	RemotePublicIPv4       string                 `json:"remote_public_ipv4"`
	RemoteKernel           string                 `json:"remote_kernel"`
	RemoteArch             string                 `json:"remote_arch"`
	RemoteBootID           string                 `json:"remote_boot_id"`
	RemoteOnlineCPUs       int                    `json:"remote_online_cpus"`
	Payload                PayloadIdentity        `json:"payload"`
	Candidates             []CandidateIdentity    `json:"candidates"`
	ScreeningControlID     string                 `json:"screening_control_id"`
	Schedules              []FrozenSchedule       `json:"schedules"`
	Rules                  FrozenRules            `json:"rules"`
	ProductionEnvironment  map[string]string      `json:"production_environment"`
	FleetInventory         []HostIdentity         `json:"fleet_inventory"`
	BaselineHealthIdentity BaselineHealthIdentity `json:"baseline_health_identity"`
	BaselineHealthCounters map[string]uint64      `json:"baseline_health_counters"`
	CapacityTCPPort        int                    `json:"capacity_tcp_port"`
}

// Manifest is a versioned proof-stage manifest.
type Manifest struct {
	SchemaVersion int           `json:"schema_version"`
	ManifestInput ManifestInput `json:"manifest_input"`
	EvidenceRoot  string        `json:"-"`
}

// NewManifest validates and returns a versioned manifest.
func NewManifest(input ManifestInput) (Manifest, error) {
	manifest := Manifest{SchemaVersion: manifestSchemaVersion, ManifestInput: cloneManifestInputValue(input)}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// ValidateManifest fail-closes every identity and stage requirement.
func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != manifestSchemaVersion {
		return fmt.Errorf("unsupported manifest schema version %d", manifest.SchemaVersion)
	}
	input := manifest.ManifestInput
	if !validManifestKind(input.Kind) {
		return fmt.Errorf("invalid manifest kind %q", input.Kind)
	}
	if err := validateEndpointIdentity(input); err != nil {
		return err
	}
	if err := validatePayloadIdentity(input.Kind, input.Payload); err != nil {
		return err
	}
	candidateIDs, err := validateCandidateIdentities(input.Kind, input.Candidates)
	if err != nil {
		return err
	}
	return runManifestValidators(
		func() error { return validateFrozenRules(input.Rules) },
		func() error { return validateFrozenSchedules(input, candidateIDs) },
		func() error { return validateProductionEnvironment(input.ProductionEnvironment) },
		func() error { return validateFleetInventory(input.FleetInventory, input.RemotePublicIPv4) },
		func() error { return validateBaselineHealth(input) },
		func() error { return validateCapacityPort(input.CapacityTCPPort) },
		func() error {
			return validateStageReferences(input.Kind, input.ParentManifest, input.ParentDecisionRefs)
		},
	)
}

// VerifyManifestTransition verifies the canonical parent hash and typed child relationship.
func VerifyManifestTransition(parent Manifest, parentDigest SHA256Digest, child Manifest) error {
	if err := validateTransitionManifests(parent, child); err != nil {
		return err
	}
	if err := verifyParentDigestBinding(parent, parentDigest, child.ManifestInput); err != nil {
		return err
	}
	if err := validateStageTransition(parent.ManifestInput.Kind, child.ManifestInput.Kind); err != nil {
		return err
	}
	if err := verifyStableTransitionIdentity(parent.ManifestInput, child.ManifestInput); err != nil {
		return err
	}
	if err := verifyFreshBaselineHealthIdentity(parent.ManifestInput, child.ManifestInput); err != nil {
		return err
	}
	return verifyKindTransition(parent.ManifestInput, child.ManifestInput)
}

func validateTransitionManifests(parent, child Manifest) error {
	if err := ValidateManifest(parent); err != nil {
		return fmt.Errorf("invalid parent manifest: %w", err)
	}
	if err := ValidateManifest(child); err != nil {
		return fmt.Errorf("invalid child manifest: %w", err)
	}
	return nil
}

func verifyParentDigestBinding(parent Manifest, parentDigest SHA256Digest, child ManifestInput) error {
	if err := validateSHA256Digest(parentDigest); err != nil {
		return fmt.Errorf("invalid supplied parent digest: %w", err)
	}
	parentBytes, err := canonicalJSONBytes(parent)
	if err != nil {
		return err
	}
	if got := DigestBytes(parentBytes); got != parentDigest {
		return fmt.Errorf("supplied parent digest %s does not identify typed parent %s", parentDigest, got)
	}
	if child.ParentManifest == nil || child.ParentManifest.SHA256 != parentDigest {
		return fmt.Errorf("child does not bind supplied parent digest")
	}
	return nil
}

func verifyKindTransition(parent, child ManifestInput) error {
	switch child.Kind {
	case ManifestProduction:
		return verifyProductionTransition(parent, child)
	case ManifestAcceptance:
		return verifyAcceptanceTransition(parent, child)
	case ManifestCeiling:
		return verifyCeilingTransition(parent, child)
	default:
		return fmt.Errorf("kind %q cannot be a child manifest", child.Kind)
	}
}

func runManifestValidators(validators ...func() error) error {
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateCapacityPort(port int) error {
	if port != 8123 {
		return fmt.Errorf("capacity TCP port = %d, want 8123", port)
	}
	return nil
}

func validManifestKind(kind ManifestKind) bool {
	switch kind {
	case ManifestExperiment, ManifestProduction, ManifestAcceptance, ManifestCeiling:
		return true
	default:
		return false
	}
}

func validateEndpointIdentity(input ManifestInput) error {
	if input.LocalPublicIPv4 == input.RemotePublicIPv4 {
		return fmt.Errorf("local and remote public IPv4 identities must differ")
	}
	if err := validatePublicIPv4(input.LocalPublicIPv4); err != nil {
		return fmt.Errorf("local public IPv4: %w", err)
	}
	if err := validatePublicIPv4(input.RemotePublicIPv4); err != nil {
		return fmt.Errorf("remote public IPv4: %w", err)
	}
	for field, value := range map[string]string{
		"remote kernel":       input.RemoteKernel,
		"remote architecture": input.RemoteArch,
		"remote boot ID":      input.RemoteBootID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is empty", field)
		}
	}
	if !validBootID(input.RemoteBootID) {
		return fmt.Errorf("remote boot ID %q is not a canonical UUID", input.RemoteBootID)
	}
	if input.RemoteArch != "x86_64" {
		return fmt.Errorf("remote architecture = %q, want x86_64", input.RemoteArch)
	}
	if input.RemoteOnlineCPUs != 2 {
		return fmt.Errorf("remote online CPUs = %d, want exactly 2", input.RemoteOnlineCPUs)
	}
	return nil
}

func validatePublicIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("%q is not a literal canonical IPv4 address", value)
	}
	if !address.Is4() || address.String() != value {
		return fmt.Errorf("%q is not a literal canonical IPv4 address", value)
	}
	if unusablePublicProofAddress(address) {
		return fmt.Errorf("%q is not a public unicast IPv4 address", value)
	}
	for _, prefix := range forbiddenPublicProofPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("%q is in forbidden special-purpose range %s", value, prefix)
		}
	}
	return nil
}

func unusablePublicProofAddress(address netip.Addr) bool {
	return !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified()
}

var forbiddenPublicProofPrefixes = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func validatePayloadIdentity(kind ManifestKind, payload PayloadIdentity) error {
	wantBytes := exactOneGiB
	if kind == ManifestAcceptance {
		wantBytes = exactThreeGiB
	}
	if payload.Bytes != wantBytes {
		return fmt.Errorf("%s payload bytes = %d, want %d", kind, payload.Bytes, wantBytes)
	}
	if err := validateSHA256Digest(payload.SHA256); err != nil {
		return fmt.Errorf("payload SHA-256: %w", err)
	}
	return nil
}

func validateCandidateIdentities(kind ManifestKind, candidates []CandidateIdentity) ([]string, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("candidate registry is empty")
	}
	if kind != ManifestExperiment && len(candidates) != 1 {
		return nil, fmt.Errorf("%s manifest requires exactly one explicit candidate identity", kind)
	}
	ids := make(map[string]struct{}, len(candidates))
	orderedIDs := make([]string, 0, len(candidates))
	configs := make(map[string]string, len(candidates))
	for index, candidate := range candidates {
		configKey, err := validateCandidateIdentity(kind, candidate, index)
		if err != nil {
			return nil, err
		}
		if _, exists := ids[candidate.ID]; exists {
			return nil, fmt.Errorf("duplicate candidate ID %q", candidate.ID)
		}
		ids[candidate.ID] = struct{}{}
		orderedIDs = append(orderedIDs, candidate.ID)
		if previous, exists := configs[configKey]; exists {
			return nil, fmt.Errorf("candidates %q and %q have duplicate configuration identity", previous, candidate.ID)
		}
		configs[configKey] = candidate.ID
	}
	return orderedIDs, nil
}

func validateCandidateIdentity(kind ManifestKind, candidate CandidateIdentity, index int) (string, error) {
	if !validIdentifier(candidate.ID) {
		return "", fmt.Errorf("candidate %d has empty ID", index)
	}
	if !validCommit(candidate.Commit) {
		return "", fmt.Errorf("candidate %q has invalid commit %q", candidate.ID, candidate.Commit)
	}
	if err := validateBinaryIdentity(candidate.ID, candidate.Commit, "Darwin", candidate.Darwin, "darwin-"); err != nil {
		return "", err
	}
	if err := validateBinaryIdentity(candidate.ID, candidate.Commit, "Linux", candidate.Linux, "linux-"); err != nil {
		return "", err
	}
	return candidateConfigurationIdentity(kind, candidate)
}

func candidateConfigurationIdentity(kind ManifestKind, candidate CandidateIdentity) (string, error) {
	if len(candidate.Config) == 0 {
		return "", fmt.Errorf("candidate %q has no explicit configuration", candidate.ID)
	}
	for key, value := range candidate.Config {
		if !validIdentifier(key) || strings.TrimSpace(value) == "" || containsControl(value) {
			return "", fmt.Errorf("candidate %q has empty configuration key or value", candidate.ID)
		}
	}
	want := map[string]string{"candidate": candidate.ID}
	switch kind {
	case ManifestProduction, ManifestAcceptance:
		want = map[string]string{"mode": "source-default"}
	case ManifestCeiling:
		want = map[string]string{"mode": "diagnostic"}
	}
	if !reflect.DeepEqual(candidate.Config, want) {
		return "", fmt.Errorf("candidate %q configuration does not match exact %s identity", candidate.ID, kind)
	}
	configBytes, err := json.Marshal(candidate.Config)
	if err != nil {
		return "", fmt.Errorf("candidate %q configuration: %w", candidate.ID, err)
	}
	return string(configBytes), nil
}

func validateBinaryIdentity(candidateID, commit, label string, binary BinaryIdentity, platformPrefix string) error {
	wantPlatform := "darwin-arm64"
	if platformPrefix == "linux-" {
		wantPlatform = "linux-amd64"
	}
	if binary.Platform != wantPlatform {
		return fmt.Errorf("candidate %q has invalid %s platform %q", candidateID, label, binary.Platform)
	}
	if err := validateSHA256Digest(binary.SHA256); err != nil {
		return fmt.Errorf("candidate %q %s binary: %w", candidateID, label, err)
	}
	if binary.VCSRevision != commit {
		return fmt.Errorf("candidate %q %s revision %q does not match commit %q", candidateID, label, binary.VCSRevision, commit)
	}
	return nil
}

func validateFrozenRules(rules FrozenRules) error {
	want := FrozenRules{
		CapacityMinimumMbps:        2050,
		FileMinimumMbps:            2000,
		MaxCV:                      0.10,
		MaterialDelta:              0.03,
		ScreenDominance:            0.10,
		FinalistDelta:              0.05,
		MaxRecovery:                0.02,
		MaxScanPerPacket:           2.0,
		MaxCPUSecondsPerGiB:        8.0,
		MinCeilingCPUSaturation:    0.90,
		MinCeilingKernelSaturation: 0.90,
		RequiredProfileAgreement:   1.0,
		CapacityAttempts:           3,
		MinRepeatedCeilingProfiles: 2,
	}
	if rules != want {
		return fmt.Errorf("frozen rules differ from approved proof contract")
	}
	return nil
}

func validateFrozenSchedules(input ManifestInput, candidateIDs []string) error {
	schedules := input.Schedules
	if len(schedules) == 0 {
		return fmt.Errorf("frozen schedules are empty")
	}
	stages := make(map[string]FrozenSchedule, len(schedules))
	candidateSet := make(map[string]struct{}, len(candidateIDs))
	for _, candidateID := range candidateIDs {
		candidateSet[candidateID] = struct{}{}
	}
	hostIDs := make(map[string]struct{}, len(input.FleetInventory))
	for _, host := range input.FleetInventory {
		hostIDs[host.ID] = struct{}{}
	}
	state := frozenScheduleValidationState{candidateIDs: candidateSet, hostIDs: hostIDs, runIDs: make(map[string]struct{})}
	for _, schedule := range schedules {
		if _, exists := stages[schedule.Stage]; exists {
			return fmt.Errorf("duplicate schedule stage %q", schedule.Stage)
		}
		if err := state.validate(schedule); err != nil {
			return err
		}
		stages[schedule.Stage] = schedule
	}
	return validateKindSchedules(input, schedules, stages, candidateIDs)
}

type frozenScheduleValidationState struct {
	candidateIDs map[string]struct{}
	hostIDs      map[string]struct{}
	runIDs       map[string]struct{}
}

func (state frozenScheduleValidationState) validate(schedule FrozenSchedule) error {
	if strings.TrimSpace(schedule.Stage) == "" {
		return fmt.Errorf("schedule has empty stage")
	}
	if !completeFrozenScheduleColumns(schedule) {
		return fmt.Errorf("schedule %q has incomplete run/candidate/host/direction/block/role order", schedule.Stage)
	}
	if schedule.Repetitions <= 0 {
		return fmt.Errorf("schedule %q has invalid repetitions %d", schedule.Stage, schedule.Repetitions)
	}
	if len(schedule.OfferedLoadMbps) != 0 && len(schedule.OfferedLoadMbps) != len(schedule.RunIDs) {
		return fmt.Errorf("schedule %q offered-load order is incomplete", schedule.Stage)
	}
	for index, runID := range schedule.RunIDs {
		if err := state.validateRow(schedule, index, runID); err != nil {
			return err
		}
	}
	return nil
}

func (state frozenScheduleValidationState) validateRow(schedule FrozenSchedule, index int, runID string) error {
	if !validIdentifier(runID) {
		return fmt.Errorf("schedule %q has unsafe run ID %q", schedule.Stage, runID)
	}
	if _, exists := state.runIDs[runID]; exists {
		return fmt.Errorf("duplicate run ID %q", runID)
	}
	state.runIDs[runID] = struct{}{}
	if _, exists := state.candidateIDs[schedule.CandidateOrder[index]]; !exists {
		return fmt.Errorf("schedule %q references unknown candidate %q", schedule.Stage, schedule.CandidateOrder[index])
	}
	if !validDirection(schedule.DirectionOrder[index]) {
		return fmt.Errorf("schedule %q has invalid direction %q", schedule.Stage, schedule.DirectionOrder[index])
	}
	if _, exists := state.hostIDs[schedule.HostOrder[index]]; !exists {
		return fmt.Errorf("schedule %q references unknown host %q", schedule.Stage, schedule.HostOrder[index])
	}
	if schedule.BlockOrder[index] < 0 {
		return fmt.Errorf("schedule %q has negative block", schedule.Stage)
	}
	if !validRunRole(schedule.RunRoles[index]) {
		return fmt.Errorf("schedule %q has invalid run role %q", schedule.Stage, schedule.RunRoles[index])
	}
	return nil
}

func completeFrozenScheduleColumns(schedule FrozenSchedule) bool {
	rows := len(schedule.RunIDs)
	return rows > 0 && rows == len(schedule.CandidateOrder) && rows == len(schedule.HostOrder) &&
		rows == len(schedule.DirectionOrder) && rows == len(schedule.BlockOrder) && rows == len(schedule.RunRoles)
}

func validRunRole(role string) bool {
	switch role {
	case "control-before", "candidate", "control-after", "file", "ceiling-sweep", "ceiling-profile":
		return true
	default:
		return false
	}
}

func validDirection(direction string) bool {
	return direction == "hetz-to-mac" || direction == "mac-to-hetz"
}

func validateKindSchedules(input ManifestInput, schedules []FrozenSchedule, stages map[string]FrozenSchedule, candidateIDs []string) error {
	switch input.Kind {
	case ManifestExperiment:
		return validateExperimentSchedules(input, schedules, stages, candidateIDs)
	case ManifestProduction:
		return validateProductionSchedules(input, schedules, stages)
	case ManifestAcceptance:
		return validateSingleFileSchedule(schedules, stages, "acceptance")
	case ManifestCeiling:
		return validateCeilingSchedules(schedules, stages, input.Rules)
	}
	return nil
}

func validateExperimentSchedules(input ManifestInput, schedules []FrozenSchedule, stages map[string]FrozenSchedule, candidateIDs []string) error {
	if err := requireExactStageOrder(schedules, "screening", "preliminary", "finalist", "finalist-rerun"); err != nil {
		return err
	}
	for _, stage := range schedules {
		if len(stage.OfferedLoadMbps) != 0 {
			return fmt.Errorf("file candidate schedules cannot contain offered UDP loads")
		}
	}
	if err := validateScreeningSchedule(input, stages["screening"], candidateIDs); err != nil {
		return err
	}
	if stages["preliminary"].Repetitions != 3 || stages["finalist"].Repetitions != 3 || stages["finalist-rerun"].Repetitions != 6 {
		return fmt.Errorf("experiment schedule repetitions must be preliminary=3 finalist=3 rerun=6")
	}
	if err := validateBalancedCandidateSchedule(input, stages["preliminary"], candidateIDs, 3); err != nil {
		return err
	}
	if err := validateBalancedCandidateSchedule(input, stages["finalist"], candidateIDs, 3); err != nil {
		return err
	}
	return validateBalancedCandidateSchedule(input, stages["finalist-rerun"], candidateIDs, 6)
}

func validateBalancedCandidateSchedule(input ManifestInput, schedule FrozenSchedule, candidateIDs []string, repetitions int) error {
	if err := validateCandidateDirectionMultiplicity(schedule, candidateIDs, repetitions, true); err != nil {
		return err
	}
	want := balancedCandidateRows(input, candidateIDs, repetitions)
	for row := range want {
		if !balancedCandidateRowMatches(schedule, row, want[row]) {
			return fmt.Errorf("schedule %q row %d does not match exact balanced rotation", schedule.Stage, row)
		}
	}
	return nil
}

type balancedCandidateRow struct {
	candidateID string
	hostID      string
	direction   string
	block       int
}

func balancedCandidateRows(input ManifestInput, candidateIDs []string, repetitions int) []balancedCandidateRow {
	rotations := finalistRotation(candidateIDs)
	primaryHost := ""
	for _, host := range input.FleetInventory {
		if host.Role == HostRolePrimary {
			primaryHost = host.ID
			break
		}
	}
	rows := make([]balancedCandidateRow, 0, len(candidateIDs)*repetitions*2)
	for _, direction := range []string{"hetz-to-mac", "mac-to-hetz"} {
		for repetition := range repetitions {
			for _, candidateID := range rotations[repetition%len(rotations)] {
				rows = append(rows, balancedCandidateRow{candidateID: candidateID, hostID: primaryHost, direction: direction, block: repetition})
			}
		}
	}
	return rows
}

func balancedCandidateRowMatches(schedule FrozenSchedule, row int, want balancedCandidateRow) bool {
	return schedule.CandidateOrder[row] == want.candidateID && schedule.DirectionOrder[row] == want.direction &&
		schedule.HostOrder[row] == want.hostID && schedule.BlockOrder[row] == want.block && schedule.RunRoles[row] == "file"
}

func validateScreeningSchedule(input ManifestInput, schedule FrozenSchedule, candidateIDs []string) error {
	if !validIdentifier(input.ScreeningControlID) {
		return fmt.Errorf("screening control identity is invalid")
	}
	if _, ok := manifestCandidate(Manifest{ManifestInput: input}, input.ScreeningControlID); !ok {
		return fmt.Errorf("screening control is not a manifest candidate")
	}
	if schedule.Repetitions != 1 || len(schedule.RunIDs) != len(candidateIDs)*3 {
		return fmt.Errorf("screening must freeze one before/candidate/after triple per candidate")
	}
	for candidateIndex, candidateID := range candidateIDs {
		start := candidateIndex * 3
		wantCandidates := []string{input.ScreeningControlID, candidateID, input.ScreeningControlID}
		wantRoles := []string{"control-before", "candidate", "control-after"}
		for offset := range 3 {
			index := start + offset
			if !screeningRowMatches(schedule, index, wantCandidates[offset], wantRoles[offset], candidateIndex) {
				return fmt.Errorf("screening row %d does not freeze exact control bracket", index)
			}
		}
	}
	return nil
}

func screeningRowMatches(schedule FrozenSchedule, index int, candidateID, role string, block int) bool {
	return schedule.CandidateOrder[index] == candidateID && schedule.RunRoles[index] == role &&
		schedule.DirectionOrder[index] == "hetz-to-mac" && schedule.BlockOrder[index] == block
}

func validateProductionSchedules(input ManifestInput, schedules []FrozenSchedule, stages map[string]FrozenSchedule) error {
	if err := requireExactStageOrder(schedules, "production", "fleet"); err != nil {
		return err
	}
	if err := validateThreePerDirection(stages["production"]); err != nil {
		return err
	}
	return validateFleetSchedule(stages["fleet"], nonPrimaryFleetHosts(input.FleetInventory))
}

func nonPrimaryFleetHosts(inventory []HostIdentity) map[string]bool {
	hosts := make(map[string]bool)
	for _, host := range inventory {
		if host.Role != HostRolePrimary {
			hosts[host.ID] = true
		}
	}
	return hosts
}

func validateFleetSchedule(fleet FrozenSchedule, wantHosts map[string]bool) error {
	if fleet.Repetitions != 3 || len(fleet.RunIDs) != len(wantHosts)*6 {
		return fmt.Errorf("fleet schedule must freeze three runs per direction for every non-primary host")
	}
	counts := make(map[string]int)
	for index, hostID := range fleet.HostOrder {
		counts[hostID+"\x00"+fleet.DirectionOrder[index]]++
	}
	for hostID := range wantHosts {
		if counts[hostID+"\x00hetz-to-mac"] != 3 || counts[hostID+"\x00mac-to-hetz"] != 3 {
			return fmt.Errorf("fleet schedule lacks exact rows for host %q", hostID)
		}
	}
	return nil
}

func validateSingleFileSchedule(schedules []FrozenSchedule, stages map[string]FrozenSchedule, stage string) error {
	if err := requireExactStageOrder(schedules, stage); err != nil {
		return err
	}
	return validateThreePerDirection(stages[stage])
}

func requireExactStageOrder(schedules []FrozenSchedule, expected ...string) error {
	if len(schedules) != len(expected) {
		return fmt.Errorf("schedule stage count = %d, want exactly %d", len(schedules), len(expected))
	}
	for index, stage := range expected {
		if schedules[index].Stage != stage {
			return fmt.Errorf("schedule stage %d = %q, want %q", index, schedules[index].Stage, stage)
		}
	}
	return nil
}

func validateCandidateDirectionMultiplicity(schedule FrozenSchedule, candidateIDs []string, repetitions int, bothDirections bool) error {
	wantRows := len(candidateIDs) * repetitions
	if bothDirections {
		wantRows *= 2
	}
	if len(schedule.RunIDs) != wantRows {
		return fmt.Errorf("schedule %q has %d rows, want %d", schedule.Stage, len(schedule.RunIDs), wantRows)
	}
	counts := make(map[string]int, wantRows)
	for index, candidateID := range schedule.CandidateOrder {
		counts[candidateID+"\x00"+schedule.DirectionOrder[index]]++
	}
	for _, candidateID := range candidateIDs {
		if bothDirections {
			for _, direction := range []string{"hetz-to-mac", "mac-to-hetz"} {
				if counts[candidateID+"\x00"+direction] != repetitions {
					return fmt.Errorf("schedule %q does not contain %d rows for candidate %q direction %q", schedule.Stage, repetitions, candidateID, direction)
				}
			}
			continue
		}
		if counts[candidateID+"\x00hetz-to-mac"] != repetitions || counts[candidateID+"\x00mac-to-hetz"] != 0 {
			return fmt.Errorf("schedule %q does not contain %d hetz-to-mac screening rows for candidate %q", schedule.Stage, repetitions, candidateID)
		}
	}
	return nil
}

func validateThreePerDirection(schedule FrozenSchedule) error {
	if schedule.Repetitions != 3 || len(schedule.RunIDs) != 6 || len(schedule.OfferedLoadMbps) != 0 {
		return fmt.Errorf("schedule %q must freeze exactly three file runs per direction", schedule.Stage)
	}
	counts := map[string]int{}
	for _, direction := range schedule.DirectionOrder {
		counts[direction]++
	}
	if counts["hetz-to-mac"] != 3 || counts["mac-to-hetz"] != 3 {
		return fmt.Errorf("schedule %q does not contain three runs per direction", schedule.Stage)
	}
	return nil
}

func validateCeilingSchedules(schedules []FrozenSchedule, stages map[string]FrozenSchedule, rules FrozenRules) error {
	expectedStages := []string{
		"ceiling-sweep-ascending-hetz-to-mac",
		"ceiling-sweep-descending-hetz-to-mac",
		"ceiling-sweep-ascending-mac-to-hetz",
		"ceiling-sweep-descending-mac-to-hetz",
		"ceiling-profile",
	}
	if err := requireExactStageOrder(schedules, expectedStages...); err != nil {
		return err
	}
	for _, stage := range expectedStages[:4] {
		if err := validateCeilingSweep(stages[stage]); err != nil {
			return err
		}
	}
	return validateCeilingProfile(stages["ceiling-profile"], rules.MinRepeatedCeilingProfiles)
}

func validateCeilingSweep(schedule FrozenSchedule) error {
	wantLoads := []float64{1200, 1500, 1800, 2100, 2400}
	if strings.Contains(schedule.Stage, "descending") {
		wantLoads = []float64{2400, 2100, 1800, 1500, 1200}
	}
	if !reflect.DeepEqual(schedule.OfferedLoadMbps, wantLoads) || schedule.Repetitions != 1 {
		return fmt.Errorf("schedule %q does not freeze exact ceiling sweep", schedule.Stage)
	}
	wantDirection := "hetz-to-mac"
	if strings.HasSuffix(schedule.Stage, "mac-to-hetz") {
		wantDirection = "mac-to-hetz"
	}
	for _, direction := range schedule.DirectionOrder {
		if direction != wantDirection {
			return fmt.Errorf("schedule %q contains wrong direction %q", schedule.Stage, direction)
		}
	}
	return nil
}

func validateCeilingProfile(profile FrozenSchedule, repetitions int) error {
	if len(profile.OfferedLoadMbps) != 0 || profile.Repetitions != repetitions {
		return fmt.Errorf("ceiling profile schedule does not freeze required repetitions")
	}
	counts := map[string]int{}
	for _, direction := range profile.DirectionOrder {
		counts[direction]++
	}
	if counts["hetz-to-mac"] != repetitions || counts["mac-to-hetz"] != repetitions || len(profile.RunIDs) != 2*repetitions {
		return fmt.Errorf("ceiling profile schedule must contain exactly two profiles per direction")
	}
	return nil
}

func validateProductionEnvironment(environment map[string]string) error {
	if len(environment) != 1 || environment["DERPHOLE_TRANSFER_TRACE_CSV"] != "trace.csv" {
		return fmt.Errorf("child-process environment must be exactly DERPHOLE_TRANSFER_TRACE_CSV=trace.csv")
	}
	return nil
}

func validateFleetInventory(inventory []HostIdentity, remotePublicIPv4 string) error {
	if len(inventory) < 4 {
		return fmt.Errorf("fleet inventory has %d hosts, want primary, at least two fleet hosts, and watchdog", len(inventory))
	}
	state := fleetValidationState{
		ids:           make(map[string]struct{}, len(inventory)),
		sshIdentities: make(map[string]struct{}, len(inventory)),
	}
	for index, host := range inventory {
		if err := state.add(host); err != nil {
			return err
		}
		if err := validateFleetRolePosition(host, index, len(inventory), remotePublicIPv4); err != nil {
			return err
		}
	}
	if state.primaryCount != 1 || state.fleetCount < 2 || state.watchdogCount != 1 {
		return fmt.Errorf("fleet inventory roles require one primary, at least two fleet hosts, and one watchdog")
	}
	return nil
}

type fleetValidationState struct {
	ids           map[string]struct{}
	sshIdentities map[string]struct{}
	primaryCount  int
	fleetCount    int
	watchdogCount int
}

func (state *fleetValidationState) add(host HostIdentity) error {
	if err := state.addUniqueIdentity(host); err != nil {
		return err
	}
	if err := validatePublicIPv4(host.PublicIPv4); err != nil {
		return fmt.Errorf("fleet host %q public IPv4: %w", host.ID, err)
	}
	return state.addRole(host)
}

func (state *fleetValidationState) addUniqueIdentity(host HostIdentity) error {
	if !validIdentifier(host.ID) {
		return fmt.Errorf("fleet host has unsafe ID %q", host.ID)
	}
	if _, exists := state.ids[host.ID]; exists {
		return fmt.Errorf("duplicate fleet host ID %q", host.ID)
	}
	state.ids[host.ID] = struct{}{}
	if !validSSHIdentity(host.SSH) {
		return fmt.Errorf("fleet host %q has invalid SSH identity", host.ID)
	}
	if _, exists := state.sshIdentities[host.SSH]; exists {
		return fmt.Errorf("duplicate fleet SSH identity %q", host.SSH)
	}
	state.sshIdentities[host.SSH] = struct{}{}
	return nil
}

func (state *fleetValidationState) addRole(host HostIdentity) error {
	switch host.Role {
	case HostRolePrimary:
		state.primaryCount++
	case HostRoleFleet:
		state.fleetCount++
	case HostRoleWatchdog:
		state.watchdogCount++
	default:
		return fmt.Errorf("fleet host %q has invalid role %q", host.ID, host.Role)
	}
	if host.EricWatchdog != (host.Role == HostRoleWatchdog) {
		return fmt.Errorf("fleet host %q watchdog flag does not match role", host.ID)
	}
	return nil
}

func validateFleetRolePosition(host HostIdentity, index, count int, remotePublicIPv4 string) error {
	if index == 0 && (host.Role != HostRolePrimary || host.PublicIPv4 != remotePublicIPv4) {
		return fmt.Errorf("first fleet host must be primary at remote public IPv4 %s", remotePublicIPv4)
	}
	if index != 0 && host.Role == HostRolePrimary {
		return fmt.Errorf("primary fleet host must be first")
	}
	if index == count-1 && host.Role != HostRoleWatchdog {
		return fmt.Errorf("last fleet host must be watchdog")
	}
	if index != count-1 && host.Role == HostRoleWatchdog {
		return fmt.Errorf("watchdog fleet host must be last")
	}
	return nil
}

func validSSHIdentity(value string) bool {
	if len(value) == 0 || len(value) > 257 || value[0] == '-' || containsControl(value) || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	user, host, found := strings.Cut(value, "@")
	return found && !strings.Contains(host, "@") && validIdentifier(user) && validIdentifier(host)
}

func validateBaselineHealth(input ManifestInput) error {
	if err := validateBaselineCounters(input.BaselineHealthCounters); err != nil {
		return err
	}
	if err := validateBaselineHealthIdentity(input); err != nil {
		return err
	}
	return validateBaselineHealthRecordDigest(input)
}

func validateBaselineCounters(counters map[string]uint64) error {
	if len(counters) != len(baselineHealthCounterKeys) {
		return fmt.Errorf("baseline health counter count = %d, want %d", len(counters), len(baselineHealthCounterKeys))
	}
	for _, key := range baselineHealthCounterKeys {
		if _, exists := counters[key]; !exists {
			return fmt.Errorf("baseline health counters are missing %q", key)
		}
	}
	if counters["uptime_seconds"] == 0 || counters["available_memory_bytes"] == 0 || counters["disk_free_bytes"] == 0 {
		return fmt.Errorf("baseline health uptime, available memory, and disk free gauges must be positive")
	}
	if counters["online_cpus"] != 2 {
		return fmt.Errorf("baseline health online CPUs = %d, want 2", counters["online_cpus"])
	}
	return nil
}

var baselineHealthCounterKeys = [...]string{
	"uptime_seconds",
	"online_cpus",
	"global_oom_kills",
	"cgroup_oom_kills",
	"available_memory_bytes",
	"swap_used_bytes",
	"disk_free_bytes",
	"kernel_error_count",
	"interface_drops",
	"udp_errors",
	"softnet_drops",
	"process_count",
	"socket_count",
}

func validateBaselineHealthIdentity(input ManifestInput) error {
	identity := input.BaselineHealthIdentity
	wantRole := "baseline-" + string(input.Kind)
	if err := validateArtifactRef(identity.Artifact, wantRole); err != nil {
		return fmt.Errorf("baseline health artifact: %w", err)
	}
	if wantPath := "baselines/" + string(input.Kind) + ".json"; identity.Artifact.Path != wantPath {
		return fmt.Errorf("baseline health artifact path = %q, want %q", identity.Artifact.Path, wantPath)
	}
	if _, err := parseCanonicalUTCTime(identity.CapturedAtUTC); err != nil {
		return fmt.Errorf("baseline health capture time: %w", err)
	}
	if identity.Sequence == 0 {
		return fmt.Errorf("baseline health capture sequence must be positive")
	}
	if len(input.FleetInventory) == 0 || identity.HostID != input.FleetInventory[0].ID || input.FleetInventory[0].Role != HostRolePrimary {
		return fmt.Errorf("baseline health host %q does not bind the primary remote fleet host", identity.HostID)
	}
	if identity.BootID != input.RemoteBootID {
		return fmt.Errorf("baseline health boot ID does not bind the remote boot ID")
	}
	return nil
}

func parseCanonicalUTCTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("%q is not canonical RFC3339 UTC", value)
	}
	return parsed, nil
}

func validateBaselineHealthRecordDigest(input ManifestInput) error {
	record := baselineHealthRecord(input)
	data, err := canonicalJSONBytes(record)
	if err != nil {
		return fmt.Errorf("marshal baseline health record: %w", err)
	}
	if got, want := DigestBytes(data), input.BaselineHealthIdentity.Artifact.SHA256; got != want {
		return fmt.Errorf("baseline health artifact digest %s does not bind canonical record %s", want, got)
	}
	return nil
}

func baselineHealthRecord(input ManifestInput) BaselineHealthRecord {
	identity := input.BaselineHealthIdentity
	counters := make(map[string]uint64, len(input.BaselineHealthCounters))
	for key, value := range input.BaselineHealthCounters {
		counters[key] = value
	}
	return BaselineHealthRecord{
		SchemaVersion: baselineHealthRecordSchemaVersion,
		Kind:          input.Kind,
		CapturedAtUTC: identity.CapturedAtUTC,
		Sequence:      identity.Sequence,
		HostID:        identity.HostID,
		BootID:        identity.BootID,
		Counters:      counters,
	}
}

func validateStageReferences(kind ManifestKind, parent *ArtifactRef, decisions []ArtifactRef) error {
	if kind == ManifestExperiment {
		return validateExperimentReferences(parent, decisions)
	}
	if parent == nil {
		return fmt.Errorf("%s manifest is missing parent manifest", kind)
	}
	if err := validateArtifactRef(*parent, "manifest"); err != nil {
		return fmt.Errorf("parent manifest: %w", err)
	}
	wantParentPath, wantRoles := stageReferenceContract(kind)
	if parent.Path != wantParentPath {
		return fmt.Errorf("%s parent manifest path = %q, want %q", kind, parent.Path, wantParentPath)
	}
	return validateDecisionReferences(kind, parent.Path, decisions, wantRoles)
}

func validateExperimentReferences(parent *ArtifactRef, decisions []ArtifactRef) error {
	if parent != nil || len(decisions) != 0 {
		return fmt.Errorf("experiment manifest must be an ancestry root")
	}
	return nil
}

func stageReferenceContract(kind ManifestKind) (string, map[string]struct{}) {
	roles := make(map[string]struct{})
	switch kind {
	case ManifestProduction:
		roles["finalist"] = struct{}{}
		return "manifest.json", roles
	case ManifestAcceptance:
		roles["prerequisite"] = struct{}{}
		roles["fleet"] = struct{}{}
	case ManifestCeiling:
		roles["peak"] = struct{}{}
		roles["fleet"] = struct{}{}
	}
	return "production-manifest.json", roles
}

func validateDecisionReferences(kind ManifestKind, parentPath string, decisions []ArtifactRef, wantRoles map[string]struct{}) error {
	if len(decisions) != len(wantRoles) {
		return fmt.Errorf("%s decision reference count = %d, want %d", kind, len(decisions), len(wantRoles))
	}
	seen := make(map[string]struct{}, len(decisions))
	seenPaths := map[string]struct{}{parentPath: {}}
	for _, decision := range decisions {
		if _, expected := wantRoles[decision.Role]; !expected {
			return fmt.Errorf("%s manifest has unexpected or anonymous decision role %q", kind, decision.Role)
		}
		if _, duplicate := seen[decision.Role]; duplicate {
			return fmt.Errorf("%s manifest has duplicate decision role %q", kind, decision.Role)
		}
		seen[decision.Role] = struct{}{}
		if err := validateArtifactRef(decision, decision.Role); err != nil {
			return fmt.Errorf("%s decision reference: %w", decision.Role, err)
		}
		if wantPath := "decisions/" + decision.Role + ".json"; decision.Path != wantPath {
			return fmt.Errorf("%s decision path = %q, want %q", decision.Role, decision.Path, wantPath)
		}
		if _, duplicate := seenPaths[decision.Path]; duplicate {
			return fmt.Errorf("duplicate artifact path %q", decision.Path)
		}
		seenPaths[decision.Path] = struct{}{}
	}
	return nil
}

func validateArtifactRef(ref ArtifactRef, wantRole string) error {
	if ref.Role != wantRole {
		return fmt.Errorf("role = %q, want %q", ref.Role, wantRole)
	}
	if strings.TrimSpace(ref.Path) == "" || path.Clean(ref.Path) == "." {
		return fmt.Errorf("artifact path is empty")
	}
	if !validArtifactPath(ref.Path) {
		return fmt.Errorf("artifact path %q is not a clean scoped relative path", ref.Path)
	}
	if err := validateSHA256Digest(ref.SHA256); err != nil {
		return err
	}
	return nil
}

func validArtifactPath(value string) bool {
	return !filepath.IsAbs(value) && !path.IsAbs(value) && path.Clean(value) == value &&
		!strings.Contains(value, `\`) && value != ".." && !strings.HasPrefix(value, "../")
}

func validateStageTransition(parent, child ManifestKind) error {
	valid := parent == ManifestExperiment && child == ManifestProduction ||
		parent == ManifestProduction && (child == ManifestAcceptance || child == ManifestCeiling)
	if !valid {
		return fmt.Errorf("invalid manifest stage transition %s -> %s", parent, child)
	}
	return nil
}

func verifyStableTransitionIdentity(parent, child ManifestInput) error {
	if !sameEndpointIdentity(parent, child) {
		return fmt.Errorf("child substituted endpoint or exact Hetzner identity")
	}
	if parent.Rules != child.Rules {
		return fmt.Errorf("child substituted frozen rules")
	}
	if !reflect.DeepEqual(parent.ProductionEnvironment, child.ProductionEnvironment) {
		return fmt.Errorf("child substituted production environment")
	}
	if !reflect.DeepEqual(parent.FleetInventory, child.FleetInventory) {
		return fmt.Errorf("child substituted canonical fleet inventory")
	}
	if parent.CapacityTCPPort != child.CapacityTCPPort {
		return fmt.Errorf("child substituted capacity control identity")
	}
	return nil
}

func verifyFreshBaselineHealthIdentity(parent, child ManifestInput) error {
	parentTime, err := parseCanonicalUTCTime(parent.BaselineHealthIdentity.CapturedAtUTC)
	if err != nil {
		return fmt.Errorf("invalid parent baseline health capture time: %w", err)
	}
	childTime, err := parseCanonicalUTCTime(child.BaselineHealthIdentity.CapturedAtUTC)
	if err != nil {
		return fmt.Errorf("invalid child baseline health capture time: %w", err)
	}
	if !childTime.After(parentTime) {
		return fmt.Errorf("child baseline health capture is not later than parent")
	}
	if child.BaselineHealthIdentity.Sequence <= parent.BaselineHealthIdentity.Sequence {
		return fmt.Errorf("child baseline health sequence did not advance")
	}
	if child.BaselineHealthIdentity.Artifact.SHA256 == parent.BaselineHealthIdentity.Artifact.SHA256 {
		return fmt.Errorf("child baseline health capture reused parent artifact identity")
	}
	return nil
}

func sameEndpointIdentity(left, right ManifestInput) bool {
	return left.LocalPublicIPv4 == right.LocalPublicIPv4 &&
		left.RemotePublicIPv4 == right.RemotePublicIPv4 &&
		left.RemoteKernel == right.RemoteKernel &&
		left.RemoteArch == right.RemoteArch &&
		left.RemoteBootID == right.RemoteBootID &&
		left.RemoteOnlineCPUs == right.RemoteOnlineCPUs
}

func verifyProductionTransition(parent, child ManifestInput) error {
	if child.Payload == parent.Payload {
		return fmt.Errorf("production manifest reused experiment payload")
	}
	candidate := child.Candidates[0]
	for _, prior := range parent.Candidates {
		if candidate.Commit == prior.Commit {
			return fmt.Errorf("production candidate did not bind a newly committed source default")
		}
		if candidate.Darwin.SHA256 == prior.Darwin.SHA256 || candidate.Linux.SHA256 == prior.Linux.SHA256 {
			return fmt.Errorf("production candidate reused an experiment binary")
		}
	}
	return nil
}

func verifyAcceptanceTransition(parent, child ManifestInput) error {
	if child.Payload == parent.Payload {
		return fmt.Errorf("acceptance manifest reused production payload")
	}
	if !reflect.DeepEqual(parent.Candidates, child.Candidates) {
		return fmt.Errorf("acceptance manifest substituted production candidate or binary identity")
	}
	return nil
}

func verifyCeilingTransition(parent, child ManifestInput) error {
	if child.Payload != parent.Payload {
		return fmt.Errorf("ceiling manifest substituted production payload identity")
	}
	diagnostic := child.Candidates[0]
	for _, production := range parent.Candidates {
		if diagnostic.Darwin.SHA256 == production.Darwin.SHA256 || diagnostic.Linux.SHA256 == production.Linux.SHA256 {
			return fmt.Errorf("ceiling manifest did not bind a distinct diagnostic binary pair")
		}
	}
	return nil
}

func cloneManifestInputValue(input ManifestInput) ManifestInput {
	cloned := input
	if input.ParentManifest != nil {
		parent := *input.ParentManifest
		cloned.ParentManifest = &parent
	}
	cloned.ParentDecisionRefs = append([]ArtifactRef(nil), input.ParentDecisionRefs...)
	cloned.Candidates = append([]CandidateIdentity(nil), input.Candidates...)
	for index := range cloned.Candidates {
		cloned.Candidates[index].Config = cloneStringMap(input.Candidates[index].Config)
	}
	cloned.Schedules = append([]FrozenSchedule(nil), input.Schedules...)
	for index := range cloned.Schedules {
		cloned.Schedules[index].RunIDs = append([]string(nil), input.Schedules[index].RunIDs...)
		cloned.Schedules[index].CandidateOrder = append([]string(nil), input.Schedules[index].CandidateOrder...)
		cloned.Schedules[index].HostOrder = append([]string(nil), input.Schedules[index].HostOrder...)
		cloned.Schedules[index].DirectionOrder = append([]string(nil), input.Schedules[index].DirectionOrder...)
		cloned.Schedules[index].BlockOrder = append([]int(nil), input.Schedules[index].BlockOrder...)
		cloned.Schedules[index].RunRoles = append([]string(nil), input.Schedules[index].RunRoles...)
		cloned.Schedules[index].OfferedLoadMbps = append([]float64(nil), input.Schedules[index].OfferedLoadMbps...)
	}
	cloned.ProductionEnvironment = cloneStringMap(input.ProductionEnvironment)
	cloned.FleetInventory = append([]HostIdentity(nil), input.FleetInventory...)
	if input.BaselineHealthCounters != nil {
		cloned.BaselineHealthCounters = make(map[string]uint64, len(input.BaselineHealthCounters))
		for key, value := range input.BaselineHealthCounters {
			cloned.BaselineHealthCounters[key] = value
		}
	}
	return cloned
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func validCommit(value string) bool {
	return (len(value) == 40 || len(value) == 64) && isLowerHex(value)
}

func validBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	return isLowerHex(strings.ReplaceAll(value, "-", ""))
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return value != ""
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || !isASCIIAlphanumeric(rune(value[0])) {
		return false
	}
	for _, character := range value {
		if !validIdentifierCharacter(character) {
			return false
		}
	}
	return true
}

func isASCIIAlphanumeric(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func validIdentifierCharacter(character rune) bool {
	if character >= 'a' && character <= 'z' {
		return true
	}
	if character >= 'A' && character <= 'Z' {
		return true
	}
	if character >= '0' && character <= '9' {
		return true
	}
	return character == '-' || character == '_' || character == '.'
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
