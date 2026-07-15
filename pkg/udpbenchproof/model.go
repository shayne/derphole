// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

// Direction is one endpoint-relative transfer direction.
type Direction string

const (
	DirectionLocalToRemote Direction = "local-to-remote"
	DirectionRemoteToLocal Direction = "remote-to-local"
)

// Stage is one mechanical proof-decision stage.
type Stage string

const (
	StageScreening     Stage = "screening"
	StagePreliminary   Stage = "preliminary"
	StageFinalist      Stage = "finalist"
	StageFinalistRerun Stage = "finalist-rerun"
	StageProduction    Stage = "production"
	StageFleet         Stage = "fleet"
	StageCeiling       Stage = "ceiling"
	StageAcceptance    Stage = "acceptance"
)

const decisionSchemaVersion = 1

// BinarySet binds the two platform binaries used by a sample or decision.
type BinarySet struct {
	Darwin BinaryIdentity `json:"darwin"`
	Linux  BinaryIdentity `json:"linux"`
}

// ScheduledRun identifies one nonreplaceable scheduled attempt.
type ScheduledRun struct {
	ID               string      `json:"id"`
	Stage            Stage       `json:"stage"`
	CandidateID      string      `json:"candidate_id"`
	HostID           string      `json:"host_id"`
	Direction        Direction   `json:"direction"`
	SizeBytes        int64       `json:"size_bytes"`
	Order            int         `json:"order"`
	CapacityRequired bool        `json:"capacity_required"`
	Block            int         `json:"block"`
	Schedule         string      `json:"schedule"`
	Role             string      `json:"role"`
	PriorDecisionRef ArtifactRef `json:"prior_decision_ref"`
}

// PayloadEvidence binds independent source hash, sink hash, and sink size reports.
type PayloadEvidence struct {
	SourceHashArtifact ArtifactRef  `json:"source_hash_artifact"`
	SinkHashArtifact   ArtifactRef  `json:"sink_hash_artifact"`
	SinkSizeArtifact   ArtifactRef  `json:"sink_size_artifact"`
	SourceSHA256       SHA256Digest `json:"source_sha256"`
	SinkSHA256         SHA256Digest `json:"sink_sha256"`
	SourceSHAReports   int          `json:"source_sha_reports"`
	SinkSHAReports     int          `json:"sink_sha_reports"`
	SinkSizeBytes      int64        `json:"sink_size_bytes"`
}

// CapacityEvidence describes the immediately preceding same-direction control.
type CapacityEvidence struct {
	Artifact  ArtifactRef `json:"artifact"`
	Direction Direction   `json:"direction"`
	Mbps      float64     `json:"mbps"`
	Valid     bool        `json:"valid"`
}

// TraceEvidence binds the paired selected-engine trace verdicts.
type TraceEvidence struct {
	Sender      ArtifactRef `json:"sender"`
	Receiver    ArtifactRef `json:"receiver"`
	Engine      string      `json:"engine"`
	PublicUDP   bool        `json:"public_udp"`
	StrictValid bool        `json:"strict_valid"`
}

// ResourceEvidence binds sender and receiver resource observations.
type ResourceEvidence struct {
	Sender                ArtifactRef `json:"sender"`
	Receiver              ArtifactRef `json:"receiver"`
	SenderUserSeconds     float64     `json:"sender_user_seconds"`
	SenderSystemSeconds   float64     `json:"sender_system_seconds"`
	ReceiverUserSeconds   float64     `json:"receiver_user_seconds"`
	ReceiverSystemSeconds float64     `json:"receiver_system_seconds"`
}

// HealthEvidence binds the before/after health captures.
type HealthEvidence struct {
	Before  ArtifactRef `json:"before"`
	After   ArtifactRef `json:"after"`
	Healthy bool        `json:"healthy"`
}

// CleanupEvidence binds the scoped cleanup verdict.
type CleanupEvidence struct {
	Artifact          ArtifactRef `json:"artifact"`
	ScopedRootRemoved bool        `json:"scoped_root_removed"`
	ProcessesRemoved  bool        `json:"processes_removed"`
	SocketsRemoved    bool        `json:"sockets_removed"`
	PayloadsRemoved   bool        `json:"payloads_removed"`
}

// Sample is the complete normalized result of one scheduled run.
type Sample struct {
	SchemaVersion    int              `json:"schema_version"`
	ManifestSHA256   SHA256Digest     `json:"manifest_sha256"`
	CandidateID      string           `json:"candidate_id"`
	BinarySet        BinarySet        `json:"binary_set"`
	Run              ScheduledRun     `json:"run"`
	Payload          PayloadEvidence  `json:"payload"`
	Capacity         CapacityEvidence `json:"capacity"`
	Trace            TraceEvidence    `json:"trace"`
	Resource         ResourceEvidence `json:"resource"`
	Health           HealthEvidence   `json:"health"`
	Cleanup          CleanupEvidence  `json:"cleanup"`
	ReceiverResult   ArtifactRef      `json:"receiver_result"`
	MechanismResult  ArtifactRef      `json:"mechanism_result"`
	ObservedAtUTC    string           `json:"observed_at_utc"`
	GoodputMbps      float64          `json:"goodput_mbps"`
	WallGoodputMbps  float64          `json:"wall_goodput_mbps"`
	RecoveryRatio    float64          `json:"recovery_ratio"`
	ScanPerPacket    float64          `json:"scan_per_packet"`
	FlatlineSeconds  float64          `json:"flatline_seconds"`
	Started          bool             `json:"started"`
	Artifact         ArtifactRef      `json:"-"`
	EvidenceRoot     string           `json:"-"`
	artifactVerified bool
}

// SampleVerdict is the fail-closed status of one sample.
type SampleVerdict struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// MaterialEdge records that From mechanically beats To.
type MaterialEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Statistics is one deterministic numeric summary.
type Statistics struct {
	Count                  int     `json:"count"`
	Mean                   float64 `json:"mean"`
	Median                 float64 `json:"median"`
	Minimum                float64 `json:"minimum"`
	Maximum                float64 `json:"maximum"`
	PopulationStdDev       float64 `json:"population_stddev"`
	CoefficientOfVariation float64 `json:"coefficient_of_variation"`
	BootstrapLow           float64 `json:"bootstrap_low"`
	BootstrapHigh          float64 `json:"bootstrap_high"`
}

// DirectionStatistics summarizes raw, normalized, capacity, and paired outcomes.
type DirectionStatistics struct {
	Direction          Direction  `json:"direction"`
	Raw                Statistics `json:"raw"`
	Normalized         Statistics `json:"normalized"`
	Capacity           Statistics `json:"capacity"`
	NearestTimeWins    int        `json:"nearest_time_wins"`
	NearestTimeMatches int        `json:"nearest_time_matches"`
}

// CandidateStatistics supplies deterministic winner-ranking values.
type CandidateStatistics struct {
	CandidateID          string                `json:"candidate_id"`
	Directions           []DirectionStatistics `json:"directions"`
	RawBottleneck        float64               `json:"raw_bottleneck"`
	NormalizedBottleneck float64               `json:"normalized_bottleneck"`
	MaxHetzCPUPerGiB     float64               `json:"max_hetz_cpu_per_gib"`
	RecoveryRatio        float64               `json:"recovery_ratio"`
	WallGoodputMbps      float64               `json:"wall_goodput_mbps"`
}

// Decision is one deterministic stage outcome.
type Decision struct {
	SchemaVersion      int                   `json:"schema_version"`
	ManifestSHA256     SHA256Digest          `json:"manifest_sha256"`
	Stage              Stage                 `json:"stage"`
	Passed             bool                  `json:"passed"`
	AcceptanceMet      bool                  `json:"acceptance_met"`
	SelectedCandidate  string                `json:"selected_candidate"`
	PeakFrontier       []string              `json:"peak_frontier"`
	FinalistCandidates []string              `json:"finalist_candidates"`
	Reasons            []string              `json:"reasons"`
	BinarySet          BinarySet             `json:"binary_set"`
	InputDecisionRefs  []ArtifactRef         `json:"input_decision_refs"`
	SampleRefs         []ArtifactRef         `json:"sample_refs"`
	FleetProbeRefs     []ArtifactRef         `json:"fleet_probe_refs"`
	Statistics         []CandidateStatistics `json:"statistics"`
	MaterialEdges      []MaterialEdge        `json:"material_edges"`
	ClosedCandidates   []string              `json:"closed_candidates"`
	RerunRequired      bool                  `json:"rerun_required"`
	Artifact           ArtifactRef           `json:"-"`
	EvidenceRoot       string                `json:"-"`
}

// PrerequisiteDecision authorizes the 3 GiB child stage for exact binaries.
type PrerequisiteDecision struct {
	SchemaVersion     int           `json:"schema_version"`
	ManifestSHA256    SHA256Digest  `json:"manifest_sha256"`
	CandidateID       string        `json:"candidate_id"`
	BinarySet         BinarySet     `json:"binary_set"`
	InputDecisionRefs []ArtifactRef `json:"input_decision_refs"`
	Samples           []ArtifactRef `json:"samples"`
	Passed            bool          `json:"passed"`
	Reasons           []string      `json:"reasons"`
	Artifact          ArtifactRef   `json:"-"`
	EvidenceRoot      string        `json:"-"`
}

// CeilingSweepPoint is one immutable 1,400-byte offered-load result.
type CeilingSweepPoint struct {
	Artifact                ArtifactRef `json:"-"`
	RunID                   string      `json:"run_id"`
	HostID                  string      `json:"host_id"`
	CandidateID             string      `json:"candidate_id"`
	BinarySet               BinarySet   `json:"binary_set"`
	Direction               Direction   `json:"direction"`
	Order                   string      `json:"order"`
	Sequence                int         `json:"sequence"`
	ObservedAtUTC           string      `json:"observed_at_utc"`
	OfferedGbps             float64     `json:"offered_gbps"`
	DeliveredGbps           float64     `json:"delivered_gbps"`
	LossRatio               float64     `json:"loss_ratio"`
	QueuePressure           float64     `json:"queue_pressure"`
	CapacityMbps            float64     `json:"capacity_mbps"`
	CapacityTCPPort         int         `json:"capacity_tcp_port"`
	CapacityParallelFlows   int         `json:"capacity_parallel_flows"`
	CapacityDurationSeconds int         `json:"capacity_duration_seconds"`
	DatagramBytes           int         `json:"datagram_bytes"`
	PublicUDP               bool        `json:"public_udp"`
	Healthy                 bool        `json:"healthy"`
	CounterFamilies         []string    `json:"counter_families"`
	Capacity                ArtifactRef `json:"capacity"`
	CapacityAfter           ArtifactRef `json:"capacity_after"`
	UDPResult               ArtifactRef `json:"udp_result"`
	Health                  ArtifactRef `json:"health"`
}

// CeilingProfile is one independent plateau profile.
type CeilingProfile struct {
	RunID                      string      `json:"run_id"`
	HostID                     string      `json:"host_id"`
	CandidateID                string      `json:"candidate_id"`
	BinarySet                  BinarySet   `json:"binary_set"`
	ObservedAtUTC              string      `json:"observed_at_utc"`
	Direction                  Direction   `json:"direction"`
	OfferedGbps                float64     `json:"offered_gbps"`
	SweepPoint                 ArtifactRef `json:"sweep_point"`
	Artifact                   ArtifactRef `json:"artifact"`
	HetzCPUUtilization         float64     `json:"hetz_cpu_utilization"`
	KernelPacketCPUUtilization float64     `json:"kernel_packet_cpu_utilization"`
	LimitingMechanism          string      `json:"limiting_mechanism"`
	Independent                bool        `json:"independent"`
	CounterFamilies            []string    `json:"counter_families"`
}

// CeilingDecision proves a measured ceiling without redefining acceptance.
type CeilingDecision struct {
	SchemaVersion     int           `json:"schema_version"`
	ManifestSHA256    SHA256Digest  `json:"manifest_sha256"`
	InputDecisionRefs []ArtifactRef `json:"input_decision_refs"`
	SweepRefs         []ArtifactRef `json:"sweep_refs"`
	ProfileRefs       []ArtifactRef `json:"profile_refs"`
	WinnerSampleRefs  []ArtifactRef `json:"winner_sample_refs"`
	PlateauStartGbps  float64       `json:"plateau_start_gbps"`
	PlateauEndGbps    float64       `json:"plateau_end_gbps"`
	LimitingMechanism string        `json:"limiting_mechanism"`
	Passed            bool          `json:"passed"`
	AcceptanceMet     bool          `json:"acceptance_met"`
	Reasons           []string      `json:"reasons"`
}

// FleetInputs binds the verified prerequisite, probes, and frozen fleet samples.
type FleetInputs struct {
	Manifest        Manifest
	ManifestRef     ArtifactRef
	Prerequisite    PrerequisiteDecision
	PrerequisiteRef ArtifactRef
	ProbeRefs       []ArtifactRef
	Samples         []Sample
	EvidenceRoot    string
}

// AcceptanceInputs binds the exact child manifest and prior decisions.
type AcceptanceInputs struct {
	Manifest        Manifest             `json:"manifest"`
	ManifestRef     ArtifactRef          `json:"manifest_ref"`
	Prerequisite    PrerequisiteDecision `json:"prerequisite"`
	PrerequisiteRef ArtifactRef          `json:"prerequisite_ref"`
	Fleet           Decision             `json:"fleet"`
	FleetRef        ArtifactRef          `json:"fleet_ref"`
	Samples         []Sample             `json:"samples"`
}

// ScheduleAuthorization carries the exact stage-specific proof set. Peak is
// the generic experiment decision used by preliminary/finalist/production;
// fleet and child schedules additionally require their typed proofs.
type ScheduleAuthorization struct {
	Peak         Decision
	Prerequisite PrerequisiteDecision
	Fleet        Decision
}
