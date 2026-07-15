// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	oneGiB   = int64(1024 * 1024 * 1024)
	threeGiB = int64(3 * 1024 * 1024 * 1024)
)

func TestNewManifestAcceptsFrozenExperiment(t *testing.T) {
	t.Parallel()

	manifest, err := NewManifest(validExperimentInput())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", manifest.SchemaVersion)
	}
	if err := ValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
}

func TestNewManifestRejectsUnfrozenSchedule(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"missing schedules": func(input *ManifestInput) { input.Schedules = nil },
		"missing run IDs": func(input *ManifestInput) {
			input.Schedules[0].RunIDs = nil
		},
		"unknown candidate": func(input *ManifestInput) {
			input.Schedules[0].CandidateOrder[0] = "unknown"
		},
		"missing direction order": func(input *ManifestInput) {
			input.Schedules[0].DirectionOrder = nil
		},
		"unequal order lengths": func(input *ManifestInput) {
			input.Schedules[0].DirectionOrder = input.Schedules[0].DirectionOrder[:1]
		},
		"unknown direction": func(input *ManifestInput) {
			input.Schedules[0].DirectionOrder[0] = "sideways"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("unfrozen schedule accepted")
			}
		})
	}
}

func TestManifestRejectsDuplicateCandidateAndScheduleIdentities(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"candidate ID": func(input *ManifestInput) {
			input.Candidates[1].ID = input.Candidates[0].ID
		},
		"candidate configuration": func(input *ManifestInput) {
			input.Candidates[1].Config = input.Candidates[0].Config
		},
		"schedule stage": func(input *ManifestInput) {
			input.Schedules[1].Stage = input.Schedules[0].Stage
		},
		"run ID": func(input *ManifestInput) {
			input.Schedules[1].RunIDs[0] = input.Schedules[0].RunIDs[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("duplicate identity accepted")
			}
		})
	}
}

func TestManifestAllowsSharedBuildIdentityAcrossDistinctCandidateConfigs(t *testing.T) {
	t.Parallel()

	input := cloneManifestInput(t, validExperimentInput())
	input.Candidates[1].Commit = input.Candidates[0].Commit
	input.Candidates[1].Darwin = input.Candidates[0].Darwin
	input.Candidates[1].Linux = input.Candidates[0].Linux
	if _, err := NewManifest(input); err != nil {
		t.Fatalf("linker/config candidates sharing one build identity were rejected: %v", err)
	}
}

func TestManifestRequiresExactCandidateConfigForEveryStage(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	tests := map[string]ManifestInput{
		"experiment mismatched candidate": func() ManifestInput {
			input := cloneManifestInput(t, validExperimentInput())
			input.Candidates[0].Config = map[string]string{"candidate": "not-control"}
			return input
		}(),
		"experiment extra config": func() ManifestInput {
			input := cloneManifestInput(t, validExperimentInput())
			input.Candidates[0].Config["mode"] = "source-default"
			return input
		}(),
		"production linker config": func() ManifestInput {
			input := cloneManifestInput(t, validProductionInput(t, experiment))
			input.Candidates[0].Config = map[string]string{"candidate": "challenger"}
			return input
		}(),
		"acceptance benchmark config": func() ManifestInput {
			input := cloneManifestInput(t, validAcceptanceInput(t, production))
			input.Candidates[0].Config = map[string]string{"mode": "benchmark"}
			return input
		}(),
		"ceiling source default": func() ManifestInput {
			input := cloneManifestInput(t, validCeilingInput(t, production))
			input.Candidates[0].Config = map[string]string{"mode": "source-default"}
			return input
		}(),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewManifest(input); err == nil {
				t.Fatal("noncanonical stage candidate configuration accepted")
			}
		})
	}
}

func TestManifestRejectsNonPublicEndpoints(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"private":           func(input *ManifestInput) { input.LocalPublicIPv4 = "10.0.0.1" },
		"tailscale CGNAT":   func(input *ManifestInput) { input.RemotePublicIPv4 = "100.100.10.20" },
		"loopback":          func(input *ManifestInput) { input.LocalPublicIPv4 = "127.0.0.1" },
		"link local":        func(input *ManifestInput) { input.RemotePublicIPv4 = "169.254.2.3" },
		"documentation 192": func(input *ManifestInput) { input.LocalPublicIPv4 = "192.0.2.1" },
		"documentation 198": func(input *ManifestInput) { input.LocalPublicIPv4 = "198.51.100.1" },
		"documentation 203": func(input *ManifestInput) { input.RemotePublicIPv4 = "203.0.113.1" },
		"benchmark range":   func(input *ManifestInput) { input.RemotePublicIPv4 = "198.18.0.1" },
		"as112 v4 prefix":   func(input *ManifestInput) { input.RemotePublicIPv4 = "192.31.196.1" },
		"amt prefix":        func(input *ManifestInput) { input.RemotePublicIPv4 = "192.52.193.1" },
		"direct delegation": func(input *ManifestInput) { input.RemotePublicIPv4 = "192.175.48.1" },
		"reserved":          func(input *ManifestInput) { input.RemotePublicIPv4 = "240.0.0.1" },
		"IPv6":              func(input *ManifestInput) { input.LocalPublicIPv4 = "2001:db8::1" },
		"same endpoints":    func(input *ManifestInput) { input.LocalPublicIPv4 = input.RemotePublicIPv4 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
		})
	}
}

func TestForbiddenPublicProofPrefixesExplicitlyDenyGlobalSpecialRanges(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"192.31.196.0/24", "192.52.193.0/24", "192.175.48.0/24"} {
		want := netip.MustParsePrefix(value)
		found := false
		for _, prefix := range forbiddenPublicProofPrefixes {
			found = found || prefix == want
		}
		if !found {
			t.Errorf("forbidden prefix table omits %s", want)
		}
	}
}

func TestManifestRequiresLinuxAMD64RemoteArchitecture(t *testing.T) {
	t.Parallel()

	for _, architecture := range []string{"arm64", "amd64", "x86-64", "garbage"} {
		t.Run(architecture, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			input.RemoteArch = architecture
			if _, err := NewManifest(input); err == nil {
				t.Fatalf("remote architecture %q accepted", architecture)
			}
		})
	}
}

func TestManifestRequiresExactHetznerCPUs(t *testing.T) {
	t.Parallel()

	for _, cpus := range []int{-1, 0, 1, 3, 4} {
		t.Run(string(rune('a'+cpus+1)), func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			input.RemoteOnlineCPUs = cpus
			if _, err := NewManifest(input); err == nil {
				t.Fatalf("RemoteOnlineCPUs=%d accepted", cpus)
			}
		})
	}
}

func TestManifestRequiresExactTraceOnlyProductionEnvironment(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"nil":               func(input *ManifestInput) { input.ProductionEnvironment = nil },
		"missing trace":     func(input *ManifestInput) { input.ProductionEnvironment = map[string]string{} },
		"wrong trace value": func(input *ManifestInput) { input.ProductionEnvironment["DERPHOLE_TRANSFER_TRACE_CSV"] = "other.csv" },
		"absolute trace": func(input *ManifestInput) {
			input.ProductionEnvironment["DERPHOLE_TRANSFER_TRACE_CSV"] = "/tmp/trace.csv"
		},
		"traversing trace": func(input *ManifestInput) {
			input.ProductionEnvironment["DERPHOLE_TRANSFER_TRACE_CSV"] = "../trace.csv"
		},
		"empty trace":       func(input *ManifestInput) { input.ProductionEnvironment["DERPHOLE_TRANSFER_TRACE_CSV"] = "" },
		"GOGC":              func(input *ManifestInput) { input.ProductionEnvironment["GOGC"] = "off" },
		"GOMEMLIMIT":        func(input *ManifestInput) { input.ProductionEnvironment["GOMEMLIMIT"] = "1GiB" },
		"GOMAXPROCS":        func(input *ManifestInput) { input.ProductionEnvironment["GOMAXPROCS"] = "1" },
		"GODEBUG":           func(input *ManifestInput) { input.ProductionEnvironment["GODEBUG"] = "gctrace=1" },
		"unlisted DERPHOLE": func(input *ManifestInput) { input.ProductionEnvironment["DERPHOLE_OTHER"] = "1" },
		"extra unrelated":   func(input *ManifestInput) { input.ProductionEnvironment["SAFE"] = "1" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("noncanonical child-process environment accepted")
			}
		})
	}
}

func TestManifestRejectsUnsafeLogicalIDs(t *testing.T) {
	t.Parallel()

	values := []string{".", "..", "../escape", "-option", "_hidden", "slash/name", "bad\ncontrol", strings.Repeat("a", 129)}
	for _, target := range []string{"candidate", "run", "fleet"} {
		for _, value := range values {
			t.Run(target+"/"+value, func(t *testing.T) {
				input := cloneManifestInput(t, validExperimentInput())
				switch target {
				case "candidate":
					prior := input.Candidates[0].ID
					input.Candidates[0].ID = value
					input.Candidates[0].Config["candidate"] = value
					for scheduleIndex := range input.Schedules {
						for rowIndex, candidateID := range input.Schedules[scheduleIndex].CandidateOrder {
							if candidateID == prior {
								input.Schedules[scheduleIndex].CandidateOrder[rowIndex] = value
							}
						}
					}
				case "run":
					input.Schedules[0].RunIDs[0] = value
				case "fleet":
					input.FleetInventory[0].ID = value
					input.BaselineHealthIdentity.HostID = value
				}
				if _, err := NewManifest(input); err == nil {
					t.Fatalf("unsafe %s ID %q accepted", target, value)
				}
			})
		}
	}
}

func TestManifestValidatesSSHIdentityShape(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"root@hetz", "ubuntu@eric-nuc", "benchmark@fleet-a"} {
		t.Run("valid/"+value, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			input.FleetInventory[1].SSH = value
			if _, err := NewManifest(input); err != nil {
				t.Fatalf("valid SSH identity %q rejected: %v", value, err)
			}
		})
	}
	for _, value := range []string{"-option@host", "benchmark", "@host", "user@", "user@@host", "user name@host", "user@host;rm", "user@host|cmd", "user@host$(id)", "user@host\n", "user@-host"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			input.FleetInventory[1].SSH = value
			if _, err := NewManifest(input); err == nil {
				t.Fatalf("unsafe SSH identity %q accepted", value)
			}
		})
	}
}

func TestManifestRejectsWrongRulesPortFleetAndHealth(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"capacity port":     func(input *ManifestInput) { input.CapacityTCPPort = 8321 },
		"file threshold":    func(input *ManifestInput) { input.Rules.FileMinimumMbps = 1999 },
		"capacity attempts": func(input *ManifestInput) { input.Rules.CapacityAttempts = 4 },
		"empty fleet":       func(input *ManifestInput) { input.FleetInventory = nil },
		"duplicate fleet ID": func(input *ManifestInput) {
			input.FleetInventory[1].ID = input.FleetInventory[0].ID
		},
		"duplicate fleet SSH": func(input *ManifestInput) {
			input.FleetInventory[1].SSH = input.FleetInventory[0].SSH
		},
		"watchdog flag": func(input *ManifestInput) {
			input.FleetInventory[len(input.FleetInventory)-1].EricWatchdog = false
		},
		"empty health": func(input *ManifestInput) { input.BaselineHealthCounters = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("invalid frozen input accepted")
			}
		})
	}
}

func TestManifestRejectsIncompleteOrReorderedExperimentSchedules(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"one-row screening": func(input *ManifestInput) {
			input.Schedules[0].RunIDs = input.Schedules[0].RunIDs[:1]
			input.Schedules[0].CandidateOrder = input.Schedules[0].CandidateOrder[:1]
			input.Schedules[0].DirectionOrder = input.Schedules[0].DirectionOrder[:1]
		},
		"wrong screening direction": func(input *ManifestInput) {
			for index := range input.Schedules[0].DirectionOrder {
				input.Schedules[0].DirectionOrder[index] = "mac-to-hetz"
			}
		},
		"omitted finalist candidate": func(input *ManifestInput) {
			for index := range input.Schedules[1].CandidateOrder {
				input.Schedules[1].CandidateOrder[index] = input.Candidates[0].ID
			}
		},
		"unbalanced finalist direction": func(input *ManifestInput) {
			input.Schedules[1].CandidateOrder[0] = input.Schedules[1].CandidateOrder[1]
		},
		"same-multiplicity preliminary position substitution": func(input *ManifestInput) {
			input.Schedules[1].CandidateOrder[0], input.Schedules[1].CandidateOrder[1] =
				input.Schedules[1].CandidateOrder[1], input.Schedules[1].CandidateOrder[0]
		},
		"same-multiplicity finalist block substitution": func(input *ManifestInput) {
			input.Schedules[2].BlockOrder[0], input.Schedules[2].BlockOrder[2] =
				input.Schedules[2].BlockOrder[2], input.Schedules[2].BlockOrder[0]
		},
		"same-multiplicity rerun position substitution": func(input *ManifestInput) {
			input.Schedules[3].CandidateOrder[0], input.Schedules[3].CandidateOrder[1] =
				input.Schedules[3].CandidateOrder[1], input.Schedules[3].CandidateOrder[0]
		},
		"short finalist multiplicity": func(input *ManifestInput) {
			input.Schedules[1].RunIDs = input.Schedules[1].RunIDs[:len(input.Schedules[1].RunIDs)-1]
			input.Schedules[1].CandidateOrder = input.Schedules[1].CandidateOrder[:len(input.Schedules[1].CandidateOrder)-1]
			input.Schedules[1].DirectionOrder = input.Schedules[1].DirectionOrder[:len(input.Schedules[1].DirectionOrder)-1]
		},
		"reordered stages": func(input *ManifestInput) {
			input.Schedules[0], input.Schedules[1] = input.Schedules[1], input.Schedules[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("incomplete or reordered experiment schedule accepted")
			}
		})
	}
}

func TestManifestFreezesCompleteCampaignScheduleGraph(t *testing.T) {
	t.Parallel()

	experiment := validExperimentInput()
	assertFrozenScheduleShape(t, experiment.Schedules, []string{"screening", "preliminary", "finalist", "finalist-rerun"})
	if got, want := len(experiment.Schedules[0].RunIDs), len(experiment.Candidates)*3; got != want {
		t.Fatalf("screening rows = %d, want exact before/candidate/after triples = %d", got, want)
	}
	for _, stage := range experiment.Schedules[1:] {
		for index := range stage.RunIDs {
			if index >= len(stage.HostOrder) || index >= len(stage.BlockOrder) || index >= len(stage.RunRoles) {
				t.Fatalf("stage %s row %d lacks frozen host/block/role identity", stage.Stage, index)
			}
		}
	}

	manifest := mustManifest(t, experiment)
	production := validProductionInput(t, manifest)
	assertFrozenScheduleShape(t, production.Schedules, []string{"production", "fleet"})
	wantFleetRows := 0
	for _, host := range production.FleetInventory {
		if host.Role != HostRolePrimary {
			wantFleetRows += 6
		}
	}
	if got := len(production.Schedules[1].RunIDs); got != wantFleetRows {
		t.Fatalf("fleet rows = %d, want %d predeclared per-host rows", got, wantFleetRows)
	}
}

func assertFrozenScheduleShape(t *testing.T, schedules []FrozenSchedule, want []string) {
	t.Helper()
	if len(schedules) != len(want) {
		t.Fatalf("schedule count = %d, want %d (%v)", len(schedules), len(want), want)
	}
	for index, stage := range want {
		if schedules[index].Stage != stage {
			t.Fatalf("schedule %d = %q, want %q", index, schedules[index].Stage, stage)
		}
	}
}

func TestManifestRequiresTypedCanonicalFleetShape(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"missing ordinary fleet": func(input *ManifestInput) {
			input.FleetInventory = input.FleetInventory[:1]
		},
		"primary not first": func(input *ManifestInput) {
			input.FleetInventory[0], input.FleetInventory[1] = input.FleetInventory[1], input.FleetInventory[0]
		},
		"renamed role": func(input *ManifestInput) {
			*input = withFleetRoleOverride(t, *input, 0, "renamed")
		},
		"missing role": func(input *ManifestInput) {
			*input = withFleetRoleOverride(t, *input, 1, "")
		},
		"watchdog not last": func(input *ManifestInput) {
			last := len(input.FleetInventory) - 1
			input.FleetInventory[1], input.FleetInventory[last] = input.FleetInventory[last], input.FleetInventory[1]
		},
		"watchdog flag on ordinary host": func(input *ManifestInput) {
			input.FleetInventory[1].EricWatchdog = true
		},
		"watchdog flag missing": func(input *ManifestInput) {
			last := len(input.FleetInventory) - 1
			input.FleetInventory[last].ID = "sentinel"
			input.FleetInventory[last].SSH = "benchmark@sentinel"
			input.FleetInventory[last].EricWatchdog = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("invalid canonical fleet shape accepted")
			}
		})
	}
}

func TestManifestRejectsEveryChangedOrNonfiniteFrozenRule(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*FrozenRules){
		"capacity minimum":          func(rules *FrozenRules) { rules.CapacityMinimumMbps = 2051 },
		"file minimum":              func(rules *FrozenRules) { rules.FileMinimumMbps = 2001 },
		"maximum CV":                func(rules *FrozenRules) { rules.MaxCV = 0.11 },
		"material delta":            func(rules *FrozenRules) { rules.MaterialDelta = 0.04 },
		"screen dominance":          func(rules *FrozenRules) { rules.ScreenDominance = 0.11 },
		"finalist delta":            func(rules *FrozenRules) { rules.FinalistDelta = 0.06 },
		"maximum recovery":          func(rules *FrozenRules) { rules.MaxRecovery = 0.03 },
		"maximum scan":              func(rules *FrozenRules) { rules.MaxScanPerPacket = 2.1 },
		"maximum CPU":               func(rules *FrozenRules) { rules.MaxCPUSecondsPerGiB = 8.1 },
		"CPU saturation":            func(rules *FrozenRules) { rules.MinCeilingCPUSaturation = 0.91 },
		"kernel saturation":         func(rules *FrozenRules) { rules.MinCeilingKernelSaturation = 0.91 },
		"profile agreement":         func(rules *FrozenRules) { rules.RequiredProfileAgreement = 0.99 },
		"capacity attempts":         func(rules *FrozenRules) { rules.CapacityAttempts = 2 },
		"repeated ceiling profiles": func(rules *FrozenRules) { rules.MinRepeatedCeilingProfiles = 3 },
		"NaN":                       func(rules *FrozenRules) { rules.MaxCV = math.NaN() },
		"positive infinity":         func(rules *FrozenRules) { rules.MaterialDelta = math.Inf(1) },
		"negative infinity":         func(rules *FrozenRules) { rules.FinalistDelta = math.Inf(-1) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input.Rules)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("changed or nonfinite frozen rule accepted")
			}
		})
	}
}

func TestManifestRejectsMalformedIdentityStructure(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"commit": func(input *ManifestInput) {
			input.Candidates[0].Commit = "not-a-commit"
			input.Candidates[0].Darwin.VCSRevision = "not-a-commit"
			input.Candidates[0].Linux.VCSRevision = "not-a-commit"
		},
		"revision": func(input *ManifestInput) { input.Candidates[0].Darwin.VCSRevision = strings.Repeat("f", 40) },
		"platform": func(input *ManifestInput) { input.Candidates[0].Darwin.Platform = "darwin- arm64" },
		"boot ID":  func(input *ManifestInput) { input.RemoteBootID = "not-a-boot-id" },
		"candidate ID": func(input *ManifestInput) {
			input.Candidates[0].ID = "candidate with spaces"
			input.Schedules[0].CandidateOrder[0] = input.Candidates[0].ID
			input.Schedules[1].CandidateOrder[0] = input.Candidates[0].ID
		},
		"config key":     func(input *ManifestInput) { input.Candidates[0].Config = map[string]string{"bad key": "value"} },
		"config control": func(input *ManifestInput) { input.Candidates[0].Config = map[string]string{"candidate": "bad\nvalue"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, validExperimentInput())
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("malformed identity accepted")
			}
		})
	}
}

func TestManifestRejectsUnsafeOrDuplicateArtifactPaths(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	valid := validAcceptanceInput(t, mustManifest(t, validProductionInput(t, experiment)))
	tests := map[string]func(*ManifestInput){
		"absolute":         func(input *ManifestInput) { input.ParentManifest.Path = "/tmp/manifest.json" },
		"dot":              func(input *ManifestInput) { input.ParentManifest.Path = "." },
		"parent traversal": func(input *ManifestInput) { input.ParentManifest.Path = "../manifest.json" },
		"nested traversal": func(input *ManifestInput) { input.ParentManifest.Path = "proof/../../manifest.json" },
		"unclean":          func(input *ManifestInput) { input.ParentManifest.Path = "proof//manifest.json" },
		"backslash":        func(input *ManifestInput) { input.ParentManifest.Path = `proof\manifest.json` },
		"duplicate path":   func(input *ManifestInput) { input.ParentDecisionRefs[1].Path = input.ParentDecisionRefs[0].Path },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, valid)
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("unsafe or duplicate artifact path accepted")
			}
		})
	}
}

func TestNewManifestDeepCopiesInput(t *testing.T) {
	t.Parallel()

	input := validExperimentInput()
	manifest := mustManifest(t, input)
	input.Candidates[0].Config["candidate"] = "mutated"
	input.Schedules[0].RunIDs[0] = "mutated"
	input.Schedules[0].CandidateOrder[0] = "mutated"
	input.ProductionEnvironment["LANG"] = "mutated"
	input.FleetInventory[0].ID = "mutated"
	input.BaselineHealthCounters["global_oom_kills"] = 99
	if err := ValidateManifest(manifest); err != nil {
		t.Fatalf("returned manifest changed with caller input: %v", err)
	}
	if manifest.ManifestInput.Candidates[0].Config["candidate"] == "mutated" ||
		manifest.ManifestInput.Schedules[0].RunIDs[0] == "mutated" ||
		manifest.ManifestInput.FleetInventory[0].ID == "mutated" ||
		manifest.ManifestInput.BaselineHealthCounters["global_oom_kills"] == 99 {
		t.Fatal("returned manifest aliases caller-owned maps or slices")
	}
}

func TestProductionManifestRequiresParentDecisionAndNewBinaryHashes(t *testing.T) {
	t.Parallel()

	parent := mustManifest(t, validExperimentInput())
	valid := validProductionInput(t, parent)
	if _, err := NewManifest(valid); err != nil {
		t.Fatalf("valid production: %v", err)
	}

	tests := map[string]func(*ManifestInput){
		"missing parent":            func(input *ManifestInput) { input.ParentManifest = nil },
		"missing finalist decision": func(input *ManifestInput) { input.ParentDecisionRefs = nil },
		"wrong decision role":       func(input *ManifestInput) { input.ParentDecisionRefs[0].Role = "fleet" },
		"anonymous decision":        func(input *ManifestInput) { input.ParentDecisionRefs[0].Role = "" },
		"duplicate decision role": func(input *ManifestInput) {
			input.ParentDecisionRefs = append(input.ParentDecisionRefs, input.ParentDecisionRefs[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, valid)
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("invalid production manifest accepted")
			}
		})
	}

	for name, mutate := range map[string]func(*ManifestInput){
		"reused payload": func(input *ManifestInput) { input.Payload = parent.ManifestInput.Payload },
		"reused Darwin binary": func(input *ManifestInput) {
			input.Candidates[0].Darwin.SHA256 = parent.ManifestInput.Candidates[0].Darwin.SHA256
		},
		"reused Linux binary": func(input *ManifestInput) {
			input.Candidates[0].Linux.SHA256 = parent.ManifestInput.Candidates[0].Linux.SHA256
		},
		"reused commit": func(input *ManifestInput) {
			input.Candidates[0].Commit = parent.ManifestInput.Candidates[0].Commit
			input.Candidates[0].Darwin.VCSRevision = input.Candidates[0].Commit
			input.Candidates[0].Linux.VCSRevision = input.Candidates[0].Commit
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, valid)
			mutate(&input)
			child := mustManifest(t, input)
			if err := VerifyManifestTransition(parent, canonicalManifestDigest(t, parent), child); err == nil {
				t.Fatal("non-fresh production transition accepted")
			}
		})
	}
}

func TestAcceptanceManifestRequiresBoundThreeGiBPayload(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	valid := validAcceptanceInput(t, production)
	child := mustManifest(t, valid)
	if err := VerifyManifestTransition(production, canonicalManifestDigest(t, production), child); err != nil {
		t.Fatalf("valid acceptance transition: %v", err)
	}

	tests := map[string]func(*ManifestInput){
		"one GiB payload":      func(input *ManifestInput) { input.Payload.Bytes = oneGiB },
		"missing prerequisite": func(input *ManifestInput) { input.ParentDecisionRefs = input.ParentDecisionRefs[1:] },
		"missing fleet":        func(input *ManifestInput) { input.ParentDecisionRefs = input.ParentDecisionRefs[:1] },
		"extra decision": func(input *ManifestInput) {
			input.ParentDecisionRefs = append(input.ParentDecisionRefs, testArtifactRef("peak", "peak.json", '9'))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, valid)
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("invalid acceptance manifest accepted")
			}
		})
	}

	changed := cloneManifestInput(t, valid)
	changed.Candidates[0].Linux.SHA256 = hexDigest('0')
	changedChild := mustManifest(t, changed)
	if err := VerifyManifestTransition(production, canonicalManifestDigest(t, production), changedChild); err == nil {
		t.Fatal("acceptance binary substitution accepted")
	}
}

func TestCeilingManifestRequiresDiagnosticSweepAndProfiles(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	valid := validCeilingInput(t, production)
	child := mustManifest(t, valid)
	if err := VerifyManifestTransition(production, canonicalManifestDigest(t, production), child); err != nil {
		t.Fatalf("valid ceiling transition: %v", err)
	}

	tests := map[string]func(*ManifestInput){
		"missing peak":                    func(input *ManifestInput) { input.ParentDecisionRefs = input.ParentDecisionRefs[1:] },
		"missing descending sweep":        func(input *ManifestInput) { input.Schedules = input.Schedules[:2] },
		"wrong sweep points":              func(input *ManifestInput) { input.Schedules[0].OfferedLoadMbps[2] = 1750 },
		"too few profiles":                func(input *ManifestInput) { input.Schedules[4].Repetitions = 1 },
		"wrong saturation":                func(input *ManifestInput) { input.Rules.MinCeilingCPUSaturation = 0.89 },
		"production binary as diagnostic": func(input *ManifestInput) { input.Candidates = cloneCandidates(production.ManifestInput.Candidates) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, valid)
			mutate(&input)
			candidate, err := NewManifest(input)
			if err != nil {
				return
			}
			if err := VerifyManifestTransition(production, canonicalManifestDigest(t, production), candidate); err == nil {
				t.Fatal("invalid ceiling manifest accepted")
			}
		})
	}
}

func TestManifestTransitionRejectsPayloadOrBinarySubstitution(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	productionInput := validProductionInput(t, experiment)
	production := mustManifest(t, productionInput)
	digest := canonicalManifestDigest(t, experiment)

	tests := map[string]func(*Manifest){
		"wrong parent digest":  func(child *Manifest) { child.ManifestInput.ParentManifest.SHA256 = hexDigest('9') },
		"payload substitution": func(child *Manifest) { child.ManifestInput.Payload = experiment.ManifestInput.Payload },
		"binary substitution": func(child *Manifest) {
			child.ManifestInput.Candidates[0].Linux.SHA256 = experiment.ManifestInput.Candidates[0].Linux.SHA256
		},
		"fleet substitution":       func(child *Manifest) { child.ManifestInput.FleetInventory[0].SSH = "other@example" },
		"rule substitution":        func(child *Manifest) { child.ManifestInput.Rules.MaxCV = 0.09 },
		"environment substitution": func(child *Manifest) { child.ManifestInput.ProductionEnvironment["LANG"] = "C" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			child := production
			child.ManifestInput = cloneManifestInput(t, production.ManifestInput)
			mutate(&child)
			if err := VerifyManifestTransition(experiment, digest, child); err == nil {
				t.Fatal("substituted transition accepted")
			}
		})
	}

	if err := VerifyManifestTransition(experiment, hexDigest('9'), production); err == nil {
		t.Fatal("supplied wrong parent digest accepted")
	}
	acceptance := mustManifest(t, validAcceptanceInput(t, production))
	if err := VerifyManifestTransition(experiment, canonicalManifestDigest(t, experiment), acceptance); err == nil {
		t.Fatal("experiment-to-acceptance stage skip accepted")
	}
}

func TestManifestTransitionPreservesExactFleetRulesAndAncestry(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	production := mustManifest(t, validProductionInput(t, experiment))
	acceptanceInput := validAcceptanceInput(t, production)

	for name, mutate := range map[string]func(*ManifestInput){
		"fleet addition": func(input *ManifestInput) {
			input.FleetInventory = append(input.FleetInventory, HostIdentity{ID: "extra", SSH: "bench@extra", PublicIPv4: "4.2.2.2"})
		},
		"stronger rule": func(input *ManifestInput) { input.Rules.FileMinimumMbps = 2100 },
	} {
		t.Run(name, func(t *testing.T) {
			input := cloneManifestInput(t, acceptanceInput)
			mutate(&input)
			child, err := NewManifest(input)
			if err != nil {
				return
			}
			if err := VerifyManifestTransition(production, canonicalManifestDigest(t, production), child); err == nil {
				t.Fatal("ancestry mutation accepted")
			}
		})
	}
}

func TestManifestTransitionAllowsFreshBaselineHealthCounters(t *testing.T) {
	t.Parallel()

	experiment := mustManifest(t, validExperimentInput())
	input := validProductionInput(t, experiment)
	input.BaselineHealthCounters["udp_errors"]++
	input.BaselineHealthCounters["softnet_drops"] = 7
	bindBaselineHealthRecordDigest(t, &input)
	production := mustManifest(t, input)
	if err := VerifyManifestTransition(experiment, canonicalManifestDigest(t, experiment), production); err != nil {
		t.Fatalf("fresh child baseline counters rejected: %v", err)
	}
}

func TestManifestRejectsUnboundBaselineHealthIdentity(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*BaselineHealthIdentity){
		"wrong artifact role": func(identity *BaselineHealthIdentity) {
			identity.Artifact.Role = "baseline"
		},
		"wrong artifact path": func(identity *BaselineHealthIdentity) {
			identity.Artifact.Path = "baselines/other.json"
		},
		"noncanonical UTC capture": func(identity *BaselineHealthIdentity) {
			identity.CapturedAtUTC = "2026-07-16T00:00:00+00:00"
		},
		"zero sequence": func(identity *BaselineHealthIdentity) {
			identity.Sequence = 0
		},
		"unknown remote host": func(identity *BaselineHealthIdentity) {
			identity.HostID = "fleet-a"
		},
		"wrong remote boot": func(identity *BaselineHealthIdentity) {
			identity.BootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validExperimentInput()
			identity := baselineIdentityForKind(ManifestExperiment)
			mutate(&identity)
			input = withBaselineHealthIdentity(t, input, identity)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("unbound baseline health identity accepted")
			}
		})
	}
}

func TestManifestTransitionRequiresFreshBaselineCaptureIdentity(t *testing.T) {
	t.Parallel()

	parent := mustManifest(t, validExperimentInput())
	tests := map[string]func(*ManifestInput){
		"stale capture time": func(input *ManifestInput) {
			input.BaselineHealthIdentity.CapturedAtUTC = parent.ManifestInput.BaselineHealthIdentity.CapturedAtUTC
		},
		"stale sequence": func(input *ManifestInput) {
			input.BaselineHealthIdentity.Sequence = parent.ManifestInput.BaselineHealthIdentity.Sequence
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			childInput := validProductionInput(t, parent)
			mutate(&childInput)
			bindBaselineHealthRecordDigest(t, &childInput)
			child := mustManifest(t, childInput)
			if err := VerifyManifestTransition(parent, canonicalManifestDigest(t, parent), child); err == nil {
				t.Fatal("stale baseline health capture accepted")
			}
		})
	}
}

func TestManifestTransitionAllowsEqualCountersWithFreshBoundCapture(t *testing.T) {
	t.Parallel()

	parent := mustManifest(t, validExperimentInput())
	childInput := validProductionInput(t, parent)
	childInput.BaselineHealthCounters = cloneUint64Map(parent.ManifestInput.BaselineHealthCounters)
	bindBaselineHealthRecordDigest(t, &childInput)
	child := mustManifest(t, childInput)
	if err := VerifyManifestTransition(parent, canonicalManifestDigest(t, parent), child); err != nil {
		t.Fatalf("fresh bound capture with equal counter values rejected: %v", err)
	}
}

func TestBaselineHealthRecordBindsCanonicalSemanticCapture(t *testing.T) {
	t.Parallel()

	input := validExperimentInput()
	record := bindBaselineHealthRecordDigest(t, &input)
	if _, err := NewManifest(input); err != nil {
		t.Fatalf("canonically bound baseline record rejected: %v", err)
	}
	data, err := canonicalJSONBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "artifact") {
		t.Fatalf("baseline record recursively contains artifact identity: %s", data)
	}
	if input.BaselineHealthIdentity.Artifact.SHA256 != DigestBytes(data) {
		t.Fatalf("baseline digest = %q, exact record digest = %q", input.BaselineHealthIdentity.Artifact.SHA256, DigestBytes(data))
	}
}

func TestBaselineHealthRecordRequiresExactCounterSet(t *testing.T) {
	t.Parallel()

	for key := range validBaselineHealthCounters() {
		t.Run("missing/"+key, func(t *testing.T) {
			input := validExperimentInput()
			bindBaselineHealthRecordDigest(t, &input)
			delete(input.BaselineHealthCounters, key)
			if _, err := NewManifest(input); err == nil {
				t.Fatalf("baseline record missing %q accepted", key)
			}
		})
	}
	t.Run("extra", func(t *testing.T) {
		input := validExperimentInput()
		bindBaselineHealthRecordDigest(t, &input)
		input.BaselineHealthCounters["unrelated"] = 1
		if _, err := NewManifest(input); err == nil {
			t.Fatal("baseline record with extra counter accepted")
		}
	})
}

func TestBaselineHealthRecordRequiresGaugeInvariants(t *testing.T) {
	t.Parallel()

	for key, value := range map[string]uint64{
		"uptime_seconds":         0,
		"online_cpus":            3,
		"available_memory_bytes": 0,
		"disk_free_bytes":        0,
	} {
		t.Run(key, func(t *testing.T) {
			input := validExperimentInput()
			input.BaselineHealthCounters[key] = value
			bindBaselineHealthRecordDigest(t, &input)
			if _, err := NewManifest(input); err == nil {
				t.Fatalf("invalid baseline gauge %s=%d accepted", key, value)
			}
		})
	}
}

func TestBaselineHealthRecordRejectsSemanticMutationWithoutDigestUpdate(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ManifestInput){
		"capture time": func(input *ManifestInput) {
			input.BaselineHealthIdentity.CapturedAtUTC = "2026-07-16T00:00:01Z"
		},
		"sequence": func(input *ManifestInput) {
			input.BaselineHealthIdentity.Sequence++
		},
		"host": func(input *ManifestInput) {
			input.BaselineHealthIdentity.HostID = "primary-renamed"
			input.FleetInventory[0].ID = "primary-renamed"
		},
		"boot": func(input *ManifestInput) {
			input.BaselineHealthIdentity.BootID = "22222222-3333-4444-5555-666666666666"
			input.RemoteBootID = "22222222-3333-4444-5555-666666666666"
		},
		"counter": func(input *ManifestInput) {
			input.BaselineHealthCounters["process_count"]++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validExperimentInput()
			bindBaselineHealthRecordDigest(t, &input)
			mutate(&input)
			if _, err := NewManifest(input); err == nil {
				t.Fatal("baseline semantic mutation without digest update accepted")
			}
		})
	}
}

func TestManifestFixtures(t *testing.T) {
	t.Parallel()

	validBytes, err := os.ReadFile(filepath.Join("testdata", "manifest-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var valid Manifest
	if err := json.Unmarshal(validBytes, &valid); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(valid); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}

	invalidBytes, err := os.ReadFile(filepath.Join("testdata", "manifest-invalid-duplicate-candidate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var invalid Manifest
	if err := json.Unmarshal(invalidBytes, &invalid); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(invalid); err == nil {
		t.Fatal("duplicate-candidate fixture accepted")
	}
}

func validExperimentInput() ManifestInput {
	control := testCandidate("control", '1', '2', '3')
	challenger := testCandidate("challenger", '4', '5', '6')
	input := ManifestInput{
		Kind:                  ManifestExperiment,
		LocalPublicIPv4:       "1.1.1.1",
		RemotePublicIPv4:      "8.8.8.8",
		RemoteKernel:          "6.8.0-test",
		RemoteArch:            "x86_64",
		RemoteBootID:          "11111111-2222-3333-4444-555555555555",
		RemoteOnlineCPUs:      2,
		Payload:               PayloadIdentity{Bytes: oneGiB, SHA256: hexDigest('a')},
		Candidates:            []CandidateIdentity{control, challenger},
		ScreeningControlID:    control.ID,
		Schedules:             experimentSchedules(control.ID, challenger.ID),
		Rules:                 validRules(),
		ProductionEnvironment: map[string]string{"DERPHOLE_TRANSFER_TRACE_CSV": "trace.csv"},
		FleetInventory: []HostIdentity{
			{ID: "primary", SSH: "benchmark@primary", PublicIPv4: "8.8.8.8", Role: HostRolePrimary},
			{ID: "fleet-a", SSH: "benchmark@fleet-a", PublicIPv4: "4.2.2.2", Role: HostRoleFleet},
			{ID: "fleet-b", SSH: "benchmark@fleet-b", PublicIPv4: "8.8.4.4", Role: HostRoleFleet},
			{ID: "sentinel", SSH: "benchmark@sentinel", PublicIPv4: "9.9.9.9", Role: HostRoleWatchdog, EricWatchdog: true},
		},
		BaselineHealthCounters: validBaselineHealthCounters(),
		BaselineHealthIdentity: baselineIdentityForKind(ManifestExperiment),
		CapacityTCPPort:        8123,
	}
	mustBindBaselineHealthRecordDigest(&input)
	return input
}

func validProductionInput(t *testing.T, parent Manifest) ManifestInput {
	t.Helper()
	input := cloneManifestInput(t, parent.ManifestInput)
	input.Kind = ManifestProduction
	input.BaselineHealthIdentity = baselineIdentityForKind(ManifestProduction)
	input.ParentManifest = ptrArtifactRef(ArtifactRef{Role: "manifest", Path: "manifest.json", SHA256: canonicalManifestDigest(t, parent)})
	input.ParentDecisionRefs = []ArtifactRef{testArtifactRef("finalist", "decisions/finalist.json", 'b')}
	input.Payload = PayloadIdentity{Bytes: oneGiB, SHA256: hexDigest('c')}
	production := testCandidate("production", '7', '8', '9')
	production.Config = map[string]string{"mode": "source-default"}
	input.Candidates = []CandidateIdentity{production}
	input.ScreeningControlID = ""
	input.Schedules = productionSchedules(input, production.ID)
	bindBaselineHealthRecordDigest(t, &input)
	return input
}

func validAcceptanceInput(t *testing.T, parent Manifest) ManifestInput {
	t.Helper()
	input := cloneManifestInput(t, parent.ManifestInput)
	input.Kind = ManifestAcceptance
	input.BaselineHealthIdentity = baselineIdentityForKind(ManifestAcceptance)
	input.ParentManifest = ptrArtifactRef(ArtifactRef{Role: "manifest", Path: "production-manifest.json", SHA256: canonicalManifestDigest(t, parent)})
	input.ParentDecisionRefs = []ArtifactRef{
		testArtifactRef("prerequisite", "decisions/prerequisite.json", 'd'),
		testArtifactRef("fleet", "decisions/fleet.json", 'e'),
	}
	input.Payload = PayloadIdentity{Bytes: threeGiB, SHA256: hexDigest('f')}
	input.ScreeningControlID = ""
	input.Schedules = repeatedSchedule("acceptance", parent.ManifestInput.Candidates[0].ID, "accept", 3)
	bindBaselineHealthRecordDigest(t, &input)
	return input
}

func validCeilingInput(t *testing.T, parent Manifest) ManifestInput {
	t.Helper()
	input := cloneManifestInput(t, parent.ManifestInput)
	input.Kind = ManifestCeiling
	input.BaselineHealthIdentity = baselineIdentityForKind(ManifestCeiling)
	input.ParentManifest = ptrArtifactRef(ArtifactRef{Role: "manifest", Path: "production-manifest.json", SHA256: canonicalManifestDigest(t, parent)})
	input.ParentDecisionRefs = []ArtifactRef{
		testArtifactRef("peak", "decisions/peak.json", 'd'),
		testArtifactRef("fleet", "decisions/fleet.json", 'e'),
	}
	diagnostic := testCandidate("diagnostic", 'a', 'b', 'c')
	diagnostic.Config = map[string]string{"mode": "diagnostic"}
	input.Candidates = []CandidateIdentity{diagnostic}
	input.ScreeningControlID = ""
	input.Schedules = ceilingSchedules(diagnostic.ID)
	bindBaselineHealthRecordDigest(t, &input)
	return input
}

func validRules() FrozenRules {
	return FrozenRules{
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
}

func testCandidate(id string, commitRune, darwinRune, linuxRune rune) CandidateIdentity {
	commit := strings.Repeat(string(commitRune), 40)
	return CandidateIdentity{
		ID:     id,
		Commit: commit,
		Darwin: BinaryIdentity{Platform: "darwin-arm64", SHA256: hexDigest(darwinRune), VCSRevision: commit},
		Linux:  BinaryIdentity{Platform: "linux-amd64", SHA256: hexDigest(linuxRune), VCSRevision: commit},
		Config: map[string]string{"candidate": id},
	}
}

func experimentSchedules(control, challenger string) []FrozenSchedule {
	candidates := []string{control, challenger}
	screening := FrozenSchedule{Stage: "screening", Repetitions: 1}
	for block, candidate := range candidates {
		for offset, row := range []struct{ suffix, candidate, role string }{
			{"before", control, "control-before"},
			{"candidate", candidate, "candidate"},
			{"after", control, "control-after"},
		} {
			screening.RunIDs = append(screening.RunIDs, fmt.Sprintf("screen-%s-%s", candidate, row.suffix))
			screening.CandidateOrder = append(screening.CandidateOrder, row.candidate)
			screening.HostOrder = append(screening.HostOrder, "primary")
			screening.DirectionOrder = append(screening.DirectionOrder, "hetz-to-mac")
			screening.BlockOrder = append(screening.BlockOrder, block)
			screening.RunRoles = append(screening.RunRoles, row.role)
			_ = offset
		}
	}
	return []FrozenSchedule{
		screening,
		balancedCandidateSchedule("preliminary", "prelim", candidates, 3),
		balancedCandidateSchedule("finalist", "final", candidates, 3),
		balancedCandidateSchedule("finalist-rerun", "rerun", candidates, 6),
	}
}

func balancedCandidateSchedule(stage, prefix string, candidates []string, repetitions int) FrozenSchedule {
	schedule := FrozenSchedule{Stage: stage, Repetitions: repetitions}
	rotations := finalistRotation(candidates)
	for _, item := range []struct{ short, direction string }{{"h2m", "hetz-to-mac"}, {"m2h", "mac-to-hetz"}} {
		for repetition := range repetitions {
			rotation := rotations[repetition%len(rotations)]
			for _, candidate := range rotation {
				schedule.RunIDs = append(schedule.RunIDs, fmt.Sprintf("%s-%s-%s-%d", prefix, item.short, candidate, repetition+1))
				schedule.CandidateOrder = append(schedule.CandidateOrder, candidate)
				schedule.HostOrder = append(schedule.HostOrder, "primary")
				schedule.DirectionOrder = append(schedule.DirectionOrder, item.direction)
				schedule.BlockOrder = append(schedule.BlockOrder, repetition)
				schedule.RunRoles = append(schedule.RunRoles, "file")
			}
		}
	}
	return schedule
}

func repeatedSchedule(stage, candidate, prefix string, repetitions int) []FrozenSchedule {
	schedule := FrozenSchedule{Stage: stage, Repetitions: repetitions}
	for i := 1; i <= repetitions; i++ {
		appendFrozenTestRow(&schedule, prefix+"-h2m-"+string(rune('0'+i)), candidate, "primary", "hetz-to-mac", i-1, "file")
	}
	for i := 1; i <= repetitions; i++ {
		appendFrozenTestRow(&schedule, prefix+"-m2h-"+string(rune('0'+i)), candidate, "primary", "mac-to-hetz", i-1, "file")
	}
	return []FrozenSchedule{schedule}
}

func productionSchedules(input ManifestInput, candidate string) []FrozenSchedule {
	schedules := repeatedSchedule("production", candidate, "prod", 3)
	fleet := FrozenSchedule{Stage: "fleet", Repetitions: 3}
	for _, host := range input.FleetInventory {
		if host.Role == HostRolePrimary {
			continue
		}
		for _, item := range []struct{ short, direction string }{{"h2m", "hetz-to-mac"}, {"m2h", "mac-to-hetz"}} {
			for repetition := 1; repetition <= 3; repetition++ {
				appendFrozenTestRow(&fleet, fmt.Sprintf("fleet-%s-%s-%d", host.ID, item.short, repetition), candidate, host.ID, item.direction, repetition-1, "file")
			}
		}
	}
	return append(schedules, fleet)
}

func appendFrozenTestRow(schedule *FrozenSchedule, runID, candidate, host, direction string, block int, role string) {
	schedule.RunIDs = append(schedule.RunIDs, runID)
	schedule.CandidateOrder = append(schedule.CandidateOrder, candidate)
	schedule.HostOrder = append(schedule.HostOrder, host)
	schedule.DirectionOrder = append(schedule.DirectionOrder, direction)
	schedule.BlockOrder = append(schedule.BlockOrder, block)
	schedule.RunRoles = append(schedule.RunRoles, role)
}

func ceilingSchedules(candidate string) []FrozenSchedule {
	loadsUp := []float64{1200, 1500, 1800, 2100, 2400}
	loadsDown := []float64{2400, 2100, 1800, 1500, 1200}
	var schedules []FrozenSchedule
	for _, item := range []struct {
		stage, direction string
		loads            []float64
	}{
		{"ceiling-sweep-ascending-hetz-to-mac", "hetz-to-mac", loadsUp},
		{"ceiling-sweep-descending-hetz-to-mac", "hetz-to-mac", loadsDown},
		{"ceiling-sweep-ascending-mac-to-hetz", "mac-to-hetz", loadsUp},
		{"ceiling-sweep-descending-mac-to-hetz", "mac-to-hetz", loadsDown},
	} {
		schedule := FrozenSchedule{Stage: item.stage, OfferedLoadMbps: append([]float64(nil), item.loads...), Repetitions: 1}
		for i := range item.loads {
			appendFrozenTestRow(&schedule, item.stage+"-"+string(rune('1'+i)), candidate, "primary", item.direction, i, "ceiling-sweep")
		}
		schedules = append(schedules, schedule)
	}
	profile := FrozenSchedule{Stage: "ceiling-profile", Repetitions: 2}
	appendFrozenTestRow(&profile, "profile-h2m-1", candidate, "primary", "hetz-to-mac", 0, "ceiling-profile")
	appendFrozenTestRow(&profile, "profile-h2m-2", candidate, "primary", "hetz-to-mac", 1, "ceiling-profile")
	appendFrozenTestRow(&profile, "profile-m2h-1", candidate, "primary", "mac-to-hetz", 0, "ceiling-profile")
	appendFrozenTestRow(&profile, "profile-m2h-2", candidate, "primary", "mac-to-hetz", 1, "ceiling-profile")
	schedules = append(schedules, profile)
	return schedules
}

func testArtifactRef(role, path string, digestRune rune) ArtifactRef {
	return ArtifactRef{Role: role, Path: path, SHA256: hexDigest(digestRune)}
}

func ptrArtifactRef(ref ArtifactRef) *ArtifactRef { return &ref }

func hexDigest(r rune) SHA256Digest { return SHA256Digest(strings.Repeat(string(r), 64)) }

func mustManifest(t *testing.T, input ManifestInput) Manifest {
	t.Helper()
	manifest, err := NewManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func canonicalManifestDigest(t *testing.T, manifest Manifest) SHA256Digest {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return DigestBytes(append(data, '\n'))
}

func cloneManifestInput(t *testing.T, input ManifestInput) ManifestInput {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var cloned ManifestInput
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func withFleetRoleOverride(t *testing.T, input ManifestInput, index int, role string) ManifestInput {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	fleet, ok := raw["fleet_inventory"].([]any)
	if !ok || index >= len(fleet) {
		t.Fatalf("invalid fleet fixture at index %d", index)
	}
	host, ok := fleet[index].(map[string]any)
	if !ok {
		t.Fatalf("invalid fleet host fixture at index %d", index)
	}
	host["role"] = role
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var result ManifestInput
	if err := json.Unmarshal(mutated, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func baselineIdentityForKind(kind ManifestKind) BaselineHealthIdentity {
	sequence := uint64(1)
	capturedAt := "2026-07-16T00:00:00Z"
	digestRune := '0'
	if kind != ManifestExperiment {
		sequence = 2
		capturedAt = "2026-07-16T00:01:00Z"
		digestRune = '1'
	}
	if kind == ManifestAcceptance || kind == ManifestCeiling {
		sequence = 3
		capturedAt = "2026-07-16T00:02:00Z"
		digestRune = '2'
	}
	identity := BaselineHealthIdentity{
		Artifact:      testArtifactRef("baseline-"+string(kind), "baselines/"+string(kind)+".json", digestRune),
		CapturedAtUTC: capturedAt,
		Sequence:      sequence,
		HostID:        "primary",
		BootID:        "11111111-2222-3333-4444-555555555555",
	}
	record := BaselineHealthRecord{
		SchemaVersion: 1,
		Kind:          kind,
		CapturedAtUTC: identity.CapturedAtUTC,
		Sequence:      identity.Sequence,
		HostID:        identity.HostID,
		BootID:        identity.BootID,
		Counters:      validBaselineHealthCounters(),
	}
	data, err := canonicalJSONBytes(record)
	if err != nil {
		panic(err)
	}
	identity.Artifact.SHA256 = DigestBytes(data)
	return identity
}

func withBaselineHealthIdentity(t *testing.T, input ManifestInput, identity BaselineHealthIdentity) ManifestInput {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var identityValue any
	if err := json.Unmarshal(identityBytes, &identityValue); err != nil {
		t.Fatal(err)
	}
	raw["baseline_health_identity"] = identityValue
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var result ManifestInput
	if err := json.Unmarshal(mutated, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func cloneUint64Map(input map[string]uint64) map[string]uint64 {
	cloned := make(map[string]uint64, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func validBaselineHealthCounters() map[string]uint64 {
	return map[string]uint64{
		"uptime_seconds":         3600,
		"online_cpus":            2,
		"global_oom_kills":       0,
		"cgroup_oom_kills":       0,
		"available_memory_bytes": 1024 * 1024 * 1024,
		"swap_used_bytes":        0,
		"disk_free_bytes":        10 * 1024 * 1024 * 1024,
		"kernel_error_count":     0,
		"interface_drops":        0,
		"udp_errors":             0,
		"softnet_drops":          0,
		"process_count":          70,
		"socket_count":           20,
	}
}

func bindBaselineHealthRecordDigest(t *testing.T, input *ManifestInput) BaselineHealthRecord {
	t.Helper()
	record, err := bindBaselineHealthRecordDigestValue(input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func mustBindBaselineHealthRecordDigest(input *ManifestInput) {
	if _, err := bindBaselineHealthRecordDigestValue(input); err != nil {
		panic(err)
	}
}

func bindBaselineHealthRecordDigestValue(input *ManifestInput) (BaselineHealthRecord, error) {
	record := BaselineHealthRecord{
		SchemaVersion: 1,
		Kind:          input.Kind,
		CapturedAtUTC: input.BaselineHealthIdentity.CapturedAtUTC,
		Sequence:      input.BaselineHealthIdentity.Sequence,
		HostID:        input.BaselineHealthIdentity.HostID,
		BootID:        input.BaselineHealthIdentity.BootID,
		Counters:      cloneUint64Map(input.BaselineHealthCounters),
	}
	data, err := canonicalJSONBytes(record)
	if err != nil {
		return BaselineHealthRecord{}, err
	}
	input.BaselineHealthIdentity.Artifact.SHA256 = DigestBytes(data)
	return record, nil
}

func cloneCandidates(candidates []CandidateIdentity) []CandidateIdentity {
	cloned := make([]CandidateIdentity, len(candidates))
	copy(cloned, candidates)
	for i := range cloned {
		cloned[i].Config = make(map[string]string, len(candidates[i].Config))
		for key, value := range candidates[i].Config {
			cloned[i].Config[key] = value
		}
	}
	return cloned
}

func TestManifestTestHelpersDoNotAlias(t *testing.T) {
	t.Parallel()

	original := validExperimentInput()
	clone := cloneManifestInput(t, original)
	clone.Candidates[0].Config["candidate"] = "changed"
	clone.Schedules[0].RunIDs[0] = "changed"
	if reflect.DeepEqual(original, clone) {
		t.Fatal("clone unexpectedly aliases original")
	}
}
