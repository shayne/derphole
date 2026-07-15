// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"math"
	"testing"
)

func TestDiskCapacityModelsOnlyConcurrentPayloadCopies(t *testing.T) {
	t.Parallel()

	requirement := DiskRequirement{
		PayloadBytes:            3 << 30,
		BinaryBytes:             40 << 20,
		EvidenceReserveBytes:    512 << 20,
		AdditionalPayloadCopies: 1,
	}
	want := int64(6<<30) + 40<<20 + 512<<20
	got, err := RequiredFreeBytes(requirement)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("required free bytes = %d, want %d for two concurrent payload copies", got, want)
	}
	if err := CheckDiskCapacity(want, requirement); err != nil {
		t.Fatalf("exact capacity rejected: %v", err)
	}
	if err := CheckDiskCapacity(want-1, requirement); err == nil {
		t.Fatal("one-byte-short capacity accepted")
	}
}

func TestDiskCapacityRejectsNegativeAndOverflowingRequirements(t *testing.T) {
	t.Parallel()

	for name, requirement := range map[string]DiskRequirement{
		"negative payload": {PayloadBytes: -1},
		"negative binary":  {BinaryBytes: -1},
		"negative reserve": {EvidenceReserveBytes: -1},
		"negative copies":  {AdditionalPayloadCopies: -1},
		"copy overflow":    {PayloadBytes: math.MaxInt64, AdditionalPayloadCopies: 1},
		"sum overflow":     {PayloadBytes: math.MaxInt64 - 1, BinaryBytes: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RequiredFreeBytes(requirement); err == nil {
				t.Fatalf("invalid requirement accepted: %#v", requirement)
			}
		})
	}
	if err := CheckDiskCapacity(-1, DiskRequirement{}); err == nil {
		t.Fatal("negative free space accepted")
	}
}
