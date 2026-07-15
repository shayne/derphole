// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"fmt"
	"math"
)

// DiskRequirement models only bytes that may coexist on disk.
type DiskRequirement struct {
	PayloadBytes            int64 `json:"payload_bytes"`
	BinaryBytes             int64 `json:"binary_bytes"`
	EvidenceReserveBytes    int64 `json:"evidence_reserve_bytes"`
	AdditionalPayloadCopies int   `json:"additional_payload_copies"`
}

// RequiredFreeBytes returns the conservative concurrent on-disk requirement.
func RequiredFreeBytes(requirement DiskRequirement) (int64, error) {
	if requirement.PayloadBytes < 0 || requirement.BinaryBytes < 0 || requirement.EvidenceReserveBytes < 0 || requirement.AdditionalPayloadCopies < 0 {
		return 0, fmt.Errorf("disk requirement values must be nonnegative")
	}
	copies := int64(requirement.AdditionalPayloadCopies) + 1
	if copies <= 0 || (requirement.PayloadBytes != 0 && copies > math.MaxInt64/requirement.PayloadBytes) {
		return 0, fmt.Errorf("payload copy requirement overflows int64")
	}
	required := requirement.PayloadBytes * copies
	var err error
	required, err = addDiskRequirement(required, requirement.BinaryBytes)
	if err != nil {
		return 0, err
	}
	return addDiskRequirement(required, requirement.EvidenceReserveBytes)
}

// CheckDiskCapacity rejects free space below the concurrent requirement.
func CheckDiskCapacity(free int64, requirement DiskRequirement) error {
	if free < 0 {
		return fmt.Errorf("disk free bytes must be nonnegative")
	}
	required, err := RequiredFreeBytes(requirement)
	if err != nil {
		return err
	}
	if free < required {
		return fmt.Errorf("disk free bytes %d below required %d", free, required)
	}
	return nil
}

func addDiskRequirement(left, right int64) (int64, error) {
	if right > math.MaxInt64-left {
		return 0, fmt.Errorf("disk requirement sum overflows int64")
	}
	return left + right, nil
}
