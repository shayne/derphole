// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"testing"
)

func TestExternalParallelAutoBootstrapReady(t *testing.T) {
	if externalParallelAutoBootstrapReady(externalHandoffSpoolSnapshot{AckedWatermark: externalParallelAutoBootstrapBytes - 1}) {
		t.Fatal("bootstrap gate should stay closed below threshold")
	}
	if !externalParallelAutoBootstrapReady(externalHandoffSpoolSnapshot{AckedWatermark: externalParallelAutoBootstrapBytes}) {
		t.Fatal("bootstrap gate should open at threshold")
	}
}

func TestExternalParallelGrowthStopReason(t *testing.T) {
	tests := []struct {
		name     string
		snapshot externalHandoffSpoolSnapshot
		err      error
		want     string
	}{
		{
			name: "done",
			snapshot: externalHandoffSpoolSnapshot{
				EOF:            true,
				SourceOffset:   1024,
				AckedWatermark: 1024,
			},
			err:  context.DeadlineExceeded,
			want: "done",
		},
		{
			name: "tail",
			snapshot: externalHandoffSpoolSnapshot{
				EOF:            true,
				SourceOffset:   8 * externalCopyBufferSize,
				AckedWatermark: 8*externalCopyBufferSize - externalParallelTailBytes,
			},
			err:  context.Canceled,
			want: "tail",
		},
		{
			name: "timeout",
			snapshot: externalHandoffSpoolSnapshot{
				SourceOffset:   16 * externalCopyBufferSize,
				AckedWatermark: 4 * externalCopyBufferSize,
			},
			err:  context.DeadlineExceeded,
			want: "timeout",
		},
		{
			name: "generic error",
			snapshot: externalHandoffSpoolSnapshot{
				SourceOffset:   16 * externalCopyBufferSize,
				AckedWatermark: 4 * externalCopyBufferSize,
			},
			err:  errors.New("boom"),
			want: "grow-error err=boom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalParallelGrowthStopReason(tt.snapshot, tt.err); got != tt.want {
				t.Fatalf("externalParallelGrowthStopReason() = %q, want %q", got, tt.want)
			}
		})
	}
}
