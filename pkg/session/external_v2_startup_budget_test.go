// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
)

func TestExternalV2RawDirectStartupBudgetDefaultsOff(t *testing.T) {
	t.Setenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS", "")

	if got := externalV2RawDirectStartupBudget(); got != 0 {
		t.Fatalf("externalV2RawDirectStartupBudget() = %s, want 0", got)
	}
	if got := externalV2SetRawDirectStartupBudgetMS(); got != 0 {
		t.Fatalf("externalV2SetRawDirectStartupBudgetMS() = %d, want 0", got)
	}
}

func TestExternalV2RawDirectStartupBudgetParsesMilliseconds(t *testing.T) {
	t.Setenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS", "850")

	if got, want := externalV2RawDirectStartupBudget(), 850*time.Millisecond; got != want {
		t.Fatalf("externalV2RawDirectStartupBudget() = %s, want %s", got, want)
	}
	if got := externalV2SetRawDirectStartupBudgetMS(); got != 850 {
		t.Fatalf("externalV2SetRawDirectStartupBudgetMS() = %d, want 850", got)
	}
}

func TestExternalV2RawDirectStartupBudgetIgnoresInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "0", "abc"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DERPHOLE_V2_RAW_DIRECT_BUDGET_MS", value)
			if got := externalV2RawDirectStartupBudget(); got != 0 {
				t.Fatalf("externalV2RawDirectStartupBudget() = %s with %q, want 0", got, value)
			}
			if got := externalV2SetRawDirectStartupBudgetMS(); got != 0 {
				t.Fatalf("externalV2SetRawDirectStartupBudgetMS() = %d with %q, want 0", got, value)
			}
		})
	}
}

func TestExternalV2AcceptedRawDirectStartupBudgetUsesAcceptValue(t *testing.T) {
	accept := externalV2Accept{RawDirectBudgetMS: 850}

	if got, want := externalV2AcceptedRawDirectStartupBudget(accept), 850*time.Millisecond; got != want {
		t.Fatalf("externalV2AcceptedRawDirectStartupBudget() = %s, want %s", got, want)
	}
	if got := externalV2AcceptedRawDirectStartupBudget(externalV2Accept{RawDirectBudgetMS: -1}); got != 0 {
		t.Fatalf("externalV2AcceptedRawDirectStartupBudget(-1) = %s, want 0", got)
	}
}

func TestExternalV2ReceiveCompleteSynthesizesFromPeerProgress(t *testing.T) {
	progress := &externalV2PeerProgressState{}
	progress.Record(128, 25)

	complete, err := receiveExternalV2Complete(
		context.Background(),
		make(chan derpbind.Packet),
		make(chan error),
		externalPeerControlAuth{},
		128,
		progress,
		time.Millisecond,
	)
	if err != nil {
		t.Fatalf("receiveExternalV2Complete() error = %v", err)
	}
	if complete.BytesReceived != 128 {
		t.Fatalf("complete bytes = %d, want 128", complete.BytesReceived)
	}
}

func TestExternalV2ReceiveCompleteTimesOutWithoutProgress(t *testing.T) {
	progress := &externalV2PeerProgressState{}
	progress.Record(64, 25)

	_, err := receiveExternalV2Complete(
		context.Background(),
		make(chan derpbind.Packet),
		make(chan error),
		externalPeerControlAuth{},
		128,
		progress,
		time.Millisecond,
	)
	if !errors.Is(err, ErrPeerDisconnected) {
		t.Fatalf("receiveExternalV2Complete() error = %v, want %v", err, ErrPeerDisconnected)
	}
}
