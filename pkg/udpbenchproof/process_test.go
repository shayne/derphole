// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdentifyProcessRequiresTwoStableObservations(t *testing.T) {
	t.Parallel()

	want := ProcessRef{Name: "derphole", PID: 42, StartIdentity: "100", ExecutableIdentity: "dev:1-ino:2"}
	var calls atomic.Int32
	observer := func(context.Context, string, int, time.Duration) (ProcessRef, error) {
		calls.Add(1)
		return want, nil
	}
	got, err := identifyProcessWithObserverAndGate(context.Background(), want.Name, want.PID, time.Second, observer, make(chan struct{}, 1))
	if err != nil || got != want {
		t.Fatalf("identified process = %#v, %v", got, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("process observations = %d, want 2", calls.Load())
	}
}

func TestIdentifyProcessFailsClosedOnAbsenceAndPIDReuse(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		observer := func(context.Context, string, int, time.Duration) (ProcessRef, error) {
			return ProcessRef{}, errors.New("process is absent")
		}
		if _, err := identifyProcessWithObserverAndGate(context.Background(), "derphole", 42, time.Second, observer, make(chan struct{}, 1)); err == nil || !strings.Contains(err.Error(), "absent") {
			t.Fatalf("absent process error = %v", err)
		}
	})

	t.Run("PID reuse", func(t *testing.T) {
		observations := []ProcessRef{
			{Name: "derphole", PID: 42, StartIdentity: "100", ExecutableIdentity: "dev:1-ino:2"},
			{Name: "derphole", PID: 42, StartIdentity: "101", ExecutableIdentity: "dev:1-ino:2"},
		}
		observer := func(context.Context, string, int, time.Duration) (ProcessRef, error) {
			observation := observations[0]
			observations = observations[1:]
			return observation, nil
		}
		if _, err := identifyProcessWithObserverAndGate(context.Background(), "derphole", 42, time.Second, observer, make(chan struct{}, 1)); err == nil || !strings.Contains(err.Error(), "changed during capture") {
			t.Fatalf("PID reuse error = %v", err)
		}
	})
}

func TestIdentifyProcessDeadlineBoundsBlockingObserver(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	observer := func(context.Context, string, int, time.Duration) (ProcessRef, error) {
		<-block
		return ProcessRef{}, nil
	}
	started := time.Now()
	_, err := identifyProcessWithObserverAndGate(context.Background(), "derphole", 42, 20*time.Millisecond, observer, make(chan struct{}, 1))
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("blocking process identity error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("blocking process identity took %s", elapsed)
	}
}
