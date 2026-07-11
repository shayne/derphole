// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/dataplane"
)

type recordingExternalV2Endpoint struct {
	closeCode   uint64
	closeReason string
}

func (e *recordingExternalV2Endpoint) CloseWithError(code uint64, reason string) error {
	e.closeCode = code
	e.closeReason = reason
	return nil
}

func (*recordingExternalV2Endpoint) Stats() dataplane.Stats {
	return dataplane.Stats{}
}

func TestExternalV2OfferFinishSendStreamDoesNotPublishZeroElapsed(t *testing.T) {
	var progressCalls int
	rt := &externalV2OfferRuntime{cfg: OfferConfig{
		Progress: func(int64, int64) { progressCalls++ },
	}}
	endpoint := &recordingExternalV2Endpoint{}
	metrics := newExternalTransferMetrics(time.Unix(1, 0))

	if err := rt.finishSendStream(context.Background(), endpoint, externalV2Complete{BytesReceived: 1024}, metrics, &externalV2PeerProgressState{}); err != nil {
		t.Fatal(err)
	}
	if progressCalls != 0 {
		t.Fatalf("terminal progress calls = %d, want 0", progressCalls)
	}
}

func TestExternalV2OfferFinishSendStreamClosesInvalidCompletion(t *testing.T) {
	rt := &externalV2OfferRuntime{}
	endpoint := &recordingExternalV2Endpoint{}

	err := rt.finishSendStream(
		context.Background(),
		endpoint,
		externalV2Complete{BytesReceived: -1},
		newExternalTransferMetrics(time.Unix(1, 0)),
		&externalV2PeerProgressState{},
	)
	if err == nil {
		t.Fatal("finishSendStream() error = nil, want invalid completion error")
	}
	if endpoint.closeCode != 1 || endpoint.closeReason == "" {
		t.Fatalf("endpoint close = (%d, %q), want error close", endpoint.closeCode, endpoint.closeReason)
	}
}

func TestRecordExternalV2CompletionUsesExactPeerProgressWithoutDuplicate(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	var got [][2]int64
	callback := func(bytesReceived, transferElapsedMS int64) {
		got = append(got, [2]int64{bytesReceived, transferElapsedMS})
	}
	externalPeerProgressConsumer(metrics, recordExternalV2PeerProgress(state, callback))(
		*newPeerProgress(1024, 750, 1),
		time.Unix(2, 0),
	)

	err := recordExternalV2Completion(
		context.Background(),
		externalV2Complete{BytesReceived: 1024},
		metrics,
		state,
		callback,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][2]int64{{1024, 750}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("progress = %#v, want %#v", got, want)
	}
	if snapshot := metrics.PeerProgressSnapshot(); snapshot.BytesReceived != 1024 || snapshot.TransferElapsedMS != 750 {
		t.Fatalf("metrics progress = %#v, want bytes=1024 elapsed=750", snapshot)
	}
}

func TestRecordExternalV2CompletionWaitsForFinalPeerProgress(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	var got [][2]int64
	callback := func(bytesReceived, transferElapsedMS int64) {
		got = append(got, [2]int64{bytesReceived, transferElapsedMS})
	}
	consume := externalPeerProgressConsumer(metrics, recordExternalV2PeerProgress(state, callback))
	consume(*newPeerProgress(512, 625, 1), time.Unix(2, 0))
	completionStarted := make(chan struct{})
	completionDone := make(chan error, 1)
	go func() {
		close(completionStarted)
		completionDone <- recordExternalV2Completion(
			context.Background(),
			externalV2Complete{BytesReceived: 1024},
			metrics,
			state,
			callback,
			time.Second,
		)
	}()
	<-completionStarted
	waitDeadline := time.After(250 * time.Millisecond)
	for {
		state.mu.Lock()
		waitingForFinal := state.changed != nil
		state.mu.Unlock()
		if waitingForFinal {
			break
		}
		select {
		case <-waitDeadline:
			t.Fatal("completion did not begin waiting for final peer progress")
		default:
			runtime.Gosched()
		}
	}
	consume(*newPeerProgress(1024, 750, 2), time.Unix(3, 0))

	if err := <-completionDone; err != nil {
		t.Fatal(err)
	}
	if want := [][2]int64{{512, 625}, {1024, 750}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("progress = %#v, want %#v", got, want)
	}
	if snapshot := metrics.PeerProgressSnapshot(); snapshot.BytesReceived != 1024 || snapshot.TransferElapsedMS != 750 {
		t.Fatalf("metrics progress = %#v, want bytes=1024 elapsed=750", snapshot)
	}
}

func TestRecordExternalV2CompletionWaitsBrieflyForFirstExactPeerProgress(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	var got [][2]int64
	callback := func(bytesReceived, transferElapsedMS int64) {
		got = append(got, [2]int64{bytesReceived, transferElapsedMS})
	}
	consume := externalPeerProgressConsumer(metrics, recordExternalV2PeerProgress(state, callback))
	completionStarted := make(chan struct{})
	completionDone := make(chan error, 1)
	go func() {
		close(completionStarted)
		completionDone <- recordExternalV2Completion(
			context.Background(),
			externalV2Complete{BytesReceived: 1024},
			metrics,
			state,
			callback,
			time.Second,
		)
	}()
	<-completionStarted

	completedBeforeProgress := false
	waitDeadline := time.After(time.Second)
	for {
		select {
		case err := <-completionDone:
			if err != nil {
				t.Fatal(err)
			}
			completedBeforeProgress = true
		default:
			state.mu.Lock()
			waitingForFirstProgress := state.changed != nil
			state.mu.Unlock()
			if waitingForFirstProgress {
				goto deliverProgress
			}
			select {
			case <-waitDeadline:
				t.Fatal("completion neither returned nor waited for first exact progress")
			default:
				runtime.Gosched()
			}
		}
		if completedBeforeProgress {
			break
		}
	}

deliverProgress:
	consume(*newPeerProgress(1024, 750, 1), time.Unix(2, 0))
	if !completedBeforeProgress {
		if err := <-completionDone; err != nil {
			t.Fatal(err)
		}
	}
	if completedBeforeProgress {
		t.Fatalf("completion skipped the no-prior grace and discarded delayed exact progress: %#v", got)
	}
	if want := [][2]int64{{1024, 750}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("progress = %#v, want %#v", got, want)
	}
}

func TestExternalV2CompletionProgressWaitUsesHalfIntervalWithoutPriorSample(t *testing.T) {
	got := externalV2CompletionProgressWait(
		1024,
		externalPeerProgressSnapshot{},
		externalPeerProgressSnapshot{},
		2*time.Second,
	)
	if want := peerProgressInterval / 2; got != want {
		t.Fatalf("no-prior completion wait = %s, want %s", got, want)
	}

	got = externalV2CompletionProgressWait(
		1024,
		externalPeerProgressSnapshot{BytesReceived: 512, TransferElapsedMS: 500, Set: true},
		externalPeerProgressSnapshot{BytesReceived: 512, TransferElapsedMS: 500, Set: true},
		2*time.Second,
	)
	if got != 2*time.Second {
		t.Fatalf("positive-partial completion wait = %s, want 2s", got)
	}
}

func TestRecordExternalV2CompletionFallsBackToLastPositivePeerElapsed(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	var got [][2]int64
	callback := func(bytesReceived, transferElapsedMS int64) {
		got = append(got, [2]int64{bytesReceived, transferElapsedMS})
	}
	externalPeerProgressConsumer(metrics, recordExternalV2PeerProgress(state, callback))(
		*newPeerProgress(512, 625, 1),
		time.Unix(2, 0),
	)

	if err := recordExternalV2Completion(
		context.Background(),
		externalV2Complete{BytesReceived: 1024},
		metrics,
		state,
		callback,
		0,
	); err != nil {
		t.Fatal(err)
	}
	recordExternalV2PeerProgress(state, callback)(1024, 750)

	if want := [][2]int64{{512, 625}, {1024, 625}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("progress including late final sample = %#v, want %#v", got, want)
	}
	if snapshot := metrics.PeerProgressSnapshot(); snapshot.BytesReceived != 1024 || snapshot.TransferElapsedMS != 625 {
		t.Fatalf("metrics progress = %#v, want bytes=1024 elapsed=625", snapshot)
	}
}

func TestRecordExternalV2CompletionDoesNotPublishWithoutPositiveElapsed(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	var progressCalls int

	if err := recordExternalV2Completion(context.Background(), externalV2Complete{BytesReceived: 1024}, metrics, state, func(int64, int64) {
		progressCalls++
	}, 0); err != nil {
		t.Fatal(err)
	}
	if progressCalls != 0 {
		t.Fatalf("zero-elapsed completion callbacks = %d, want 0", progressCalls)
	}
	if snapshot := metrics.PeerProgressSnapshot(); snapshot.BytesReceived != 1024 || snapshot.TransferElapsedMS != 0 {
		t.Fatalf("metrics progress = %#v, want exact bytes without elapsed", snapshot)
	}
}

func TestRecordExternalV2CompletionRejectsNegativeBytes(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	var progressCalls int

	if err := recordExternalV2Completion(context.Background(), externalV2Complete{BytesReceived: -1}, metrics, state, func(int64, int64) {
		progressCalls++
	}, 0); err == nil {
		t.Fatal("recordExternalV2Completion() error = nil, want invalid bytes error")
	}
	if progressCalls != 0 {
		t.Fatalf("invalid completion callbacks = %d, want 0", progressCalls)
	}
	if snapshot := metrics.PeerProgressSnapshot(); snapshot.Set {
		t.Fatalf("invalid completion changed metrics: %#v", snapshot)
	}
}

func TestRecordExternalV2CompletionWaitIsContextCancelableWithBlockedCallback(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	progressDone := make(chan struct{})
	go func() {
		recordExternalV2PeerProgress(state, func(int64, int64) {
			close(callbackEntered)
			<-releaseCallback
		})(1024, 750)
		close(progressDone)
	}()
	<-callbackEntered

	ctx, cancel := context.WithCancel(context.Background())
	completionDone := make(chan error, 1)
	go func() {
		completionDone <- recordExternalV2Completion(
			ctx,
			externalV2Complete{BytesReceived: 1024},
			metrics,
			state,
			func(int64, int64) {},
			time.Second,
		)
	}()
	cancel()
	select {
	case err := <-completionDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("completion error = %v, want context canceled", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("completion wait did not stop after context cancellation")
	}
	close(releaseCallback)
	select {
	case <-progressDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("blocked progress callback did not return after release")
	}
}

func TestRecordExternalV2CompletionBoundsBlockedCallbackWait(t *testing.T) {
	metrics := newExternalTransferMetrics(time.Unix(1, 0))
	state := &externalV2PeerProgressState{}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	progressDone := make(chan struct{})
	go func() {
		recordExternalV2PeerProgress(state, func(int64, int64) {
			close(callbackEntered)
			<-releaseCallback
		})(1024, 750)
		close(progressDone)
	}()
	<-callbackEntered

	completionDone := make(chan error, 1)
	go func() {
		completionDone <- recordExternalV2Completion(
			context.Background(),
			externalV2Complete{BytesReceived: 1024},
			metrics,
			state,
			func(int64, int64) {},
			25*time.Millisecond,
		)
	}()
	var completionErr error
	bounded := true
	select {
	case completionErr = <-completionDone:
	case <-time.After(250 * time.Millisecond):
		bounded = false
	}
	close(releaseCallback)
	<-progressDone
	if !bounded {
		completionErr = <-completionDone
		t.Fatalf("completion ignored its callback wait bound; eventual error = %v", completionErr)
	}
	if !errors.Is(completionErr, context.DeadlineExceeded) {
		t.Fatalf("completion error = %v, want deadline exceeded", completionErr)
	}
}

func TestRecordExternalV2PeerProgressCallbackCanReadState(t *testing.T) {
	state := &externalV2PeerProgressState{}
	got := make(chan int64, 1)
	done := make(chan struct{})
	go func() {
		recordExternalV2PeerProgress(state, func(int64, int64) {
			got <- state.BytesReceived()
		})(512, 500)
		close(done)
	}()

	select {
	case bytesReceived := <-got:
		if bytesReceived != 512 {
			t.Fatalf("callback state bytes = %d, want 512", bytesReceived)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("progress callback deadlocked while reading state")
	}
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("progress publisher did not return after reentrant callback")
	}
}
