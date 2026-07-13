// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux

package derphole

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestReceiveBlockFileSinkMapsDirectDestination(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "direct-receive-*")
	if err != nil {
		t.Fatal(err)
	}
	const size = 64 << 10
	sink, err := newReceiveBlockFileSink(file, size, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x6d}, size)
	buffer := sink.DirectWriteBuffer()
	if len(buffer) != size {
		t.Fatalf("direct buffer length = %d, want %d", len(buffer), size)
	}
	if !sink.whole || sink.prepared != size {
		t.Fatalf("small direct file was not fully prepared: whole=%t prepared=%d", sink.whole, sink.prepared)
	}
	copy(buffer, payload)
	if err := sink.CommitDirectWrite(len(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("mapped receive payload was not persisted")
	}
}

func TestReceiveBlockFilePreparationStaysMemoryBounded(t *testing.T) {
	const maximumResidentPreparation = int64(96 << 20)
	if receiveBlockFilePrepareInitial > maximumResidentPreparation {
		t.Fatalf("initial receive-file preparation = %d, want at most %d", receiveBlockFilePrepareInitial, maximumResidentPreparation)
	}
	if receiveBlockFilePrepareWholeMax > maximumResidentPreparation {
		t.Fatalf("whole-file preparation limit = %d, want at most %d", receiveBlockFilePrepareWholeMax, maximumResidentPreparation)
	}
}

func TestReceiveBlockFileWindowAdvancesOutsideCommitPath(t *testing.T) {
	prepareStarted := make(chan struct{})
	allowPrepare := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var prepared, released [][2]int64
	window := newReceiveBlockFileWindow(
		512<<20,
		96<<20,
		func(start, end int64) error {
			once.Do(func() {
				close(prepareStarted)
				<-allowPrepare
			})
			mu.Lock()
			prepared = append(prepared, [2]int64{start, end})
			mu.Unlock()
			return nil
		},
		func(start, end int64) error {
			mu.Lock()
			released = append(released, [2]int64{start, end})
			mu.Unlock()
			return nil
		},
	)
	window.request(64 << 20)
	select {
	case <-prepareStarted:
	case <-time.After(time.Second):
		t.Fatal("background prepare did not start")
	}

	requestReturned := make(chan struct{})
	go func() {
		window.request(320 << 20)
		close(requestReturned)
	}()
	select {
	case <-requestReturned:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("window request blocked behind memory advice")
	}
	close(allowPrepare)
	deadline := time.Now().Add(time.Second)
	for {
		preparedEnd, releasedEnd := window.state()
		if preparedEnd >= 416<<20 && releasedEnd >= 256<<20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("window state = prepared %d released %d, want at least 416/256 MiB", preparedEnd, releasedEnd)
		}
		time.Sleep(time.Millisecond)
	}
	if err := window.close(); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(prepared) == 0 || prepared[len(prepared)-1][1] < 416<<20 {
		t.Fatalf("prepared ranges = %v, want coalesced preparation through at least 416 MiB", prepared)
	}
	for _, span := range prepared {
		if span[1]-span[0] > receiveBlockFileAdviceChunk {
			t.Fatalf("prepared range = %v, want chunks no larger than %d", span, receiveBlockFileAdviceChunk)
		}
	}
	if len(released) == 0 || released[len(released)-1][1] < 256<<20 {
		t.Fatalf("released ranges = %v, want reclamation through at least 256 MiB", released)
	}
	for _, span := range released {
		if span[1]-span[0] > receiveBlockFileAdviceChunk {
			t.Fatalf("released range = %v, want chunks no larger than %d", span, receiveBlockFileAdviceChunk)
		}
	}
}

func TestReceiveBlockFileWindowReportsBackgroundFailure(t *testing.T) {
	wantErr := errors.New("prepare failed")
	window := newReceiveBlockFileWindow(
		512<<20,
		96<<20,
		func(int64, int64) error { return wantErr },
		func(int64, int64) error { return nil },
	)
	window.request(64 << 20)
	deadline := time.Now().Add(time.Second)
	for !errors.Is(window.err(), wantErr) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := window.close(); !errors.Is(err, wantErr) {
		t.Fatalf("close error = %v, want %v", err, wantErr)
	}
}

func TestReceiveBlockFileWindowReleasesBeforePreparing(t *testing.T) {
	var mu sync.Mutex
	var events []string
	window := newReceiveBlockFileWindow(
		512<<20,
		256<<20,
		func(int64, int64) error {
			mu.Lock()
			events = append(events, "prepare")
			mu.Unlock()
			return nil
		},
		func(int64, int64) error {
			mu.Lock()
			events = append(events, "release")
			mu.Unlock()
			return nil
		},
	)
	window.request(240 << 20)
	deadline := time.Now().Add(time.Second)
	for {
		preparedEnd, releasedEnd := window.state()
		if preparedEnd >= 336<<20 && releasedEnd >= 176<<20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("window state = prepared %d released %d, want at least 336/176 MiB", preparedEnd, releasedEnd)
		}
		time.Sleep(time.Millisecond)
	}
	if err := window.close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	firstRelease, firstPrepare := -1, -1
	for index, event := range events {
		if event == "release" && firstRelease < 0 {
			firstRelease = index
		}
		if event == "prepare" && firstPrepare < 0 {
			firstPrepare = index
		}
	}
	if firstRelease < 0 || firstPrepare < 0 || firstRelease > firstPrepare {
		t.Fatalf("memory advice order = %v, want release before prepare", events)
	}
}
