// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/types/key"
)

const (
	peerProgressInterval          = 500 * time.Millisecond
	peerProgressFinalTimeout      = 2 * time.Second
	peerProgressWatcherStopWait   = time.Second
	externalTestRelayPlaintextEnv = "DERPHOLE_TEST_RELAY_PLAINTEXT_MARKER"
)

type externalV2PeerProgressState struct {
	mu                sync.Mutex
	bytesReceived     int64
	transferElapsedMS int64
	set               bool
	completed         bool
	changed           chan struct{}
	lastPublished     chan struct{}
}

func (s *externalV2PeerProgressState) Record(bytesReceived int64, transferElapsedMS int64) {
	s.recordIfOpen(bytesReceived, transferElapsedMS)
}

func (s *externalV2PeerProgressState) recordIfOpen(bytesReceived int64, transferElapsedMS int64) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return false
	}
	s.bytesReceived = bytesReceived
	s.transferElapsedMS = transferElapsedMS
	s.set = true
	s.notifyChangedLocked()
	return true
}

func (s *externalV2PeerProgressState) recordAndPublish(bytesReceived int64, transferElapsedMS int64, progress func(int64, int64)) {
	if s == nil {
		if progress != nil {
			progress(bytesReceived, transferElapsedMS)
		}
		return
	}
	s.mu.Lock()
	if s.completed {
		s.mu.Unlock()
		return
	}
	s.bytesReceived = bytesReceived
	s.transferElapsedMS = transferElapsedMS
	s.set = true
	s.notifyChangedLocked()
	if progress == nil {
		s.mu.Unlock()
		return
	}
	previous := s.lastPublishedLocked()
	done := make(chan struct{})
	s.lastPublished = done
	s.mu.Unlock()
	<-previous
	defer close(done)
	progress(bytesReceived, transferElapsedMS)
}

func (s *externalV2PeerProgressState) completeAndPublish(ctx context.Context, bytesReceived int64, transferElapsedMS int64, progress func(int64, int64)) error {
	if s == nil {
		if progress == nil || transferElapsedMS <= 0 {
			return nil
		}
		return invokeExternalV2Progress(ctx, progress, bytesReceived, transferElapsedMS)
	}
	publication, ok := s.prepareCompletionPublication(bytesReceived, transferElapsedMS, progress != nil)
	if !ok {
		return nil
	}
	if err := waitExternalV2ProgressPublished(ctx, publication.previous); err != nil {
		if publication.done != nil {
			close(publication.done)
		}
		return err
	}
	if publication.done == nil {
		return nil
	}
	go func() {
		progress(bytesReceived, transferElapsedMS)
		close(publication.done)
	}()
	return waitExternalV2ProgressPublished(ctx, publication.done)
}

type externalV2ProgressPublication struct {
	previous <-chan struct{}
	done     chan struct{}
}

func (s *externalV2PeerProgressState) prepareCompletionPublication(bytesReceived int64, transferElapsedMS int64, hasProgress bool) (externalV2ProgressPublication, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return externalV2ProgressPublication{}, false
	}
	alreadyPublished := s.set && s.bytesReceived >= bytesReceived && s.transferElapsedMS > 0
	s.bytesReceived = bytesReceived
	s.transferElapsedMS = transferElapsedMS
	s.set = true
	s.completed = true
	s.notifyChangedLocked()
	publication := externalV2ProgressPublication{previous: s.lastPublishedLocked()}
	if !hasProgress || transferElapsedMS <= 0 || alreadyPublished {
		return publication, true
	}
	publication.done = make(chan struct{})
	s.lastPublished = publication.done
	return publication, true
}

func (s *externalV2PeerProgressState) BytesReceived() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytesReceived
}

func (s *externalV2PeerProgressState) snapshot() externalPeerProgressSnapshot {
	if s == nil {
		return externalPeerProgressSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return externalPeerProgressSnapshot{
		BytesReceived:     s.bytesReceived,
		TransferElapsedMS: s.transferElapsedMS,
		Set:               s.set,
	}
}

func (s *externalV2PeerProgressState) waitForExact(ctx context.Context, bytesReceived int64) (externalPeerProgressSnapshot, error) {
	if s == nil {
		return externalPeerProgressSnapshot{}, nil
	}
	for {
		s.mu.Lock()
		snapshot := externalPeerProgressSnapshot{
			BytesReceived:     s.bytesReceived,
			TransferElapsedMS: s.transferElapsedMS,
			Set:               s.set,
		}
		if snapshot.BytesReceived >= bytesReceived && snapshot.TransferElapsedMS > 0 {
			s.mu.Unlock()
			return snapshot, nil
		}
		if s.changed == nil {
			s.changed = make(chan struct{})
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return snapshot, ctx.Err()
		}
	}
}

func (s *externalV2PeerProgressState) notifyChangedLocked() {
	if s.changed != nil {
		close(s.changed)
		s.changed = make(chan struct{})
	}
}

func (s *externalV2PeerProgressState) lastPublishedLocked() <-chan struct{} {
	if s.lastPublished == nil {
		done := make(chan struct{})
		close(done)
		s.lastPublished = done
	}
	return s.lastPublished
}

func recordExternalV2PeerProgress(state *externalV2PeerProgressState, next func(int64, int64)) func(int64, int64) {
	return func(bytesReceived int64, transferElapsedMS int64) {
		state.recordAndPublish(bytesReceived, transferElapsedMS, next)
	}
}

func recordExternalV2Completion(ctx context.Context, complete externalV2Complete, metrics *externalTransferMetrics, state *externalV2PeerProgressState, progress func(int64, int64), wait time.Duration) error {
	if complete.BytesReceived < 0 {
		return fmt.Errorf("invalid v2 complete bytes %d", complete.BytesReceived)
	}
	stateSnapshot, metricsSnapshot, err := externalV2CompletionProgressSnapshots(ctx, complete.BytesReceived, metrics, state, wait)
	if err != nil {
		return err
	}
	transferElapsedMS := externalV2CompletionElapsed(complete.BytesReceived, stateSnapshot, metricsSnapshot)
	metrics.RecordPeerProgress(complete.BytesReceived, transferElapsedMS, time.Now())
	publishCtx, cancelPublish := externalV2CompletionPublishContext(ctx, wait)
	defer cancelPublish()
	return state.completeAndPublish(publishCtx, complete.BytesReceived, transferElapsedMS, progress)
}

func externalV2CompletionProgressSnapshots(ctx context.Context, bytesReceived int64, metrics *externalTransferMetrics, state *externalV2PeerProgressState, wait time.Duration) (externalPeerProgressSnapshot, externalPeerProgressSnapshot, error) {
	stateSnapshot := state.snapshot()
	metricsSnapshot := metrics.PeerProgressSnapshot()
	progressWait := externalV2CompletionProgressWait(bytesReceived, stateSnapshot, metricsSnapshot, wait)
	if progressWait <= 0 {
		return stateSnapshot, metricsSnapshot, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, progressWait)
	stateSnapshot, _ = state.waitForExact(waitCtx, bytesReceived)
	cancel()
	if ctx.Err() != nil {
		return stateSnapshot, metricsSnapshot, ctx.Err()
	}
	return stateSnapshot, metrics.PeerProgressSnapshot(), nil
}

func externalV2CompletionProgressWait(bytesReceived int64, stateSnapshot, metricsSnapshot externalPeerProgressSnapshot, wait time.Duration) time.Duration {
	if wait <= 0 || stateSnapshot.BytesReceived >= bytesReceived {
		return 0
	}
	if stateSnapshot.TransferElapsedMS > 0 || metricsSnapshot.TransferElapsedMS > 0 {
		return wait
	}
	return min(wait, peerProgressInterval/2)
}

func externalV2CompletionElapsed(bytesReceived int64, stateSnapshot, metricsSnapshot externalPeerProgressSnapshot) int64 {
	if stateSnapshot.BytesReceived >= bytesReceived && stateSnapshot.TransferElapsedMS > 0 {
		return stateSnapshot.TransferElapsedMS
	}
	return metricsSnapshot.TransferElapsedMS
}

func externalV2CompletionPublishContext(ctx context.Context, wait time.Duration) (context.Context, context.CancelFunc) {
	if wait > 0 {
		return context.WithTimeout(ctx, wait)
	}
	return ctx, func() {}
}

func invokeExternalV2Progress(ctx context.Context, progress func(int64, int64), bytesReceived int64, transferElapsedMS int64) error {
	done := make(chan struct{})
	go func() {
		progress(bytesReceived, transferElapsedMS)
		close(done)
	}()
	return waitExternalV2ProgressPublished(ctx, done)
}

func waitExternalV2ProgressPublished(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func externalPeerProgressConsumer(metrics *externalTransferMetrics, callback func(int64, int64)) func(peerProgress, time.Time) {
	return func(progress peerProgress, at time.Time) {
		if metrics != nil {
			metrics.RecordPeerProgress(progress.BytesReceived, progress.TransferElapsedMS, at)
		}
		if callback != nil {
			callback(progress.BytesReceived, progress.TransferElapsedMS)
		}
	}
}

func peerProgressForTransfer(bytesReceived int64, firstByteAt time.Time, now time.Time, sequence uint64) peerProgress {
	var elapsedMS int64
	if !firstByteAt.IsZero() && now.After(firstByteAt) {
		elapsedMS = now.Sub(firstByteAt).Milliseconds()
	}
	return *newPeerProgress(bytesReceived, elapsedMS, sequence)
}

type externalV2PeerProgressSender struct {
	cancel      context.CancelFunc
	done        <-chan uint64
	client      *derpbind.Client
	peerDERP    key.NodePublic
	firstByteAt func() time.Time
	auth        externalPeerControlAuth
}

func startExternalV2PeerProgressSender(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth) *externalV2PeerProgressSender {
	progressCtx, cancel := context.WithCancel(ctx)
	done := make(chan uint64, 1)
	go func() {
		done <- sendPeerProgressLoop(progressCtx, client, peerDERP, bytesReceived, firstByteAt, auth)
	}()
	return &externalV2PeerProgressSender{
		cancel:      cancel,
		done:        done,
		client:      client,
		peerDERP:    peerDERP,
		firstByteAt: firstByteAt,
		auth:        auth,
	}
}

func (s *externalV2PeerProgressSender) Stop() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}

func (s *externalV2PeerProgressSender) Complete(ctx context.Context, bytesReceived int64) error {
	if s == nil {
		return nil
	}
	s.Stop()
	var sequence uint64
	select {
	case sequence = <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	firstByteAt := time.Time{}
	if s.firstByteAt != nil {
		firstByteAt = s.firstByteAt()
	}
	progress := peerProgressForTransfer(bytesReceived, firstByteAt, time.Now(), sequence+1)
	if progress.TransferElapsedMS <= 0 {
		return nil
	}
	return sendPeerProgress(ctx, s.client, s.peerDERP, progress.BytesReceived, progress.TransferElapsedMS, progress.Sequence, s.auth)
}

func sendPeerProgressLoop(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth) uint64 {
	ticker := time.NewTicker(peerProgressInterval)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case now := <-ticker.C:
			sequence = sendPeerProgressSnapshot(ctx, client, peerDERP, bytesReceived, firstByteAt, auth, sequence, now)
		case <-ctx.Done():
			return sequence
		}
	}
}

func sendPeerProgressSnapshot(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth, sequence uint64, now time.Time) uint64 {
	if firstByteAt == nil {
		return sequence
	}
	firstByte := firstByteAt()
	if firstByte.IsZero() {
		return sequence
	}
	sequence++
	var received int64
	if bytesReceived != nil {
		received = bytesReceived()
	}
	progress := peerProgressForTransfer(received, firstByte, now, sequence)
	_ = sendPeerProgress(ctx, client, peerDERP, progress.BytesReceived, progress.TransferElapsedMS, progress.Sequence, auth)
	return sequence
}

func watchPeerProgress(ctx context.Context, ch <-chan derpbind.Packet, auth externalPeerControlAuth, consume func(peerProgress, time.Time)) error {
	var lastSequence uint64
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return net.ErrClosed
			}
			progress, handled, err := verifyPeerProgressPacket(pkt, auth, &lastSequence)
			if handled {
				continue
			}
			if err != nil {
				return err
			}
			if consume != nil {
				consume(progress, time.Now())
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func startPeerProgressWatcher(ctx context.Context, progressCh <-chan derpbind.Packet, auth externalPeerControlAuth, metrics *externalTransferMetrics, progress func(int64, int64), emitter *telemetry.Emitter) func() {
	progressCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	consume := externalPeerProgressConsumer(metrics, progress)
	go func() {
		done <- watchPeerProgress(progressCtx, progressCh, auth, consume)
	}()
	return func() {
		cancel()
		select {
		case err := <-done:
			emitPeerProgressWatcherStopDebug(emitter, err)
		case <-time.After(peerProgressWatcherStopWait):
			if emitter != nil {
				emitter.Debug("udp-peer-progress-watch-stop-timeout")
			}
		}
	}
}

func emitPeerProgressWatcherStopDebug(emitter *telemetry.Emitter, err error) {
	if emitter == nil || err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	emitter.Debug("udp-peer-progress-watch-error=" + err.Error())
}

func externalAssertNoPlaintextRelayMarker(payload []byte) error {
	marker := os.Getenv(externalTestRelayPlaintextEnv)
	if marker == "" {
		return nil
	}
	if strings.Contains(string(payload), marker) {
		return errors.New("relay payload contains plaintext marker")
	}
	return nil
}
