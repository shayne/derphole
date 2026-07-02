// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
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
	bytesReceived     atomic.Int64
	transferElapsedMS atomic.Int64
}

func (s *externalV2PeerProgressState) Record(bytesReceived int64, transferElapsedMS int64) {
	if s == nil {
		return
	}
	s.bytesReceived.Store(bytesReceived)
	s.transferElapsedMS.Store(transferElapsedMS)
}

func (s *externalV2PeerProgressState) BytesReceived() int64 {
	if s == nil {
		return 0
	}
	return s.bytesReceived.Load()
}

func recordExternalV2PeerProgress(state *externalV2PeerProgressState, next func(int64, int64)) func(int64, int64) {
	return func(bytesReceived int64, transferElapsedMS int64) {
		if state != nil {
			state.Record(bytesReceived, transferElapsedMS)
		}
		if next != nil {
			next(bytesReceived, transferElapsedMS)
		}
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

func sendPeerProgressLoop(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth) {
	ticker := time.NewTicker(peerProgressInterval)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case now := <-ticker.C:
			sequence = sendPeerProgressSnapshot(ctx, client, peerDERP, bytesReceived, firstByteAt, auth, sequence, now)
		case <-ctx.Done():
			finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), peerProgressFinalTimeout)
			_ = sendPeerProgressSnapshot(finalCtx, client, peerDERP, bytesReceived, firstByteAt, auth, sequence, time.Now())
			cancel()
			return
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
