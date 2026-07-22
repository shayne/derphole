// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"golang.org/x/time/rate"
	"tailscale.com/types/key"
)

const (
	externalV2BulkPacketPayloadSize      = 1358
	externalV2BulkPacketMaxSize          = 1400
	externalV2BulkPacketHeaderSize       = 26
	externalV2BulkPacketHelloWait        = 2 * time.Second
	externalV2BulkPacketRepairWait       = 30 * time.Second
	externalV2BulkPacketReadIdle         = 100 * time.Millisecond
	externalV2BulkPacketRepairSkip       = 250 * time.Millisecond
	externalV2BulkPacketDoneRepeats      = 5
	externalV2BulkPacketMaxMissing       = 300
	externalV2BulkPacketMissingLookahead = 4096
	// Buffer one authenticated direct receive window in user space so the lane
	// lane readers can keep draining their sockets while decrypt and disk writes
	// briefly fall behind. Keep this below 40 MiB on memory-constrained peers.
	externalV2BulkPacketDataQueue         = 24576
	externalV2BulkPacketReceiveBatchQueue = externalV2BulkPacketDataQueue / externalV2BulkPacketMaxBatch
	externalV2BulkPacketRepairQueue       = 1024
	externalV2BulkPacketReceiveGroupBytes = 64 << 10
	// Keep at most 36 MiB of incomplete async group payload resident. That covers
	// the authenticated 32 MiB sender window plus one concurrent batch per lane.
	// Older sparse groups still spill so actual loss cannot retain one group for
	// every chunk in a large file.
	externalV2BulkPacketReceiveGroupBudget = 36 << 20
	externalV2BulkPacketReceiveGroupLimit  = externalV2BulkPacketReceiveGroupBudget / externalV2BulkPacketWriteGroup
	externalV2BulkPacketWriteRetryDelay    = 100 * time.Microsecond
	externalV2BulkPacketMaximumNonceSize   = 24
	externalV2BulkPacketPrimaryRepairDelay = 25 * time.Millisecond
	externalV2BulkPacketPrimaryDoneRepeats = 3
)

const (
	externalV2BulkPacketData            byte = 1
	externalV2BulkPacketMiss            byte = 2
	externalV2BulkPacketDone            byte = 3
	externalV2BulkPacketHello           byte = 4
	externalV2BulkPacketProbeData       byte = 5
	externalV2BulkPacketAck             byte = 8
	externalV2BulkPacketPrimaryComplete byte = 9
	externalV2BulkPacketProbeTaggedData byte = 11
)

const externalV2BulkPacketAckInterval = 25 * time.Millisecond

var (
	externalV2BulkPacketMagic       = [4]byte{'D', 'V', '2', 'B'}
	externalV2BulkPacketAEADDomain  = []byte("derphole-v2-bulk-packet-aead-v2")
	externalV2BulkPacketPayloadPool = newExternalV2BulkPacketSyncPayloadPool()
)

type externalV2BulkPacketPayloadBuffer struct {
	data []byte
}

type externalV2BulkPacketPayloadBufferRecycler interface {
	get() *externalV2BulkPacketPayloadBuffer
	put(*externalV2BulkPacketPayloadBuffer)
}

type externalV2BulkPacketSyncPayloadPool struct {
	pool sync.Pool
}

func newExternalV2BulkPacketSyncPayloadPool() *externalV2BulkPacketSyncPayloadPool {
	pool := &externalV2BulkPacketSyncPayloadPool{}
	pool.pool.New = func() any {
		return &externalV2BulkPacketPayloadBuffer{
			data: make([]byte, 0, externalV2BulkPacketPayloadSize),
		}
	}
	return pool
}

func (p *externalV2BulkPacketSyncPayloadPool) get() *externalV2BulkPacketPayloadBuffer {
	buffer := p.pool.Get().(*externalV2BulkPacketPayloadBuffer)
	buffer.data = buffer.data[:0]
	return buffer
}

func (p *externalV2BulkPacketSyncPayloadPool) put(buffer *externalV2BulkPacketPayloadBuffer) {
	if buffer == nil {
		return
	}
	buffer.data = buffer.data[:0]
	p.pool.Put(buffer)
}

type externalV2BulkPacketPath struct {
	Conns []net.PacketConn
	Addrs []net.Addr
}

func externalV2BulkPacketPathFromRaw(path externalV2DirectPacketPath) externalV2BulkPacketPath {
	return externalV2BulkPacketPath{
		Conns: append([]net.PacketConn(nil), path.conns...),
		Addrs: append([]net.Addr(nil), path.addrs...),
	}
}

type externalV2BulkPacketAuth struct {
	data    cipher.AEAD
	control cipher.AEAD
	grouped cipher.AEAD
	probe   cipher.Block
}

func (a externalV2BulkPacketAuth) withGrouped(enabled bool) externalV2BulkPacketAuth {
	if !enabled {
		a.grouped = nil
		a.probe = nil
	}
	return a
}

type externalV2BulkPacketHeader struct {
	kind    byte
	runID   uint64
	index   uint32
	total   uint32
	length  uint16
	payload []byte
}

type externalV2BulkPacketReceiveResult struct {
	header          externalV2BulkPacketHeader
	data            []byte
	direct          bool
	grouped         bool
	fragmentStart   uint32
	fragmentCount   uint32
	primaryComplete bool
	payloadBuffer   *externalV2BulkPacketPayloadBuffer
	payloadPool     externalV2BulkPacketPayloadBufferRecycler
	sealedBuffer    *externalV2BulkPacketSealedBuffer
	sealedPool      *sync.Pool
}

type externalV2BulkPacketReceiveAck struct {
	bytes  atomic.Int64
	window atomic.Int64
	set    atomic.Bool
}

func (a *externalV2BulkPacketReceiveAck) record(bytes, window int64) {
	if a == nil || bytes < 0 || window <= 0 || window > externalV2BulkPacketFallbackReceiveWindow {
		return
	}
	updateExternalV2BulkPacketAtomicMax(&a.bytes, bytes)
	a.window.Store(window)
	a.set.Store(true)
}

func (a *externalV2BulkPacketReceiveAck) snapshot() (int64, int64, bool) {
	if a == nil || !a.set.Load() {
		return 0, 0, false
	}
	return a.bytes.Load(), a.window.Load(), true
}

func (r *externalV2BulkPacketReceiveResult) release() {
	recycled := false
	if r.payloadBuffer != nil && r.payloadPool != nil {
		buffer := r.payloadBuffer
		pool := r.payloadPool
		r.payloadBuffer = nil
		r.payloadPool = nil
		pool.put(buffer)
		recycled = true
	}
	if r.sealedBuffer != nil && r.sealedPool != nil {
		buffer := r.sealedBuffer
		pool := r.sealedPool
		r.sealedBuffer = nil
		r.sealedPool = nil
		pool.Put(buffer)
		recycled = true
	}
	if recycled {
		r.data = nil
	}
}

func externalV2BulkPacketAuthForToken(tok token.Token, senderDERP key.NodePublic, receiverDERP key.NodePublic) (externalV2BulkPacketAuth, error) {
	data, err := externalV2BulkPacketAEAD(tok, senderDERP, receiverDERP, "data")
	if err != nil {
		return externalV2BulkPacketAuth{}, err
	}
	control, err := externalV2BulkPacketAEAD(tok, senderDERP, receiverDERP, "control")
	if err != nil {
		return externalV2BulkPacketAuth{}, err
	}
	grouped, err := externalV2BulkPacketAEADWithKeySize(tok, senderDERP, receiverDERP, "grouped-data-v1", 16)
	if err != nil {
		return externalV2BulkPacketAuth{}, err
	}
	probeKey := externalV2BulkPacketDerivedKey(tok, senderDERP, receiverDERP, "probe-tag-v1")
	probe, err := aes.NewCipher(probeKey[:16])
	if err != nil {
		return externalV2BulkPacketAuth{}, err
	}
	return externalV2BulkPacketAuth{data: data, control: control, grouped: grouped, probe: probe}, nil
}

func externalV2BulkPacketAEAD(tok token.Token, senderDERP key.NodePublic, receiverDERP key.NodePublic, label string) (cipher.AEAD, error) {
	return externalV2BulkPacketAEADWithKeySize(tok, senderDERP, receiverDERP, label, 32)
}

func externalV2BulkPacketAEADWithKeySize(tok token.Token, senderDERP key.NodePublic, receiverDERP key.NodePublic, label string, keySize int) (cipher.AEAD, error) {
	keyBytes := externalV2BulkPacketDerivedKey(tok, senderDERP, receiverDERP, label)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid bulk packet AES key size %d", keySize)
	}
	block, err := aes.NewCipher(keyBytes[:keySize])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func externalV2BulkPacketDerivedKey(tok token.Token, senderDERP key.NodePublic, receiverDERP key.NodePublic, label string) []byte {
	mac := hmac.New(sha256.New, tok.BearerSecret[:])
	mac.Write(externalV2BulkPacketAEADDomain)
	mac.Write(tok.SessionID[:])
	mac.Write(senderDERP.AppendTo(nil))
	mac.Write(receiverDERP.AppendTo(nil))
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

type externalV2BulkPacketTransferOptions struct {
	CapacityProbe bool
	Decision      *externalV2BulkDecisionCoordinator
}

func (o externalV2BulkPacketTransferOptions) validate() error {
	if o.CapacityProbe && o.Decision == nil {
		return errors.New("bulk capacity probe requires decision coordinator")
	}
	return nil
}

type externalV2BulkPacketDecisionContext struct {
	context.Context
	caller context.Context
}

func (c externalV2BulkPacketDecisionContext) Deadline() (time.Time, bool) {
	decisionDeadline, decisionOK := c.Context.Deadline()
	callerDeadline, callerOK := c.caller.Deadline()
	if !decisionOK || callerOK && callerDeadline.Before(decisionDeadline) {
		return callerDeadline, callerOK
	}
	return decisionDeadline, true
}

func (c externalV2BulkPacketDecisionContext) Value(key any) any {
	return c.caller.Value(key)
}

func externalV2BulkPacketContext(ctx context.Context, options externalV2BulkPacketTransferOptions) (context.Context, context.CancelCauseFunc, func() bool) {
	if !options.CapacityProbe {
		return ctx, func(error) {}, func() bool { return false }
	}
	parent := externalV2BulkPacketDecisionContext{Context: options.Decision.Context(), caller: ctx}
	linkedCtx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(ctx, func() {
		cancel(context.Cause(ctx))
	})
	return linkedCtx, cancel, stop
}

func sendExternalV2BulkBlockPackets(ctx context.Context, src *BlockSource, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics, options externalV2BulkPacketTransferOptions) (externalDirectTransferStats, error) {
	if err := options.validate(); err != nil {
		return externalDirectTransferStats{}, err
	}
	ctx, cancelTransfer, stopCallerLink := externalV2BulkPacketContext(ctx, options)
	defer func() {
		stopCallerLink()
		cancelTransfer(context.Canceled)
	}()
	if err := validateExternalV2BulkPacketSender(src, path, auth); err != nil {
		return externalDirectTransferStats{}, err
	}
	if err := metrics.SetFilePayloadLaneAddrs(path.Addrs, time.Now()); err != nil {
		return externalDirectTransferStats{}, err
	}

	sendCtx, cancel := context.WithCancel(ctx)
	sender := newExternalV2BulkPacketSender(sendCtx, src, path, auth, metrics)
	writeDeadlineDone := startExternalV2BulkPacketWriteDeadlineCancel(sendCtx, path)

	missingCh := make(chan []uint32, externalV2BulkPacketRepairQueue)
	doneCh := make(chan struct{}, 1)
	helloCh := make(chan struct{}, 1)
	workerErrCh := make(chan error, len(path.Conns)+1)
	controlDone := startExternalV2BulkPacketControlReaders(sendCtx, path, auth, sender.runID, sender.totalPackets, missingCh, doneCh, helloCh, workerErrCh, &sender.repairRequests, &sender.receiveAck)
	if err := waitExternalV2BulkPacketHello(ctx, helloCh, workerErrCh); err != nil {
		return cleanupExternalV2BulkPacketSenderBeforePayload(sender, cancel, writeDeadlineDone, controlDone, path, err)
	}
	if options.CapacityProbe {
		decision, probeErr, decisionErr := resolveExternalV2BulkPacketSenderDecision(sendCtx, sender, options.Decision)
		if decisionErr != nil {
			return cleanupExternalV2BulkPacketSenderBeforePayload(sender, cancel, writeDeadlineDone, controlDone, path, decisionErr)
		}
		metrics.SetBulkDecision(decision, time.Now())
		if decision.Mode == externalV2BulkModeQUIC {
			return cleanupExternalV2BulkPacketSenderForQUICFallback(
				sender, cancel, writeDeadlineDone, controlDone, path,
				externalV2BulkPacketSenderFallbackError(probeErr),
			)
		}
		sender.setInitialPaceMbps(decision.SelectedMbps)
		replaceExternalV2BulkPacketSenderBatchConns(sender, path)
	}
	metrics.SelectFilePayloadEngine(transfertrace.FilePayloadEngineBulk, time.Now())
	if err := enableExternalV2BulkPacketFixedPeers(path, sender.batchConns, sender.laneCount); err != nil {
		cancel()
		deadlineErr := <-writeDeadlineDone
		<-controlDone
		disarmExternalV2BulkPacketWriteCancellations(sender.batchConns)
		cleanupErr := clearExternalV2BulkPacketDeadlines(path)
		return sender.stats(false), errors.Join(err, deadlineErr, cleanupErr)
	}

	controllerDone := sender.startController(sendCtx)
	repairActivityCh := make(chan struct{}, 1)
	repairDone := sender.startRepairWorker(sendCtx, missingCh, repairActivityCh, workerErrCh)

	err := sender.sendInitialPacketsUntilWorkerFailure(sendCtx, cancel, workerErrCh)
	committed := false
	if err == nil {
		_ = sender.sendPrimaryCompleteRepeats()
		err = sender.waitForCompletion(doneCh, repairActivityCh, workerErrCh)
		committed = err == nil
	}
	cancel()
	deadlineErr := <-writeDeadlineDone
	<-controllerDone
	<-repairDone
	<-controlDone
	disarmExternalV2BulkPacketWriteCancellations(sender.batchConns)
	cleanupErr := clearExternalV2BulkPacketDeadlines(path)
	return sender.stats(committed), errors.Join(err, deadlineErr, cleanupErr, externalV2BulkPacketContextCause(ctx))
}

func resolveExternalV2BulkPacketSenderDecision(
	ctx context.Context,
	sender *externalV2BulkPacketSender,
	coordinator *externalV2BulkDecisionCoordinator,
) (decision externalV2BulkDecision, probeErr, err error) {
	probeResult, probeErr := sendExternalV2BulkPacketProbe(ctx, sender, coordinator)
	sender.probeResult = probeResult
	if externalV2BulkPacketProbeTestOutcomeInvalid(probeErr) {
		return decision, probeErr, probeErr
	}
	if probeFailure := externalV2BulkPacketProbeDecisionFailure(probeErr, false); probeFailure != nil {
		return decision, probeErr, probeFailure
	}
	decision, err = coordinator.ResolveSender(ctx, sender.runID, probeResult, probeErr)
	return decision, probeErr, err
}

func externalV2BulkPacketSenderFallbackError(probeErr error) error {
	if errors.Is(probeErr, errExternalV2BulkPacketProbeForcedSenderReject) {
		return errors.Join(errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject)
	}
	return errExternalV2BulkPacketProbeRejected
}

func replaceExternalV2BulkPacketSenderBatchConns(sender *externalV2BulkPacketSender, path externalV2BulkPacketPath) {
	disarmExternalV2BulkPacketWriteCancellations(sender.batchConns)
	for lane := range sender.batchConns {
		sender.batchConns[lane] = newExternalV2BulkPacketBatchConn(path.Conns[lane])
	}
}

func cleanupExternalV2BulkPacketSenderBeforePayload(
	sender *externalV2BulkPacketSender,
	cancel context.CancelFunc,
	writeDeadlineDone <-chan error,
	controlDone <-chan struct{},
	path externalV2BulkPacketPath,
	cause error,
) (externalDirectTransferStats, error) {
	disarmExternalV2BulkPacketWriteCancellations(sender.batchConns)
	cancel()
	deadlineErr := <-writeDeadlineDone
	<-controlDone
	cleanupErr := clearExternalV2BulkPacketDeadlines(path)
	return sender.stats(false), errors.Join(cause, deadlineErr, cleanupErr)
}

func cleanupExternalV2BulkPacketSenderForQUICFallback(
	sender *externalV2BulkPacketSender,
	cancel context.CancelFunc,
	writeDeadlineDone <-chan error,
	controlDone <-chan struct{},
	path externalV2BulkPacketPath,
	cause error,
) (externalDirectTransferStats, error) {
	disarmExternalV2BulkPacketWriteCancellations(sender.batchConns)
	cancel()
	deadlineErr := <-writeDeadlineDone
	<-controlDone
	drain, drainErr := externalV2BulkPacketDrainForHandoff(sender.ctx, path)
	sender.probeResult.HandoffDrain = drain
	return sender.stats(false), errors.Join(cause, deadlineErr, drainErr)
}

func externalV2BulkPacketContextCause(ctx context.Context) error {
	cause := context.Cause(ctx)
	if cause == nil || errors.Is(cause, context.Canceled) {
		return nil
	}
	return cause
}

func validateExternalV2BulkPacketSender(src *BlockSource, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth) error {
	if !validExternalV2BlockSource(src) {
		return errors.New("invalid block source")
	}
	if len(path.Conns) == 0 || len(path.Addrs) == 0 {
		return errors.New("no bulk packet path")
	}
	if auth.data == nil || auth.control == nil {
		return errors.New("bulk packet auth is not configured")
	}
	return nil
}

func startExternalV2BulkPacketWriteDeadlineCancel(ctx context.Context, path externalV2BulkPacketPath) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		<-ctx.Done()
		done <- interruptExternalV2BulkPacketWrites(path, time.Now())
	}()
	return done
}

func interruptExternalV2BulkPacketWrites(path externalV2BulkPacketPath, deadline time.Time) error {
	var errs []error
	for lane, conn := range path.Conns {
		writeErr := conn.SetWriteDeadline(deadline)
		if writeErr == nil {
			continue
		}
		deadlineErr := conn.SetDeadline(deadline)
		if deadlineErr == nil {
			continue
		}
		closeErr := conn.Close()
		errs = append(errs, fmt.Errorf("bulk packet lane %d could not interrupt writes: %w", lane, errors.Join(
			fmt.Errorf("set write deadline: %w", writeErr),
			fmt.Errorf("set generic deadline: %w", deadlineErr),
			wrapExternalV2BulkPacketCloseError(closeErr),
		)))
	}
	return errors.Join(errs...)
}

func clearExternalV2BulkPacketDeadlines(path externalV2BulkPacketPath) error {
	var errs []error
	for lane, conn := range path.Conns {
		if err := clearExternalV2BulkPacketConnDeadlines(conn); err != nil {
			errs = append(errs, fmt.Errorf("bulk packet lane %d deadline cleanup: %w", lane, err))
		}
	}
	return errors.Join(errs...)
}

func clearExternalV2BulkPacketConnDeadlines(conn net.PacketConn) error {
	zero := time.Time{}
	readErr := conn.SetReadDeadline(zero)
	writeErr := conn.SetWriteDeadline(zero)
	if readErr == nil && writeErr == nil {
		return nil
	}
	deadlineErr := conn.SetDeadline(zero)
	if deadlineErr == nil {
		return nil
	}
	closeErr := conn.Close()
	return errors.Join(
		wrapExternalV2BulkPacketDeadlineError("clear read deadline", readErr),
		wrapExternalV2BulkPacketDeadlineError("clear write deadline", writeErr),
		fmt.Errorf("clear generic deadline: %w", deadlineErr),
		wrapExternalV2BulkPacketCloseError(closeErr),
	)
}

func wrapExternalV2BulkPacketDeadlineError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func wrapExternalV2BulkPacketCloseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close connection: %w", err)
}

type externalV2BulkPacketSender struct {
	ctx                  context.Context
	src                  *BlockSource
	path                 externalV2BulkPacketPath
	batchConns           []externalV2BulkPacketBatchConn
	slabPool             externalV2BulkPacketSlabPool
	auth                 externalV2BulkPacketAuth
	metrics              *externalTransferMetrics
	initialPaceMbps      int
	runID                uint64
	totalPackets         uint32
	groupCount           uint32
	grouped              bool
	laneCount            int
	pacer                *rate.Limiter
	controller           *externalV2BulkPacketController
	sentPackets          atomic.Uint64
	sentPayload          atomic.Int64
	primaryPayloadBytes  atomic.Int64
	primaryWireBytes     atomic.Int64
	repairWireBytes      atomic.Int64
	repairPackets        atomic.Int64
	repairPayloadBytes   atomic.Int64
	repairRequests       atomic.Int64
	currentPaceMbps      atomic.Int64
	batchCryptoQueuePeak atomic.Uint32
	batchLaneQueuePeak   atomic.Uint32
	probeResult          externalV2BulkPacketProbeResult
	receiveAck           externalV2BulkPacketReceiveAck
	receiveWindowBlocked atomic.Bool
	ackNegotiationUntil  time.Time

	localENOBUFSRetries        atomic.Int64
	localENOBUFSWaitNanos      atomic.Int64
	localENOBUFSMaxConsecutive atomic.Int64
}

func newExternalV2BulkPacketSender(ctx context.Context, src *BlockSource, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics) *externalV2BulkPacketSender {
	initialPaceMbps := externalV2BulkPacketInitialWireMbps()
	controller := newExternalV2BulkPacketController(initialPaceMbps)
	grouped := src.PayloadSize >= externalV2BulkPacketGroupedMinimumFileBytes && auth.grouped != nil
	totalPackets := externalV2BulkPacketCount(src.PayloadSize)
	groupCount := uint32(0)
	if grouped {
		groupCount, totalPackets = externalV2BulkPacketGroupedLayout(src.PayloadSize, auth.grouped.Overhead())
	}
	sender := &externalV2BulkPacketSender{
		ctx:             ctx,
		src:             src,
		path:            path,
		auth:            auth,
		metrics:         metrics,
		initialPaceMbps: initialPaceMbps,
		runID:           randomExternalV2BulkPacketRunID(),
		totalPackets:    totalPackets,
		groupCount:      groupCount,
		grouped:         grouped,
		laneCount:       externalV2BulkPacketDataLaneCount(len(path.Conns), len(path.Addrs)),
		pacer: rate.NewLimiter(
			externalV2BulkPacketRateLimit(initialPaceMbps),
			externalV2BulkPacketPaceBurstBytes,
		),
		controller: controller,
	}
	sender.batchConns = make([]externalV2BulkPacketBatchConn, sender.laneCount)
	for lane := range sender.laneCount {
		sender.batchConns[lane] = newExternalV2BulkPacketBatchConn(path.Conns[lane])
	}
	sender.currentPaceMbps.Store(int64(initialPaceMbps))
	return sender
}

func (s *externalV2BulkPacketSender) sendInitialPackets() error {
	s.ackNegotiationUntil = time.Now().Add(externalV2BulkPacketAckNegotiationWait)
	if len(s.batchConns) == s.laneCount && s.laneCount > 0 {
		return s.sendInitialPacketsBatched()
	}
	for index := uint32(0); index < s.totalPackets; index++ {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if err := s.sendPacket(index, externalV2BulkPacketPrimaryLane(index, s.laneCount), false); err != nil {
			return err
		}
	}
	return nil
}

func (s *externalV2BulkPacketSender) sendInitialPacketsUntilWorkerFailure(
	ctx context.Context,
	cancel context.CancelFunc,
	workerErrCh <-chan error,
) error {
	sendErrCh := make(chan error, 1)
	go func() {
		sendErrCh <- s.sendInitialPackets()
	}()

	select {
	case err := <-sendErrCh:
		return err
	case workerErr := <-workerErrCh:
		cancel()
		return errors.Join(workerErr, <-sendErrCh)
	case <-ctx.Done():
		cancel()
		return errors.Join(ctx.Err(), <-sendErrCh)
	}
}

func (s *externalV2BulkPacketSender) sendPacket(index uint32, lane int, repair bool) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	data, err := readExternalV2BulkPacketPayload(s.src, index)
	if err != nil {
		return err
	}
	packet, err := sealExternalV2BulkPacket(s.auth.data, externalV2BulkPacketHeader{
		kind:   externalV2BulkPacketData,
		runID:  s.runID,
		index:  index,
		total:  s.totalPackets,
		length: uint16(len(data)),
	}, data)
	if err != nil {
		return err
	}
	wireBytes := externalV2BulkPacketIPv4WireBytes(len(packet))
	if err := s.pacer.WaitN(s.ctx, wireBytes); err != nil {
		return err
	}
	n, err := s.writeDataPacket(lane, packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return io.ErrShortWrite
	}
	s.sentPackets.Add(1)
	s.sentPayload.Add(int64(len(data)))
	if repair {
		s.repairWireBytes.Add(int64(wireBytes))
		s.repairPackets.Add(1)
		s.repairPayloadBytes.Add(int64(len(data)))
	} else {
		s.primaryWireBytes.Add(int64(wireBytes))
		s.primaryPayloadBytes.Add(int64(len(data)))
	}
	if s.metrics != nil {
		s.metrics.RecordDirectPacketSend(int64(len(data)), time.Now())
	}
	return nil
}

func (s *externalV2BulkPacketSender) writeDataPacket(lane int, packet []byte) (int, error) {
	consecutive := int64(0)
	for {
		n, err := s.path.Conns[lane].WriteTo(packet, s.path.Addrs[lane])
		if !errors.Is(err, syscall.ENOBUFS) {
			return n, err
		}

		consecutive++
		s.localENOBUFSRetries.Add(1)
		updateExternalV2BulkPacketAtomicMax(&s.localENOBUFSMaxConsecutive, consecutive)
		waitStarted := time.Now()
		timer := time.NewTimer(externalV2BulkPacketWriteRetryDelay)
		select {
		case <-timer.C:
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
		case <-s.ctx.Done():
			timer.Stop()
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
			return 0, s.ctx.Err()
		}
	}
}

func updateExternalV2BulkPacketAtomicMax(counter *atomic.Int64, candidate int64) {
	for {
		current := counter.Load()
		if candidate <= current || counter.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func externalV2BulkPacketRoundedUpMicroseconds(nanos int64) int64 {
	if nanos <= 0 {
		return 0
	}
	return (nanos + int64(time.Microsecond) - 1) / int64(time.Microsecond)
}

func (s *externalV2BulkPacketSender) startRepairWorker(ctx context.Context, missingCh <-chan []uint32, repairActivityCh chan<- struct{}, repairErrCh chan<- error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		lastRepair := make(map[uint32]time.Time)
		repairAttempt := make(map[uint32]uint64)
		for {
			select {
			case missing := <-missingCh:
				if ctx.Err() != nil {
					return
				}
				sentRepair, err := s.repairMissing(missing, lastRepair, repairAttempt)
				if err != nil {
					offerExternalV2BulkPacketRepairError(repairErrCh, err)
					return
				}
				if sentRepair || len(missing) > 0 {
					signalExternalV2BulkPacketRepairActivity(repairActivityCh)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}

func (s *externalV2BulkPacketSender) repairMissing(missing []uint32, lastRepair map[uint32]time.Time, repairAttempt map[uint32]uint64) (bool, error) {
	now := time.Now()
	repairs := make([]externalV2BulkPacketRepair, 0, len(missing))
	for _, index := range missing {
		if !s.shouldRepairMissing(index, now, lastRepair) {
			continue
		}
		attempt := repairAttempt[index]
		repairAttempt[index] = attempt + 1
		repairs = append(repairs, externalV2BulkPacketRepair{
			index: index,
			lane:  externalV2BulkPacketRepairLane(index, s.laneCount, attempt),
		})
	}
	if len(repairs) == 0 {
		return false, nil
	}
	if len(s.batchConns) == s.laneCount && s.laneCount > 0 {
		return true, s.sendRepairPacketsBatched(repairs)
	}
	for _, repair := range repairs {
		if err := s.sendPacket(repair.index, repair.lane, true); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *externalV2BulkPacketSender) sendPrimaryCompleteRepeats() error {
	var writeErr error
	for repeat := uint32(0); repeat < externalV2BulkPacketPrimaryDoneRepeats; repeat++ {
		writeErr = errors.Join(writeErr, writeExternalV2BulkPacketWithAEAD(
			s.path,
			s.auth.data,
			externalV2BulkPacketHeader{
				kind:  externalV2BulkPacketPrimaryComplete,
				runID: s.runID,
				index: repeat,
				total: s.totalPackets,
			},
			nil,
		))
	}
	return writeErr
}

func (s *externalV2BulkPacketSender) shouldRepairMissing(index uint32, now time.Time, lastRepair map[uint32]time.Time) bool {
	if index >= s.totalPackets {
		return false
	}
	if last, ok := lastRepair[index]; ok && now.Sub(last) < externalV2BulkPacketRepairSkip {
		return false
	}
	lastRepair[index] = now
	return true
}

func (s *externalV2BulkPacketSender) waitForCompletion(doneCh <-chan struct{}, repairActivityCh <-chan struct{}, repairErrCh <-chan error) error {
	deadline := time.NewTimer(externalV2BulkPacketRepairWait)
	defer deadline.Stop()
	for {
		select {
		case <-doneCh:
			return nil
		case err := <-repairErrCh:
			return err
		case <-repairActivityCh:
			resetExternalV2BulkPacketTimer(deadline, externalV2BulkPacketRepairWait)
		case <-deadline.C:
			return ErrPeerDisconnected
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}

func (s *externalV2BulkPacketSender) stats(committed bool) externalDirectTransferStats {
	stats := externalV2BulkPacketSendStats(
		s.src.PayloadSize,
		s.primaryPayloadBytes.Load(),
		s.sentPayload.Load(),
		s.repairPackets.Load(),
		s.repairPayloadBytes.Load(),
		s.repairRequests.Load(),
		s.laneCount,
		s.initialPaceMbps,
		int(s.currentPaceMbps.Load()),
		committed,
	)
	stats.Diagnostics.LocalENOBUFSRetries = s.localENOBUFSRetries.Load()
	stats.Diagnostics.LocalENOBUFSWaitUS = externalV2BulkPacketRoundedUpMicroseconds(s.localENOBUFSWaitNanos.Load())
	stats.Diagnostics.LocalENOBUFSMaxConsecutive = s.localENOBUFSMaxConsecutive.Load()
	mergeExternalV2BulkPacketBatchDiagnostics(&stats.Diagnostics, externalV2BulkPacketBatchDiagnostics(s.batchConns, s.batchCryptoQueuePeak.Load(), 0, s.batchLaneQueuePeak.Load()))
	setExternalV2BulkPacketProbeDiagnostics(&stats.Diagnostics, s.probeResult)
	return stats
}

func (s *externalV2BulkPacketSender) startController(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	s.observeController(time.Now())
	go func() {
		defer close(done)
		ticker := time.NewTicker(externalV2BulkPacketControllerInterval)
		defer ticker.Stop()
		for {
			select {
			case at := <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				s.observeController(at)
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}

func (s *externalV2BulkPacketSender) observeController(at time.Time) {
	peer := s.metrics.PeerProgressSnapshot()
	decision := s.controller.Observe(externalV2BulkPacketControllerSample{
		At:                    at,
		PrimaryWireBytes:      s.primaryWireBytes.Load(),
		RepairWireBytes:       s.repairWireBytes.Load(),
		PeerBytes:             peer.BytesReceived,
		PeerTransferElapsedMS: peer.TransferElapsedMS,
		PeerProgress:          peer.Set,
		ReceiveWindowBlocked:  s.receiveWindowBlocked.Swap(false),
	})
	current := int(s.currentPaceMbps.Load())
	if decision.TargetMbps != current {
		s.currentPaceMbps.Store(int64(decision.TargetMbps))
		s.pacer.SetLimitAt(at, externalV2BulkPacketRateLimit(decision.TargetMbps))
	}
	s.publishControllerDiagnostics(at, decision)
}

func (s *externalV2BulkPacketSender) publishControllerDiagnostics(
	at time.Time,
	decision externalV2BulkPacketControllerDecision,
) {
	if s.metrics == nil {
		return
	}
	diagnostics := externalDirectTransferDiagnostics{
		RateSelectedMbps:           s.initialPaceMbps,
		RateTargetMbps:             decision.TargetMbps,
		RateCeilingMbps:            externalV2BulkPacketCeilingWireMbps,
		ActiveLanes:                s.laneCount,
		AvailableLanes:             s.laneCount,
		ControllerDecision:         decision.Action,
		ControllerReason:           decision.Reason,
		Retransmits:                s.repairPackets.Load(),
		RepairRequests:             s.repairRequests.Load(),
		RepairBytes:                s.repairPayloadBytes.Load(),
		LocalENOBUFSRetries:        s.localENOBUFSRetries.Load(),
		LocalENOBUFSWaitUS:         externalV2BulkPacketRoundedUpMicroseconds(s.localENOBUFSWaitNanos.Load()),
		LocalENOBUFSMaxConsecutive: s.localENOBUFSMaxConsecutive.Load(),
	}
	mergeExternalV2BulkPacketBatchDiagnostics(&diagnostics, externalV2BulkPacketBatchDiagnostics(s.batchConns, s.batchCryptoQueuePeak.Load(), 0, s.batchLaneQueuePeak.Load()))
	s.metrics.SetDirectDiagnostics(diagnostics, at)
}

func offerExternalV2BulkPacketRepairError(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func signalExternalV2BulkPacketRepairActivity(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func receiveExternalV2BulkBlockPackets(ctx context.Context, sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics, options externalV2BulkPacketTransferOptions) (int64, externalDirectTransferStats, error) {
	if err := options.validate(); err != nil {
		return 0, externalDirectTransferStats{}, err
	}
	ctx, cancelTransfer, stopCallerLink := externalV2BulkPacketContext(ctx, options)
	defer func() {
		stopCallerLink()
		cancelTransfer(context.Canceled)
	}()
	if err := validateExternalV2BulkPacketReceiver(sink, cfg, path, auth); err != nil {
		return 0, externalDirectTransferStats{}, err
	}
	if err := metrics.SetFilePayloadLaneAddrs(path.Addrs, time.Now()); err != nil {
		return 0, externalDirectTransferStats{}, err
	}

	receiver := newExternalV2BulkPacketReceiver(sink, cfg, path, auth, metrics)
	recvCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	receiver.stopHello = startExternalV2BulkPacketHelloLoop(recvCtx, path, auth, receiver.totalPackets)
	defer receiver.stopHello()
	if options.CapacityProbe {
		if err := receiver.resolveCapacityProbe(recvCtx, options.Decision); err != nil {
			return receiver.result(err)
		}
	}

	dataCh := make(chan externalV2BulkPacketReceiveBatch, externalV2BulkPacketReceiveBatchQueue)
	errCh := make(chan error, receiver.laneCount)
	var dataReadersDone <-chan struct{}
	if receiver.directSink == nil && !receiver.grouped {
		receiver.assembler = newExternalV2BulkPacketAsyncReceiveAssembler(recvCtx, sink, cfg, receiver.totalPackets, metrics)
	}
	receiver.batchConns = make([]externalV2BulkPacketBatchConn, receiver.laneCount)
	for lane := range receiver.laneCount {
		_ = tuneExternalPacketConnReceive(path.Conns[lane], externalV2BulkPacketReceiveSocketBufferBytes)
		receiver.batchConns[lane] = newExternalV2BulkPacketBatchConn(path.Conns[lane])
		enableExternalV2BulkPacketReceiveCoalescing(receiver.batchConns[lane])
	}
	dataReadersDone = startExternalV2BulkPacketBatchedDataReaders(recvCtx, receiver.batchConns, auth, dataCh, errCh, receiver.arrivals, receiver.directWriteBuffer(), receiver.groupAssembler, &receiver.batchCryptoQueuePeak, &receiver.batchReceiveQueuePeak)
	receiver.stopHello()

	return runExternalV2BulkPacketReceiver(ctx, receiver, cancel, dataReadersDone, dataCh, errCh)
}

func (r *externalV2BulkPacketReceiver) resolveCapacityProbe(ctx context.Context, coordinator *externalV2BulkDecisionCoordinator) error {
	probeResult, decision, probeCleanupErr, decisionErr := coordinator.ResolveReceiver(ctx, func(probeCtx context.Context) (externalV2BulkPacketProbeResult, error) {
		return receiveExternalV2BulkPacketProbe(probeCtx, r.path, r.auth, r.totalPackets, coordinator)
	})
	r.probeResult = probeResult
	if decisionErr != nil {
		return errors.Join(decisionErr, probeCleanupErr)
	}
	r.metrics.SetBulkDecision(decision, time.Now())
	if decision.Mode == externalV2BulkModeQUIC {
		if probeCleanupErr != nil {
			return errors.Join(errExternalV2BulkPacketProbeRejected, probeCleanupErr)
		}
		return errExternalV2BulkPacketProbeRejected
	}
	if probeCleanupErr != nil {
		return probeCleanupErr
	}
	r.probeResult.SelectedMbps = decision.SelectedMbps
	if r.grouped && !r.groupAssembler.setExpectedRunID(decision.ProbeRunID) {
		return errors.New("bulk packet grouped decision did not authenticate a run ID")
	}
	r.metrics.SelectFilePayloadEngine(transfertrace.FilePayloadEngineBulk, time.Now())
	return nil
}

func runExternalV2BulkPacketReceiver(ctx context.Context, receiver *externalV2BulkPacketReceiver, cancel context.CancelFunc, dataReadersDone <-chan struct{}, dataCh <-chan externalV2BulkPacketReceiveBatch, errCh <-chan error) (int64, externalDirectTransferStats, error) {
	received, stats, err := receiver.runBatched(ctx, dataCh, errCh)
	cancel()
	<-dataReadersDone
	for {
		select {
		case batch := <-dataCh:
			batch.release()
		default:
			return received, stats, errors.Join(err, externalV2BulkPacketContextCause(ctx))
		}
	}
}

func validateExternalV2BulkPacketReceiver(sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth) error {
	if sink == nil {
		return errors.New("nil block sink")
	}
	if cfg.PayloadSize < 0 {
		return fmt.Errorf("negative block payload size %d", cfg.PayloadSize)
	}
	if len(path.Conns) == 0 || len(path.Addrs) == 0 {
		return errors.New("no bulk packet path")
	}
	if auth.data == nil || auth.control == nil {
		return errors.New("bulk packet auth is not configured")
	}
	return nil
}

type externalV2BulkPacketReceiver struct {
	cfg                   externalV2BlockReceiveConfig
	path                  externalV2BulkPacketPath
	auth                  externalV2BulkPacketAuth
	batchConns            []externalV2BulkPacketBatchConn
	batchCryptoQueuePeak  atomic.Uint32
	batchReceiveQueuePeak atomic.Uint32
	batchDecryptBatches   atomic.Uint64
	batchDecryptDatagrams atomic.Uint64
	probeResult           externalV2BulkPacketProbeResult
	metrics               *externalTransferMetrics
	laneCount             int
	totalPackets          uint32
	groupCount            uint32
	grouped               bool
	seen                  []bool
	missing               *externalV2BulkPacketMissingTracker
	receiveRate           externalV2BulkPacketReceiveRate
	arrivals              *externalV2BulkPacketArrivalTracker
	assembler             *externalV2BulkPacketReceiveAssembler
	groupAssembler        *externalV2BulkPacketGroupAssembler
	sink                  BlockReceiveSink
	directSink            DirectBlockReceiveSink
	runID                 uint64
	receivedPackets       uint32
	highestSeenPlusOne    uint32
	lastDataAt            time.Time
	committedPayload      int64
	repairRequests        int64
	controlSeq            uint32
	lastAckAt             time.Time
	primaryComplete       bool
	stopHello             func()
}

func newExternalV2BulkPacketReceiver(sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics) *externalV2BulkPacketReceiver {
	laneCount := externalV2BulkPacketDataLaneCount(len(path.Conns), len(path.Addrs))
	totalPackets := externalV2BulkPacketCount(cfg.PayloadSize)
	grouped := cfg.PayloadSize >= externalV2BulkPacketGroupedMinimumFileBytes && auth.grouped != nil
	groupCount := uint32(0)
	if grouped {
		groupCount, totalPackets = externalV2BulkPacketGroupedLayout(cfg.PayloadSize, auth.grouped.Overhead())
	}
	arrivals := newExternalV2BulkPacketArrivalTracker(totalPackets)
	receiver := &externalV2BulkPacketReceiver{
		cfg:          cfg,
		path:         path,
		auth:         auth,
		metrics:      metrics,
		laneCount:    laneCount,
		totalPackets: totalPackets,
		groupCount:   groupCount,
		grouped:      grouped,
		sink:         sink,
		seen:         make([]bool, totalPackets),
		missing:      newExternalV2BulkPacketMissingTracker(totalPackets, arrivals),
		arrivals:     arrivals,
	}
	if direct, ok := sink.(DirectBlockReceiveSink); ok && int64(len(direct.DirectWriteBuffer())) == cfg.PayloadSize {
		receiver.directSink = direct
	} else if !grouped {
		receiver.assembler = newExternalV2BulkPacketReceiveAssembler(sink, cfg, totalPackets)
	}
	if grouped {
		receiver.groupAssembler = newExternalV2BulkPacketGroupAssembler(cfg.PayloadSize, auth.grouped, arrivals, receiver.directWriteBuffer())
	}
	return receiver
}

func (r *externalV2BulkPacketReceiver) directWriteBuffer() []byte {
	if r == nil || r.directSink == nil {
		return nil
	}
	return r.directSink.DirectWriteBuffer()
}

func (r *externalV2BulkPacketReceiver) run(ctx context.Context, dataCh <-chan externalV2BulkPacketReceiveResult, errCh <-chan error) (int64, externalDirectTransferStats, error) {
	repairTicker := time.NewTicker(externalV2BulkPacketReadIdle)
	defer repairTicker.Stop()
	primaryTimer := time.NewTimer(time.Hour)
	stopExternalV2BulkPacketTimer(primaryTimer)
	defer primaryTimer.Stop()
	var primaryRepair <-chan time.Time
	for r.receivedPackets < r.totalPackets {
		select {
		case result := <-dataCh:
			err := r.handleDataResult(result)
			result.release()
			if err != nil {
				return r.result(err)
			}
			if r.primaryComplete {
				resetExternalV2BulkPacketTimer(primaryTimer, externalV2BulkPacketPrimaryRepairDelay)
				primaryRepair = primaryTimer.C
			}
		case err := <-errCh:
			if err != nil {
				return r.result(err)
			}
		case <-repairTicker.C:
			r.repairTick(time.Now())
		case <-primaryRepair:
			r.sendPrimaryCompleteRepair(time.Now())
			primaryRepair = nil
		case <-ctx.Done():
			return r.result(ctx.Err())
		}
	}
	r.sendDoneRepeats()
	return r.result(nil)
}

func (r *externalV2BulkPacketReceiver) runBatched(ctx context.Context, dataCh <-chan externalV2BulkPacketReceiveBatch, errCh <-chan error) (int64, externalDirectTransferStats, error) {
	repairTicker := time.NewTicker(externalV2BulkPacketReadIdle)
	defer repairTicker.Stop()
	primaryTimer := time.NewTimer(time.Hour)
	stopExternalV2BulkPacketTimer(primaryTimer)
	defer primaryTimer.Stop()
	var primaryRepair <-chan time.Time
	for r.receivedPackets < r.totalPackets {
		select {
		case batch := <-dataCh:
			err := r.handleDataBatch(batch, time.Now())
			batch.release()
			if err != nil {
				return r.result(err)
			}
			if r.primaryComplete {
				resetExternalV2BulkPacketTimer(primaryTimer, externalV2BulkPacketPrimaryRepairDelay)
				primaryRepair = primaryTimer.C
			}
		case err := <-errCh:
			if err != nil {
				return r.result(err)
			}
		case <-repairTicker.C:
			r.repairTick(time.Now())
		case <-primaryRepair:
			r.sendPrimaryCompleteRepair(time.Now())
			primaryRepair = nil
		case <-ctx.Done():
			return r.result(ctx.Err())
		}
	}
	r.sendDoneRepeats()
	return r.result(nil)
}

func (r *externalV2BulkPacketReceiver) handleDataResult(result externalV2BulkPacketReceiveResult) error {
	now := time.Now()
	if result.primaryComplete {
		r.handlePrimaryComplete(result.header)
		return nil
	}
	accepted, err := r.handleDataResultAt(result, now)
	if accepted {
		if result.direct {
			n := int(result.header.length)
			highestEnd := int64(result.header.index)*externalV2BulkPacketPayloadSize + int64(n)
			if commitErr := r.directSink.CommitDirectWrite(n, highestEnd); commitErr != nil {
				return errors.Join(err, commitErr)
			}
			if r.metrics != nil {
				r.metrics.RecordDirectPacketReceive(int64(n), now)
				r.metrics.RecordFilePayloadCommit(transfertrace.FilePayloadEngineBulk, int64(n), now)
			}
		}
		r.receiveRate.observeN(now, 1)
		r.sendReceiveAck(now)
	}
	return err
}

func (r *externalV2BulkPacketReceiver) handleDataBatch(batch externalV2BulkPacketReceiveBatch, now time.Time) error {
	accepted := uint32(0)
	directBytes := 0
	directHighestEnd := int64(0)
	decryptedDatagrams := uint64(0)
	for _, result := range batch.results {
		if result.primaryComplete {
			r.handlePrimaryComplete(result.header)
			decryptedDatagrams++
			continue
		}
		if result.grouped {
			groupAccepted, groupDirectBytes, groupHighestEnd, err := r.handleGroupedDataResultAt(result, now)
			if err != nil {
				return err
			}
			accepted += groupAccepted
			directBytes += groupDirectBytes
			directHighestEnd = max(directHighestEnd, groupHighestEnd)
			decryptedDatagrams += uint64(result.fragmentCount)
			continue
		}
		resultAccepted, err := r.handleDataResultAt(result, now)
		if err != nil {
			return err
		}
		if resultAccepted {
			accepted++
			if result.direct {
				directBytes += int(result.header.length)
				directHighestEnd = max(
					directHighestEnd,
					int64(result.header.index)*externalV2BulkPacketPayloadSize+int64(result.header.length),
				)
			}
		}
		decryptedDatagrams++
	}
	r.batchDecryptBatches.Add(1)
	r.batchDecryptDatagrams.Add(decryptedDatagrams)
	if accepted > 0 {
		if directBytes > 0 {
			if err := r.directSink.CommitDirectWrite(directBytes, directHighestEnd); err != nil {
				return err
			}
			if r.metrics != nil {
				r.metrics.RecordDirectPacketReceive(int64(directBytes), now)
				r.metrics.RecordFilePayloadCommit(transfertrace.FilePayloadEngineBulk, int64(directBytes), now)
			}
		}
		r.receiveRate.observeN(now, accepted)
		r.sendReceiveAck(now)
	}
	return nil
}

func (r *externalV2BulkPacketReceiver) handleGroupedDataResultAt(
	result externalV2BulkPacketReceiveResult,
	now time.Time,
) (uint32, int, int64, error) {
	header := result.header
	if !r.grouped || header.kind != externalV2BulkPacketGroupedData || header.total != r.groupCount ||
		header.index >= r.groupCount || result.fragmentCount == 0 {
		return 0, 0, 0, nil
	}
	plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(header.index, r.cfg.PayloadSize)
	firstFragment, fragmentCount := externalV2BulkPacketGroupedFragmentRange(header.index, r.cfg.PayloadSize, r.auth.grouped.Overhead())
	if int(header.length) != plainBytes || result.fragmentStart != firstFragment || result.fragmentCount != fragmentCount {
		return 0, 0, 0, fmt.Errorf("bulk packet grouped result %d has invalid layout", header.index)
	}
	if r.runID == 0 {
		r.runID = header.runID
		r.stopHello()
		r.metrics.SelectFilePayloadEngine(transfertrace.FilePayloadEngineBulk, now)
	}
	if header.runID != r.runID || r.seen[firstFragment] {
		return 0, 0, 0, nil
	}
	if !result.direct {
		n, err := r.sink.WriteAt(result.data, plainStart)
		if err != nil {
			return 0, 0, 0, err
		}
		if n != plainBytes {
			return 0, 0, 0, io.ErrShortWrite
		}
		if r.metrics != nil {
			r.metrics.RecordDirectPacketReceive(int64(n), now)
			r.metrics.RecordFilePayloadCommit(transfertrace.FilePayloadEngineBulk, int64(n), now)
		}
	}
	for index := firstFragment; index < firstFragment+fragmentCount; index++ {
		r.missing.resolve(index)
		r.seen[index] = true
		r.markHighestSeen(index)
	}
	r.receivedPackets += fragmentCount
	r.committedPayload += int64(plainBytes)
	r.lastDataAt = now
	if result.direct {
		return fragmentCount, plainBytes, plainStart + int64(plainBytes), nil
	}
	return fragmentCount, 0, 0, nil
}

func (r *externalV2BulkPacketReceiver) handlePrimaryComplete(header externalV2BulkPacketHeader) {
	if r.runID != 0 && header.runID == r.runID && header.total == r.totalPackets {
		r.primaryComplete = true
	}
}

func (r *externalV2BulkPacketReceiver) sendPrimaryCompleteRepair(now time.Time) {
	if !r.primaryComplete {
		return
	}
	r.primaryComplete = false
	r.sendIdleMissing(now)
}

func (r *externalV2BulkPacketReceiver) handleDataResultAt(result externalV2BulkPacketReceiveResult, now time.Time) (bool, error) {
	header := result.header
	if header.total != r.totalPackets || header.index >= r.totalPackets {
		return false, nil
	}
	if r.runID == 0 {
		r.runID = header.runID
		r.stopHello()
		r.metrics.SelectFilePayloadEngine(transfertrace.FilePayloadEngineBulk, now)
	}
	if header.runID != r.runID || r.seen[header.index] {
		return false, nil
	}
	dataLength := len(result.data)
	if result.direct {
		if r.directSink == nil {
			return false, errors.New("bulk packet direct result has no direct sink")
		}
		dataLength = int(header.length)
	}
	if err := r.validateDataLength(header, dataLength); err != nil {
		return false, err
	}
	r.arrivals.markData(header)
	r.lastDataAt = now
	var n int
	var err error
	if result.direct {
		n = dataLength
	} else {
		var accepted bool
		n, accepted, err = r.assembler.addPacket(header.index, result.data)
		if !accepted {
			return false, err
		}
	}
	r.markHighestSeen(header.index)
	if n > 0 {
		r.committedPayload += int64(n)
		if r.metrics != nil && !result.direct {
			r.metrics.RecordDirectPacketReceive(int64(n), now)
		}
	}
	if err != nil {
		return false, err
	}
	if n > 0 && !result.direct {
		r.metrics.RecordFilePayloadCommit(transfertrace.FilePayloadEngineBulk, int64(n), now)
	}
	r.missing.resolve(header.index)
	r.seen[header.index] = true
	r.receivedPackets++
	return true, nil
}

func (r *externalV2BulkPacketReceiver) authenticatedPayloadCredit() int64 {
	if r.arrivals != nil {
		return min(r.cfg.PayloadSize, r.arrivals.payloadBytes())
	}
	var payload int64
	for index, seen := range r.seen {
		if seen {
			payload += int64(externalV2BulkPacketPayloadLength(uint32(index), r.cfg.PayloadSize))
		}
	}
	return min(r.cfg.PayloadSize, payload)
}

func (r *externalV2BulkPacketReceiver) sendReceiveAck(now time.Time) {
	if r.runID == 0 || (!r.lastAckAt.IsZero() && now.Sub(r.lastAckAt) < externalV2BulkPacketAckInterval) {
		return
	}
	payload := encodeExternalV2BulkPacketAck(r.authenticatedPayloadCredit(), r.advertisedReceiveWindow())
	_ = writeExternalV2BulkPacketControl(r.path, r.auth, externalV2BulkPacketHeader{
		kind:   externalV2BulkPacketAck,
		runID:  r.runID,
		index:  r.controlSeq,
		total:  r.totalPackets,
		length: uint16(len(payload)),
	}, payload)
	r.controlSeq++
	r.lastAckAt = now
}

func (r *externalV2BulkPacketReceiver) advertisedReceiveWindow() int64 {
	if r.directSink != nil {
		return externalV2BulkPacketDirectReceiveWindow
	}
	return externalV2BulkPacketBufferedReceiveWindow
}

func (r *externalV2BulkPacketReceiver) repairTick(now time.Time) {
	lastActivity := r.lastDataAt
	if arrived := r.arrivals.lastActivity(); arrived.After(lastActivity) {
		lastActivity = arrived
	}
	if !lastActivity.IsZero() && now.Sub(lastActivity) < externalV2BulkPacketReadIdle {
		r.sendActiveMissing(now)
		return
	}
	r.sendIdleMissing(now)
}

func (r *externalV2BulkPacketReceiver) validateDataLength(header externalV2BulkPacketHeader, length int) error {
	offset := int64(header.index) * externalV2BulkPacketPayloadSize
	wantLen := externalV2BulkPacketPayloadLength(header.index, r.cfg.PayloadSize)
	if length == wantLen && offset+int64(length) <= r.cfg.PayloadSize {
		return nil
	}
	return fmt.Errorf("bulk packet offset %d length %d, want %d within payload size %d", offset, length, wantLen, r.cfg.PayloadSize)
}

func (r *externalV2BulkPacketReceiver) markHighestSeen(index uint32) {
	if index+1 > r.highestSeenPlusOne {
		r.highestSeenPlusOne = index + 1
	}
}

func (r *externalV2BulkPacketReceiver) sendActiveMissing(now time.Time) {
	if r.runID == 0 || r.receivedPackets == r.totalPackets {
		return
	}
	trail := r.receiveRate.trailPackets()
	highest := max(r.highestSeenPlusOne, r.arrivals.highestPlusOne())
	if highest <= trail {
		return
	}
	r.missing.advance(r.seen, highest-trail)
	r.sendMissingBatches(r.missing.batches(r.seen, now, false))
}

func (r *externalV2BulkPacketReceiver) sendIdleMissing(now time.Time) {
	if r.runID == 0 || r.receivedPackets == r.totalPackets {
		return
	}
	highest := max(r.highestSeenPlusOne, r.arrivals.highestPlusOne())
	limit := r.totalPackets
	if remaining := r.totalPackets - highest; remaining > externalV2BulkPacketMissingLookahead {
		limit = highest + externalV2BulkPacketMissingLookahead
	}
	r.missing.advance(r.seen, limit)
	r.sendMissingBatches(r.missing.batches(r.seen, now, true))
}

func (r *externalV2BulkPacketReceiver) sendMissingBatches(batches [][]uint32) {
	for _, missing := range batches {
		if len(missing) > 0 {
			r.sendMissingBatch(missing)
		}
	}
}

func (r *externalV2BulkPacketReceiver) sendMissingBatch(missing []uint32) {
	payload := encodeExternalV2BulkPacketMissing(missing)
	_ = writeExternalV2BulkPacketControl(r.path, r.auth, externalV2BulkPacketHeader{
		kind:   externalV2BulkPacketMiss,
		runID:  r.runID,
		index:  r.controlSeq,
		total:  r.totalPackets,
		length: uint16(len(payload)),
	}, payload)
	r.controlSeq++
	r.repairRequests++
}

func (r *externalV2BulkPacketReceiver) sendDoneRepeats() {
	for i := uint32(0); i < externalV2BulkPacketDoneRepeats; i++ {
		_ = writeExternalV2BulkPacketControl(r.path, r.auth, externalV2BulkPacketHeader{
			kind:   externalV2BulkPacketDone,
			runID:  r.runID,
			index:  r.controlSeq,
			total:  r.totalPackets,
			length: 0,
		}, nil)
		r.controlSeq++
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *externalV2BulkPacketReceiver) result(err error) (int64, externalDirectTransferStats, error) {
	if r.assembler != nil && r.assembler.isAsync() {
		committed, writerErr := r.assembler.finish()
		r.committedPayload = committed
		err = errors.Join(err, writerErr)
	}
	repairStats := r.missing.stats()
	stats := externalV2BulkPacketReceiveStats(
		r.cfg.PayloadSize,
		r.committedPayload,
		r.repairRequests,
		r.laneCount,
		repairStats,
		r.receiveRate.trailPackets(),
		r.receiveRate.packetsPerSecond(),
	)
	writerQueuePeak := uint32(0)
	if r.assembler != nil {
		writerQueuePeak = r.assembler.writerQueuePeak()
	}
	mergeExternalV2BulkPacketBatchDiagnostics(&stats.Diagnostics, externalV2BulkPacketBatchDiagnostics(r.batchConns, r.batchCryptoQueuePeak.Load(), writerQueuePeak, 0))
	stats.Diagnostics.BulkReceiveQueuePeak = r.batchReceiveQueuePeak.Load()
	stats.Diagnostics.BulkDecryptBatches = r.batchDecryptBatches.Load()
	stats.Diagnostics.BulkDecryptDatagrams = r.batchDecryptDatagrams.Load()
	setExternalV2BulkPacketProbeDiagnostics(&stats.Diagnostics, r.probeResult)
	return r.cfg.HeaderBytes + r.committedPayload, stats, err
}

type externalV2BulkPacketReceiveAssembler struct {
	sink            BlockReceiveSink
	payloadSize     int64
	totalPackets    uint32
	packetsPerGroup uint32
	groups          map[uint32]*externalV2BulkPacketReceiveGroup
	flushedGroups   []bool
	groupOrder      []uint32
	groupOrderHead  int
	asyncWriter     *externalV2BulkPacketAsyncWriter
	finishOnce      sync.Once
	finishCommitted int64
	finishErr       error
}

type externalV2BulkPacketReceiveGroup struct {
	baseIndex uint32
	seen      []bool
	data      []byte
	received  uint32
}

func newExternalV2BulkPacketReceiveAssembler(sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, totalPackets uint32) *externalV2BulkPacketReceiveAssembler {
	groupBytes := min(externalV2BlockChunkSize(cfg.ChunkSize), externalV2BulkPacketReceiveGroupBytes)
	return newExternalV2BulkPacketReceiveAssemblerWithGroup(sink, cfg, totalPackets, groupBytes)
}

func newExternalV2BulkPacketAsyncReceiveAssembler(ctx context.Context, sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, totalPackets uint32, metrics *externalTransferMetrics) *externalV2BulkPacketReceiveAssembler {
	groupBytes := min(externalV2BlockChunkSize(cfg.ChunkSize), externalV2BulkPacketWriteGroup)
	assembler := newExternalV2BulkPacketReceiveAssemblerWithGroup(sink, cfg, totalPackets, groupBytes)
	assembler.asyncWriter = newExternalV2BulkPacketAsyncWriter(ctx, sink, externalV2BulkPacketWriterQueue, metrics)
	return assembler
}

func newExternalV2BulkPacketReceiveAssemblerWithGroup(sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, totalPackets uint32, groupBytes int) *externalV2BulkPacketReceiveAssembler {
	packetsPerGroup := uint32(max(1, groupBytes/externalV2BulkPacketPayloadSize))
	return &externalV2BulkPacketReceiveAssembler{
		sink:            sink,
		payloadSize:     cfg.PayloadSize,
		totalPackets:    totalPackets,
		packetsPerGroup: packetsPerGroup,
		groups:          make(map[uint32]*externalV2BulkPacketReceiveGroup),
		flushedGroups:   make([]bool, (totalPackets+packetsPerGroup-1)/packetsPerGroup),
	}
}

func (a *externalV2BulkPacketReceiveAssembler) add(index uint32, data []byte) (int, error) {
	n, _, err := a.addPacket(index, data)
	return n, err
}

func (a *externalV2BulkPacketReceiveAssembler) addPacket(index uint32, data []byte) (int, bool, error) {
	groupID := index / a.packetsPerGroup
	if a.flushedGroups[groupID] {
		n, err := a.writeExtent(
			int64(index)*externalV2BulkPacketPayloadSize,
			data,
			true,
		)
		return n, err == nil, err
	}
	committed := 0
	group := a.groups[groupID]
	if group == nil {
		if len(a.groups) >= externalV2BulkPacketReceiveGroupLimit {
			n, err := a.spillOldestGroup()
			committed += n
			if err != nil {
				return committed, false, err
			}
		}
		group = a.newGroup(groupID)
		a.groups[groupID] = group
		a.groupOrder = append(a.groupOrder, groupID)
	}
	groupOffset := index - group.baseIndex
	if groupOffset >= uint32(len(group.seen)) {
		return 0, false, fmt.Errorf("bulk packet index %d outside receive group %d", index, groupID)
	}
	if group.seen[groupOffset] {
		return 0, false, nil
	}
	offset := int(groupOffset) * externalV2BulkPacketPayloadSize
	copy(group.data[offset:], data)
	group.seen[groupOffset] = true
	group.received++
	if group.received < uint32(len(group.seen)) {
		return committed, true, nil
	}
	if a.asyncWriter != nil {
		if err := a.asyncWriter.enqueue(externalV2BulkPacketWriteExtent{
			Offset: int64(group.baseIndex) * externalV2BulkPacketPayloadSize,
			Data:   group.data,
		}); err != nil {
			return committed, false, err
		}
		delete(a.groups, groupID)
		return committed, true, nil
	}
	n, err := a.sink.WriteAt(group.data, int64(group.baseIndex)*externalV2BulkPacketPayloadSize)
	if err != nil {
		return committed + n, false, err
	}
	if n != len(group.data) {
		return committed + n, false, io.ErrShortWrite
	}
	delete(a.groups, groupID)
	return committed + n, true, nil
}

func (a *externalV2BulkPacketReceiveAssembler) spillOldestGroup() (int, error) {
	for a.groupOrderHead < len(a.groupOrder) {
		groupID := a.groupOrder[a.groupOrderHead]
		a.groupOrderHead++
		group := a.groups[groupID]
		if group == nil {
			continue
		}
		committed, err := a.spillGroup(group)
		if err != nil {
			return committed, err
		}
		delete(a.groups, groupID)
		a.flushedGroups[groupID] = true
		return committed, nil
	}
	return 0, errors.New("bulk packet receive group limit reached without a spill candidate")
}

func (a *externalV2BulkPacketReceiveAssembler) spillGroup(group *externalV2BulkPacketReceiveGroup) (int, error) {
	committed := 0
	for start := 0; start < len(group.seen); {
		if !group.seen[start] {
			start++
			continue
		}
		end := start + 1
		for end < len(group.seen) && group.seen[end] {
			end++
		}
		dataStart := start * externalV2BulkPacketPayloadSize
		dataEnd := min(len(group.data), end*externalV2BulkPacketPayloadSize)
		n, err := a.writeExtent(
			int64(group.baseIndex+uint32(start))*externalV2BulkPacketPayloadSize,
			group.data[dataStart:dataEnd],
			false,
		)
		committed += n
		if err != nil {
			return committed, err
		}
		start = end
	}
	return committed, nil
}

func (a *externalV2BulkPacketReceiveAssembler) writeExtent(offset int64, data []byte, copyData bool) (int, error) {
	if a.asyncWriter != nil {
		if copyData {
			data = append([]byte(nil), data...)
		}
		if err := a.asyncWriter.enqueue(externalV2BulkPacketWriteExtent{Offset: offset, Data: data}); err != nil {
			return 0, err
		}
		return 0, nil
	}
	n, err := a.sink.WriteAt(data, offset)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (a *externalV2BulkPacketReceiveAssembler) isAsync() bool {
	return a.asyncWriter != nil
}

func (a *externalV2BulkPacketReceiveAssembler) finish() (int64, error) {
	if a.asyncWriter == nil {
		return 0, nil
	}
	a.finishOnce.Do(func() {
		a.finishCommitted, a.finishErr = a.asyncWriter.finish()
	})
	return a.finishCommitted, a.finishErr
}

func (a *externalV2BulkPacketReceiveAssembler) writerQueuePeak() uint32 {
	if a.asyncWriter == nil {
		return 0
	}
	return a.asyncWriter.peak.Load()
}

func (a *externalV2BulkPacketReceiveAssembler) newGroup(groupID uint32) *externalV2BulkPacketReceiveGroup {
	baseIndex := groupID * a.packetsPerGroup
	packetCount := min(a.packetsPerGroup, a.totalPackets-baseIndex)
	start := int64(baseIndex) * externalV2BulkPacketPayloadSize
	end := min(a.payloadSize, start+int64(packetCount)*externalV2BulkPacketPayloadSize)
	return &externalV2BulkPacketReceiveGroup{
		baseIndex: baseIndex,
		seen:      make([]bool, packetCount),
		data:      make([]byte, end-start),
	}
}

func startExternalV2BulkPacketControlReaders(ctx context.Context, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, runID uint64, totalPackets uint32, missingCh chan<- []uint32, doneCh chan<- struct{}, helloCh chan<- struct{}, errCh chan<- error, repairRequests *atomic.Int64, receiveAck *externalV2BulkPacketReceiveAck) <-chan struct{} {
	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(len(path.Conns))
	for _, conn := range path.Conns {
		go func(conn net.PacketConn) {
			defer readers.Done()
			readExternalV2BulkPacketControlLoop(ctx, conn, auth, runID, totalPackets, missingCh, doneCh, helloCh, errCh, repairRequests, receiveAck)
		}(conn)
	}
	go func() {
		readers.Wait()
		close(done)
	}()
	return done
}

type externalV2BulkPacketReader struct {
	conn          net.PacketConn
	deadlineArmed bool
	nonceScratch  [externalV2BulkPacketMaximumNonceSize]byte
}

func readExternalV2BulkPacketControlLoop(ctx context.Context, conn net.PacketConn, auth externalV2BulkPacketAuth, runID uint64, totalPackets uint32, missingCh chan<- []uint32, doneCh chan<- struct{}, helloCh chan<- struct{}, errCh chan<- error, repairRequests *atomic.Int64, receiveAck *externalV2BulkPacketReceiveAck) {
	buf := make([]byte, externalV2BulkPacketMaxSize)
	reader := externalV2BulkPacketReader{conn: conn}
	for {
		header, payload, ok, stop := readExternalV2BulkPacketControl(ctx, &reader, auth, buf, errCh)
		if stop {
			return
		}
		if !ok {
			continue
		}
		if handleExternalV2BulkPacketControl(header, payload, runID, totalPackets, missingCh, doneCh, helloCh, repairRequests, receiveAck) {
			return
		}
	}
}

func readExternalV2BulkPacketControl(ctx context.Context, reader *externalV2BulkPacketReader, auth externalV2BulkPacketAuth, buf []byte, errCh chan<- error) (externalV2BulkPacketHeader, []byte, bool, bool) {
	n, ok, stop := readExternalV2BulkPacketBytes(ctx, reader, buf, errCh)
	if !ok {
		return externalV2BulkPacketHeader{}, nil, false, stop
	}
	header, payload, opened := openExternalV2BulkPacketIntoWithNonce(auth.control, buf[:n], nil, &reader.nonceScratch)
	return header, payload, opened, false
}

func handleExternalV2BulkPacketControl(header externalV2BulkPacketHeader, payload []byte, runID uint64, totalPackets uint32, missingCh chan<- []uint32, doneCh chan<- struct{}, helloCh chan<- struct{}, repairRequests *atomic.Int64, receiveAck *externalV2BulkPacketReceiveAck) bool {
	switch header.kind {
	case externalV2BulkPacketHello:
		handleExternalV2BulkPacketHello(header, totalPackets, helloCh)
	case externalV2BulkPacketMiss:
		handleExternalV2BulkPacketMissing(header, payload, runID, missingCh, repairRequests)
	case externalV2BulkPacketDone:
		return handleExternalV2BulkPacketDone(header, runID, doneCh)
	case externalV2BulkPacketAck:
		if header.runID == runID && header.total == totalPackets {
			if bytes, window, ok := decodeExternalV2BulkPacketAck(payload); ok {
				receiveAck.record(bytes, window)
			}
		}
	}
	return false
}

func handleExternalV2BulkPacketHello(header externalV2BulkPacketHeader, totalPackets uint32, helloCh chan<- struct{}) {
	if header.runID != 0 || header.total != totalPackets {
		return
	}
	signalExternalV2BulkPacketRepairActivity(helloCh)
}

func handleExternalV2BulkPacketMissing(header externalV2BulkPacketHeader, payload []byte, runID uint64, missingCh chan<- []uint32, repairRequests *atomic.Int64) {
	if header.runID != runID {
		return
	}
	missing := decodeExternalV2BulkPacketMissing(payload)
	if len(missing) == 0 {
		return
	}
	if repairRequests != nil {
		repairRequests.Add(1)
	}
	select {
	case missingCh <- missing:
	default:
	}
}

func handleExternalV2BulkPacketDone(header externalV2BulkPacketHeader, runID uint64, doneCh chan<- struct{}) bool {
	if header.runID != runID {
		return false
	}
	signalExternalV2BulkPacketRepairActivity(doneCh)
	return true
}

func waitExternalV2BulkPacketHello(ctx context.Context, helloCh <-chan struct{}, errCh <-chan error) error {
	return waitExternalV2BulkPacketHelloWithin(ctx, helloCh, errCh, externalV2BulkPacketHelloWait)
}

func waitExternalV2BulkPacketHelloWithin(ctx context.Context, helloCh <-chan struct{}, errCh <-chan error, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-helloCh:
		return nil
	case err := <-errCh:
		return err
	case <-timer.C:
		return ErrPeerDisconnected
	case <-ctx.Done():
		return ctx.Err()
	}
}

func startExternalV2BulkPacketHelloLoop(ctx context.Context, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, totalPackets uint32) func() {
	helloCtx, cancel := context.WithCancel(ctx)
	var stopOnce sync.Once
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		var seq uint32
		for {
			_ = writeExternalV2BulkPacketControl(path, auth, externalV2BulkPacketHeader{
				kind:   externalV2BulkPacketHello,
				runID:  0,
				index:  seq,
				total:  totalPackets,
				length: 0,
			}, nil)
			seq++
			select {
			case <-helloCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() {
		stopOnce.Do(cancel)
	}
}

func readExternalV2BulkPacketDataLoopWithPool(ctx context.Context, conn net.PacketConn, auth externalV2BulkPacketAuth, dataCh chan<- externalV2BulkPacketReceiveResult, errCh chan<- error, pool externalV2BulkPacketPayloadBufferRecycler) {
	buf := make([]byte, externalV2BulkPacketMaxSize)
	reader := externalV2BulkPacketReader{conn: conn}
	for {
		result, ok, stop := readExternalV2BulkPacketDataWithPool(ctx, &reader, auth, buf, errCh, pool)
		if stop {
			return
		}
		if !ok {
			continue
		}
		select {
		case dataCh <- result:
		case <-ctx.Done():
			result.release()
			return
		}
	}
}

func readExternalV2BulkPacketData(ctx context.Context, reader *externalV2BulkPacketReader, auth externalV2BulkPacketAuth, buf []byte, errCh chan<- error) (externalV2BulkPacketReceiveResult, bool, bool) {
	return readExternalV2BulkPacketDataWithPool(ctx, reader, auth, buf, errCh, externalV2BulkPacketPayloadPool)
}

func readExternalV2BulkPacketDataWithPool(ctx context.Context, reader *externalV2BulkPacketReader, auth externalV2BulkPacketAuth, buf []byte, errCh chan<- error, pool externalV2BulkPacketPayloadBufferRecycler) (externalV2BulkPacketReceiveResult, bool, bool) {
	n, ok, stop := readExternalV2BulkPacketBytes(ctx, reader, buf, errCh)
	if !ok {
		return externalV2BulkPacketReceiveResult{}, false, stop
	}
	payloadBuffer := pool.get()
	header, payload, opened := openExternalV2BulkPacketIntoWithNonce(auth.data, buf[:n], payloadBuffer.data, &reader.nonceScratch)
	if !opened || (header.kind != externalV2BulkPacketData && header.kind != externalV2BulkPacketPrimaryComplete) {
		pool.put(payloadBuffer)
		return externalV2BulkPacketReceiveResult{}, false, false
	}
	if header.kind == externalV2BulkPacketPrimaryComplete {
		pool.put(payloadBuffer)
		if len(payload) != 0 {
			return externalV2BulkPacketReceiveResult{}, false, false
		}
		return externalV2BulkPacketReceiveResult{header: header, primaryComplete: true}, true, false
	}
	payloadBuffer.data = payload
	return externalV2BulkPacketReceiveResult{
		header:        header,
		data:          payload,
		payloadBuffer: payloadBuffer,
		payloadPool:   pool,
	}, true, false
}

func readExternalV2BulkPacketBytes(ctx context.Context, reader *externalV2BulkPacketReader, buf []byte, errCh chan<- error) (int, bool, bool) {
	if !reader.deadlineArmed {
		if err := reader.conn.SetReadDeadline(time.Now().Add(externalV2BulkPacketReadIdle)); err != nil {
			if errCh != nil {
				offerExternalV2BulkPacketRepairError(errCh, err)
			}
			return 0, false, true
		}
		reader.deadlineArmed = true
	}
	n, _, err := reader.conn.ReadFrom(buf)
	if err == nil {
		return n, true, false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		reader.deadlineArmed = false
		return 0, false, ctx.Err() != nil
	}
	if errCh != nil {
		offerExternalV2BulkPacketRepairError(errCh, err)
	}
	return 0, false, true
}

func readExternalV2BulkPacketPayload(src *BlockSource, index uint32) ([]byte, error) {
	offset := int64(index) * externalV2BulkPacketPayloadSize
	want := min(externalV2BulkPacketPayloadSize, int(src.PayloadSize-offset))
	data := make([]byte, want)
	n, err := src.Payload.ReadAt(data, offset)
	if n <= 0 {
		return nil, err
	}
	data = data[:n]
	if err := externalV2BlockReadError(err, n, want, offset+int64(n), src.PayloadSize); err != nil {
		return nil, err
	}
	return data, nil
}

func writeExternalV2BulkPacketControl(path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, header externalV2BulkPacketHeader, payload []byte) error {
	return writeExternalV2BulkPacketWithAEAD(path, auth.control, header, payload)
}

func writeExternalV2BulkPacketWithAEAD(path externalV2BulkPacketPath, aead cipher.AEAD, header externalV2BulkPacketHeader, payload []byte) error {
	packet, err := sealExternalV2BulkPacket(aead, header, payload)
	if err != nil {
		return err
	}
	laneCount := min(len(path.Conns), len(path.Addrs))
	if laneCount == 0 {
		return errors.New("no bulk packet control path")
	}
	var lastErr error
	var wrote bool
	for lane := range laneCount {
		n, err := path.Conns[lane].WriteTo(packet, path.Addrs[lane])
		if err != nil {
			lastErr = err
			continue
		}
		if n != len(packet) {
			lastErr = io.ErrShortWrite
			continue
		}
		wrote = true
	}
	if wrote {
		return nil
	}
	return lastErr
}

func openExternalV2BulkPacketPrimaryComplete(aead cipher.AEAD, packet []byte, nonce *[externalV2BulkPacketMaximumNonceSize]byte) (externalV2BulkPacketHeader, bool) {
	header, payload, opened := openExternalV2BulkPacketIntoWithNonce(aead, packet, nil, nonce)
	if !opened || header.kind != externalV2BulkPacketPrimaryComplete || header.length != 0 || len(payload) != 0 {
		return externalV2BulkPacketHeader{}, false
	}
	return header, true
}

func stopExternalV2BulkPacketTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func resetExternalV2BulkPacketTimer(timer *time.Timer, d time.Duration) {
	stopExternalV2BulkPacketTimer(timer)
	timer.Reset(d)
}

func sealExternalV2BulkPacket(aead cipher.AEAD, header externalV2BulkPacketHeader, payload []byte) ([]byte, error) {
	return sealExternalV2BulkPacketInto(aead, nil, header, payload)
}

func sealExternalV2BulkPacketInto(aead cipher.AEAD, dst []byte, header externalV2BulkPacketHeader, payload []byte) ([]byte, error) {
	if aead == nil {
		return nil, errors.New("nil bulk packet AEAD")
	}
	if len(payload) > externalV2BulkPacketPayloadSize && header.kind == externalV2BulkPacketData {
		return nil, fmt.Errorf("bulk packet payload too large: %d", len(payload))
	}
	header.length = uint16(len(payload))
	wantCapacity := externalV2BulkPacketHeaderSize + len(payload) + aead.Overhead()
	if cap(dst) < wantCapacity {
		dst = make([]byte, externalV2BulkPacketHeaderSize, wantCapacity)
	} else {
		dst = dst[:externalV2BulkPacketHeaderSize]
		clear(dst)
	}
	out := dst
	fillExternalV2BulkPacketHeader(out, header)
	nonceSize := aead.NonceSize()
	if nonceSize < 12 || nonceSize > externalV2BulkPacketMaximumNonceSize {
		return nil, fmt.Errorf("unsupported bulk packet AEAD nonce size %d", nonceSize)
	}
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	fillExternalV2BulkPacketNonce(nonce[:nonceSize], header)
	out = aead.Seal(out, nonce[:nonceSize], payload, out[:externalV2BulkPacketHeaderSize])
	return out, nil
}

func openExternalV2BulkPacket(aead cipher.AEAD, packet []byte) (externalV2BulkPacketHeader, []byte, bool) {
	return openExternalV2BulkPacketInto(aead, packet, nil)
}

func openExternalV2BulkPacketInto(aead cipher.AEAD, packet []byte, dst []byte) (externalV2BulkPacketHeader, []byte, bool) {
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	return openExternalV2BulkPacketIntoWithNonce(aead, packet, dst, &nonce)
}

func openExternalV2BulkPacketIntoWithNonce(aead cipher.AEAD, packet []byte, dst []byte, nonce *[externalV2BulkPacketMaximumNonceSize]byte) (externalV2BulkPacketHeader, []byte, bool) {
	header, ok := parseExternalV2BulkPacketHeader(packet)
	if !ok || aead == nil {
		return externalV2BulkPacketHeader{}, nil, false
	}
	nonceSize := aead.NonceSize()
	if nonceSize < 12 || nonceSize > len(nonce) {
		return externalV2BulkPacketHeader{}, nil, false
	}
	ciphertextLen := len(packet) - externalV2BulkPacketHeaderSize
	if ciphertextLen != int(header.length)+aead.Overhead() {
		return externalV2BulkPacketHeader{}, nil, false
	}
	fillExternalV2BulkPacketNonce(nonce[:nonceSize], header)
	payload, err := aead.Open(dst, nonce[:nonceSize], header.payload, packet[:externalV2BulkPacketHeaderSize])
	if err != nil {
		return externalV2BulkPacketHeader{}, nil, false
	}
	return header, payload, true
}

func parseExternalV2BulkPacketHeader(packet []byte) (externalV2BulkPacketHeader, bool) {
	if len(packet) < externalV2BulkPacketHeaderSize || !externalV2BulkPacketHasMagic(packet) {
		return externalV2BulkPacketHeader{}, false
	}
	length := binary.BigEndian.Uint16(packet[24:26])
	if len(packet) < externalV2BulkPacketHeaderSize+int(length) {
		return externalV2BulkPacketHeader{}, false
	}
	return externalV2BulkPacketHeader{
		kind:    packet[4],
		runID:   binary.BigEndian.Uint64(packet[8:16]),
		index:   binary.BigEndian.Uint32(packet[16:20]),
		total:   binary.BigEndian.Uint32(packet[20:24]),
		length:  length,
		payload: packet[externalV2BulkPacketHeaderSize:],
	}, true
}

func externalV2BulkPacketHasMagic(packet []byte) bool {
	for i, b := range externalV2BulkPacketMagic {
		if packet[i] != b {
			return false
		}
	}
	return true
}

func fillExternalV2BulkPacketHeader(packet []byte, header externalV2BulkPacketHeader) {
	copy(packet[:4], externalV2BulkPacketMagic[:])
	packet[4] = header.kind
	binary.BigEndian.PutUint64(packet[8:16], header.runID)
	binary.BigEndian.PutUint32(packet[16:20], header.index)
	binary.BigEndian.PutUint32(packet[20:24], header.total)
	binary.BigEndian.PutUint16(packet[24:26], header.length)
}

func externalV2BulkPacketNonce(header externalV2BulkPacketHeader) [externalV2BulkPacketMaximumNonceSize]byte {
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	fillExternalV2BulkPacketNonce(nonce[:], header)
	return nonce
}

func fillExternalV2BulkPacketNonce(nonce []byte, header externalV2BulkPacketHeader) {
	clear(nonce)
	if len(nonce) >= externalV2BulkPacketMaximumNonceSize {
		binary.BigEndian.PutUint64(nonce[:8], header.runID)
		nonce[8] = header.kind
		binary.BigEndian.PutUint32(nonce[9:13], header.index)
		binary.BigEndian.PutUint32(nonce[13:17], header.total)
		binary.BigEndian.PutUint16(nonce[17:19], header.length)
		return
	}
	// Session keys are unique per transfer. Retain part of the random run ID,
	// then use kind, index, and total to keep probe, data, and control nonces
	// distinct within the AES-GCM key.
	nonce[0] = byte(header.runID >> 16)
	nonce[1] = byte(header.runID >> 8)
	nonce[2] = byte(header.runID)
	nonce[3] = header.kind
	binary.BigEndian.PutUint32(nonce[4:8], header.index)
	binary.BigEndian.PutUint32(nonce[8:12], header.total)
}

func encodeExternalV2BulkPacketMissing(missing []uint32) []byte {
	out := make([]byte, len(missing)*4)
	for i, index := range missing {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], index)
	}
	return out
}

func encodeExternalV2BulkPacketAck(bytes, window int64) []byte {
	payload := make([]byte, 16)
	binary.BigEndian.PutUint64(payload, uint64(max(int64(0), bytes)))
	binary.BigEndian.PutUint64(payload[8:], uint64(max(int64(1), window)))
	return payload
}

func decodeExternalV2BulkPacketAck(payload []byte) (int64, int64, bool) {
	if len(payload) != 8 && len(payload) != 16 {
		return 0, 0, false
	}
	bytes := binary.BigEndian.Uint64(payload)
	if bytes > math.MaxInt64 {
		return 0, 0, false
	}
	window := int64(externalV2BulkPacketBufferedReceiveWindow)
	if len(payload) == 16 {
		encodedWindow := binary.BigEndian.Uint64(payload[8:])
		if encodedWindow == 0 || encodedWindow > math.MaxInt64 || encodedWindow > externalV2BulkPacketFallbackReceiveWindow {
			return 0, 0, false
		}
		window = int64(encodedWindow)
	}
	return int64(bytes), window, true
}

func decodeExternalV2BulkPacketMissing(payload []byte) []uint32 {
	if len(payload)%4 != 0 {
		return nil
	}
	out := make([]uint32, 0, len(payload)/4)
	for len(payload) > 0 {
		out = append(out, binary.BigEndian.Uint32(payload[:4]))
		payload = payload[4:]
	}
	return out
}

func externalV2BulkPacketPrimaryLane(index uint32, laneCount int) int {
	if laneCount <= 1 {
		return 0
	}
	return int(index % uint32(laneCount))
}

func externalV2BulkPacketRepairLane(index uint32, laneCount int, attempt uint64) int {
	primary := externalV2BulkPacketPrimaryLane(index, laneCount)
	if laneCount <= 1 {
		return primary
	}
	return (primary + 1 + int(attempt%uint64(laneCount-1))) % laneCount
}

func externalV2BulkPacketRateLimit(mbps int) rate.Limit {
	return rate.Limit(float64(mbps) * 1000 * 1000 / 8)
}

func externalV2BulkPacketCount(sizeBytes int64) uint32 {
	if sizeBytes <= 0 {
		return 0
	}
	return uint32((sizeBytes + externalV2BulkPacketPayloadSize - 1) / externalV2BulkPacketPayloadSize)
}

func externalV2BulkPacketPayloadLength(index uint32, sizeBytes int64) int {
	offset := int64(index) * externalV2BulkPacketPayloadSize
	if offset >= sizeBytes {
		return 0
	}
	return min(externalV2BulkPacketPayloadSize, int(sizeBytes-offset))
}

func randomExternalV2BulkPacketRunID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}

func externalV2BulkPacketSendStats(
	payloadSize int64,
	primaryPayloadBytes int64,
	directPacketBytes int64,
	repairPackets int64,
	repairBytes int64,
	repairRequests int64,
	lanes int,
	initialPaceMbps int,
	paceMbps int,
	committed bool,
) externalDirectTransferStats {
	committedBytes := int64(0)
	if committed {
		committedBytes = payloadSize
	}
	return externalDirectTransferStats{
		BytesSent:   primaryPayloadBytes,
		Retransmits: repairPackets,
		Diagnostics: externalDirectTransferDiagnostics{
			RateSelectedMbps:     initialPaceMbps,
			RateTargetMbps:       paceMbps,
			RateCeilingMbps:      externalV2BulkPacketCeilingWireMbps,
			ActiveLanes:          lanes,
			AvailableLanes:       lanes,
			Retransmits:          repairPackets,
			RepairRequests:       repairRequests,
			RepairBytes:          repairBytes,
			DirectPacketBytes:    directPacketBytes,
			DirectCommittedBytes: committedBytes,
		},
	}
}

func externalV2BulkPacketReceiveStats(
	payloadSize int64,
	receivedPayload int64,
	repairRequests int64,
	lanes int,
	repairStats externalV2BulkPacketMissingStats,
	reorderTrailPackets uint32,
	receivePacketRatePPS uint32,
) externalDirectTransferStats {
	return externalDirectTransferStats{
		BytesReceived: receivedPayload,
		Diagnostics: externalDirectTransferDiagnostics{
			ActiveLanes:                lanes,
			AvailableLanes:             lanes,
			ControllerDecision:         "bulk-packets",
			ControllerReason:           "selective-repair",
			RepairRequests:             repairRequests,
			DirectPacketBytes:          receivedPayload,
			DirectCommittedBytes:       receivedPayload,
			ReceiverCommittedBytes:     uint64(receivedPayload),
			RateSelectedMbps:           0,
			RateTargetMbps:             0,
			RateCeilingMbps:            0,
			RateExplorationCeilingMbps: 0,
			MissingScanChecks:          repairStats.ScanChecks,
			PendingMissing:             repairStats.Pending,
			PendingMissingPeak:         repairStats.PendingPeak,
			RepairRequestedPackets:     repairStats.RequestedPackets,
			RepairRequestBatches:       repairStats.RequestBatches,
			ReorderTrailPackets:        reorderTrailPackets,
			ReceivePacketRatePPS:       receivePacketRatePPS,
		},
	}
}
