// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shayne/derphole/pkg/token"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/time/rate"
	"tailscale.com/types/key"
)

const (
	externalV2BulkPacketPayloadSize       = 1358
	externalV2BulkPacketMaxSize           = 1400
	externalV2BulkPacketHeaderSize        = 26
	externalV2BulkPacketRepairWait        = 30 * time.Second
	externalV2BulkPacketReadIdle          = 100 * time.Millisecond
	externalV2BulkPacketActiveRepair      = 100 * time.Millisecond
	externalV2BulkPacketActiveRepairTrail = 8192
	externalV2BulkPacketRepairSkip        = 250 * time.Millisecond
	externalV2BulkPacketDoneRepeats       = 5
	externalV2BulkPacketMaxMissing        = 300
	externalV2BulkPacketMissingLookahead  = 4096
	externalV2BulkPacketDataQueue         = 4096
	externalV2BulkPacketRepairQueue       = 1024
	externalV2BulkPacketReceiveGroupBytes = 64 << 10
	externalV2BulkPacketWriteRetryDelay   = 100 * time.Microsecond
)

const (
	externalV2BulkPacketData  byte = 1
	externalV2BulkPacketMiss  byte = 2
	externalV2BulkPacketDone  byte = 3
	externalV2BulkPacketHello byte = 4
)

var (
	externalV2BulkPacketMagic      = [4]byte{'D', 'V', '2', 'B'}
	externalV2BulkPacketAEADDomain = []byte("derphole-v2-bulk-packet-aead-v1")
)

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
	header externalV2BulkPacketHeader
	data   []byte
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
	return externalV2BulkPacketAuth{data: data, control: control}, nil
}

func externalV2BulkPacketAEAD(tok token.Token, senderDERP key.NodePublic, receiverDERP key.NodePublic, label string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, tok.BearerSecret[:])
	mac.Write(externalV2BulkPacketAEADDomain)
	mac.Write(tok.SessionID[:])
	mac.Write(senderDERP.AppendTo(nil))
	mac.Write(receiverDERP.AppendTo(nil))
	mac.Write([]byte(label))
	keyBytes := mac.Sum(nil)
	return chacha20poly1305.NewX(keyBytes[:chacha20poly1305.KeySize])
}

func sendExternalV2BulkBlockPackets(ctx context.Context, src *BlockSource, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics) (externalDirectTransferStats, error) {
	if err := validateExternalV2BulkPacketSender(src, path, auth); err != nil {
		return externalDirectTransferStats{}, err
	}

	sendCtx, cancel := context.WithCancel(ctx)
	sender := newExternalV2BulkPacketSender(sendCtx, src, path, auth, metrics)
	writeDeadlineDone := startExternalV2BulkPacketWriteDeadlineCancel(sendCtx, path)

	missingCh := make(chan []uint32, externalV2BulkPacketRepairQueue)
	doneCh := make(chan struct{}, 1)
	helloCh := make(chan struct{}, 1)
	workerErrCh := make(chan error, len(path.Conns)+1)
	controlDone := startExternalV2BulkPacketControlReaders(sendCtx, path, auth, sender.runID, sender.totalPackets, missingCh, doneCh, helloCh, workerErrCh, &sender.repairRequests)
	if err := waitExternalV2BulkPacketHello(ctx, helloCh, workerErrCh); err != nil {
		cancel()
		deadlineErr := <-writeDeadlineDone
		<-controlDone
		cleanupErr := clearExternalV2BulkPacketDeadlines(path)
		return sender.stats(false), errors.Join(err, deadlineErr, cleanupErr)
	}

	controllerDone := sender.startController(sendCtx)
	repairActivityCh := make(chan struct{}, 1)
	repairDone := sender.startRepairWorker(sendCtx, missingCh, repairActivityCh, workerErrCh)

	err := sender.sendInitialPacketsUntilWorkerFailure(sendCtx, cancel, workerErrCh)
	committed := false
	if err == nil {
		err = sender.waitForCompletion(doneCh, repairActivityCh, workerErrCh)
		committed = err == nil
	}
	cancel()
	deadlineErr := <-writeDeadlineDone
	<-controllerDone
	<-repairDone
	<-controlDone
	cleanupErr := clearExternalV2BulkPacketDeadlines(path)
	return sender.stats(committed), errors.Join(err, deadlineErr, cleanupErr)
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
	ctx                 context.Context
	src                 *BlockSource
	path                externalV2BulkPacketPath
	auth                externalV2BulkPacketAuth
	metrics             *externalTransferMetrics
	initialPaceMbps     int
	runID               uint64
	totalPackets        uint32
	laneCount           int
	pacer               *rate.Limiter
	controller          *externalV2BulkPacketController
	sentPackets         atomic.Uint64
	sentPayload         atomic.Int64
	primaryPayloadBytes atomic.Int64
	primaryWireBytes    atomic.Int64
	repairWireBytes     atomic.Int64
	repairPackets       atomic.Int64
	repairPayloadBytes  atomic.Int64
	repairRequests      atomic.Int64
	currentPaceMbps     atomic.Int64

	localENOBUFSRetries        atomic.Int64
	localENOBUFSWaitNanos      atomic.Int64
	localENOBUFSMaxConsecutive atomic.Int64
}

func newExternalV2BulkPacketSender(ctx context.Context, src *BlockSource, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics) *externalV2BulkPacketSender {
	initialPaceMbps := externalV2BulkPacketInitialWireMbps()
	controller := newExternalV2BulkPacketController(initialPaceMbps)
	sender := &externalV2BulkPacketSender{
		ctx:             ctx,
		src:             src,
		path:            path,
		auth:            auth,
		metrics:         metrics,
		initialPaceMbps: initialPaceMbps,
		runID:           randomExternalV2BulkPacketRunID(),
		totalPackets:    externalV2BulkPacketCount(src.PayloadSize),
		laneCount:       min(len(path.Conns), len(path.Addrs)),
		pacer: rate.NewLimiter(
			externalV2BulkPacketRateLimit(initialPaceMbps),
			externalV2BulkPacketPaceBurstBytes,
		),
		controller: controller,
	}
	sender.currentPaceMbps.Store(int64(initialPaceMbps))
	return sender
}

func (s *externalV2BulkPacketSender) sendInitialPackets() error {
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
	sentRepair := false
	now := time.Now()
	for _, index := range missing {
		if !s.shouldRepairMissing(index, now, lastRepair) {
			continue
		}
		attempt := repairAttempt[index]
		repairAttempt[index] = attempt + 1
		if err := s.sendPacket(index, externalV2BulkPacketRepairLane(index, s.laneCount, attempt), true); err != nil {
			return sentRepair, err
		}
		sentRepair = true
	}
	return sentRepair, nil
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
	s.metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
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
	}, at)
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

func receiveExternalV2BulkBlockPackets(ctx context.Context, sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics) (int64, externalDirectTransferStats, error) {
	if err := validateExternalV2BulkPacketReceiver(sink, cfg, path, auth); err != nil {
		return 0, externalDirectTransferStats{}, err
	}

	receiver := newExternalV2BulkPacketReceiver(sink, cfg, path, auth, metrics)
	recvCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dataCh := make(chan externalV2BulkPacketReceiveResult, externalV2BulkPacketDataQueue)
	errCh := make(chan error, len(path.Conns))
	startExternalV2BulkPacketDataReaders(recvCtx, path, auth, dataCh, errCh)
	receiver.stopHello = startExternalV2BulkPacketHelloLoop(recvCtx, path, auth, receiver.totalPackets)
	defer receiver.stopHello()

	return receiver.run(ctx, dataCh, errCh)
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
	cfg                externalV2BlockReceiveConfig
	path               externalV2BulkPacketPath
	auth               externalV2BulkPacketAuth
	metrics            *externalTransferMetrics
	laneCount          int
	totalPackets       uint32
	seen               []bool
	assembler          *externalV2BulkPacketReceiveAssembler
	runID              uint64
	receivedPackets    uint32
	highestSeenPlusOne uint32
	committedPayload   int64
	repairRequests     int64
	controlSeq         uint32
	lastActiveRepair   time.Time
	stopHello          func()
}

func newExternalV2BulkPacketReceiver(sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, metrics *externalTransferMetrics) *externalV2BulkPacketReceiver {
	laneCount := min(len(path.Conns), len(path.Addrs))
	totalPackets := externalV2BulkPacketCount(cfg.PayloadSize)
	return &externalV2BulkPacketReceiver{
		cfg:          cfg,
		path:         path,
		auth:         auth,
		metrics:      metrics,
		laneCount:    laneCount,
		totalPackets: totalPackets,
		seen:         make([]bool, totalPackets),
		assembler:    newExternalV2BulkPacketReceiveAssembler(sink, cfg, totalPackets),
	}
}

func (r *externalV2BulkPacketReceiver) run(ctx context.Context, dataCh <-chan externalV2BulkPacketReceiveResult, errCh <-chan error) (int64, externalDirectTransferStats, error) {
	for r.receivedPackets < r.totalPackets {
		timer := time.NewTimer(externalV2BulkPacketReadIdle)
		select {
		case result := <-dataCh:
			stopExternalV2BulkPacketTimer(timer)
			if err := r.handleDataResult(result); err != nil {
				return r.result(err)
			}
		case err := <-errCh:
			stopExternalV2BulkPacketTimer(timer)
			if err != nil {
				return r.result(err)
			}
		case <-timer.C:
			r.sendIdleMissing()
		case <-ctx.Done():
			stopExternalV2BulkPacketTimer(timer)
			return r.result(ctx.Err())
		}
	}
	r.sendDoneRepeats()
	return r.result(nil)
}

func (r *externalV2BulkPacketReceiver) handleDataResult(result externalV2BulkPacketReceiveResult) error {
	header := result.header
	if header.total != r.totalPackets || header.index >= r.totalPackets {
		return nil
	}
	if r.runID == 0 {
		r.runID = header.runID
		r.stopHello()
	}
	if header.runID != r.runID || r.seen[header.index] {
		return nil
	}
	if err := r.validateData(header, result.data); err != nil {
		return err
	}
	r.markHighestSeen(header.index)
	n, err := r.assembler.add(header.index, result.data)
	if n > 0 {
		r.committedPayload += int64(n)
		if r.metrics != nil {
			r.metrics.RecordDirectPacketReceive(int64(n), time.Now())
		}
	}
	if err != nil {
		return err
	}
	r.seen[header.index] = true
	r.receivedPackets++
	r.sendActiveMissing(time.Now())
	return nil
}

func (r *externalV2BulkPacketReceiver) validateData(header externalV2BulkPacketHeader, data []byte) error {
	offset := int64(header.index) * externalV2BulkPacketPayloadSize
	wantLen := externalV2BulkPacketPayloadLength(header.index, r.cfg.PayloadSize)
	if len(data) == wantLen && offset+int64(len(data)) <= r.cfg.PayloadSize {
		return nil
	}
	return fmt.Errorf("bulk packet offset %d length %d, want %d within payload size %d", offset, len(data), wantLen, r.cfg.PayloadSize)
}

func (r *externalV2BulkPacketReceiver) markHighestSeen(index uint32) {
	if index+1 > r.highestSeenPlusOne {
		r.highestSeenPlusOne = index + 1
	}
}

func (r *externalV2BulkPacketReceiver) sendIdleMissing() {
	limit := r.totalPackets
	if remaining := r.totalPackets - r.highestSeenPlusOne; remaining > externalV2BulkPacketMissingLookahead {
		limit = r.highestSeenPlusOne + externalV2BulkPacketMissingLookahead
	}
	r.sendMissing(limit)
}

func (r *externalV2BulkPacketReceiver) sendActiveMissing(now time.Time) {
	if r.highestSeenPlusOne <= externalV2BulkPacketActiveRepairTrail || now.Sub(r.lastActiveRepair) < externalV2BulkPacketActiveRepair {
		return
	}
	r.lastActiveRepair = now
	r.sendMissing(r.highestSeenPlusOne - externalV2BulkPacketActiveRepairTrail)
}

func (r *externalV2BulkPacketReceiver) sendMissing(limit uint32) {
	if r.runID == 0 || r.receivedPackets == r.totalPackets {
		return
	}
	for _, missing := range externalV2BulkPacketMissingBatches(r.seen, limit) {
		if len(missing) == 0 {
			continue
		}
		r.sendMissingBatch(missing)
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
	return r.cfg.HeaderBytes + r.committedPayload,
		externalV2BulkPacketReceiveStats(r.cfg.PayloadSize, r.committedPayload, r.repairRequests, r.laneCount),
		err
}

type externalV2BulkPacketReceiveAssembler struct {
	sink            BlockReceiveSink
	payloadSize     int64
	totalPackets    uint32
	packetsPerGroup uint32
	groups          map[uint32]*externalV2BulkPacketReceiveGroup
}

type externalV2BulkPacketReceiveGroup struct {
	baseIndex uint32
	seen      []bool
	data      []byte
	received  uint32
}

func newExternalV2BulkPacketReceiveAssembler(sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, totalPackets uint32) *externalV2BulkPacketReceiveAssembler {
	groupBytes := min(externalV2BlockChunkSize(cfg.ChunkSize), externalV2BulkPacketReceiveGroupBytes)
	packetsPerGroup := uint32(max(1, groupBytes/externalV2BulkPacketPayloadSize))
	return &externalV2BulkPacketReceiveAssembler{
		sink:            sink,
		payloadSize:     cfg.PayloadSize,
		totalPackets:    totalPackets,
		packetsPerGroup: packetsPerGroup,
		groups:          make(map[uint32]*externalV2BulkPacketReceiveGroup),
	}
}

func (a *externalV2BulkPacketReceiveAssembler) add(index uint32, data []byte) (int, error) {
	groupID := index / a.packetsPerGroup
	group := a.groups[groupID]
	if group == nil {
		group = a.newGroup(groupID)
		a.groups[groupID] = group
	}
	groupOffset := index - group.baseIndex
	if groupOffset >= uint32(len(group.seen)) {
		return 0, fmt.Errorf("bulk packet index %d outside receive group %d", index, groupID)
	}
	if group.seen[groupOffset] {
		return 0, nil
	}
	offset := int(groupOffset) * externalV2BulkPacketPayloadSize
	copy(group.data[offset:], data)
	group.seen[groupOffset] = true
	group.received++
	if group.received < uint32(len(group.seen)) {
		return 0, nil
	}
	n, err := a.sink.WriteAt(group.data, int64(group.baseIndex)*externalV2BulkPacketPayloadSize)
	if err != nil {
		return n, err
	}
	if n != len(group.data) {
		return n, io.ErrShortWrite
	}
	delete(a.groups, groupID)
	return n, nil
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

func startExternalV2BulkPacketControlReaders(ctx context.Context, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, runID uint64, totalPackets uint32, missingCh chan<- []uint32, doneCh chan<- struct{}, helloCh chan<- struct{}, errCh chan<- error, repairRequests *atomic.Int64) <-chan struct{} {
	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(len(path.Conns))
	for _, conn := range path.Conns {
		go func(conn net.PacketConn) {
			defer readers.Done()
			readExternalV2BulkPacketControlLoop(ctx, conn, auth, runID, totalPackets, missingCh, doneCh, helloCh, errCh, repairRequests)
		}(conn)
	}
	go func() {
		readers.Wait()
		close(done)
	}()
	return done
}

func readExternalV2BulkPacketControlLoop(ctx context.Context, conn net.PacketConn, auth externalV2BulkPacketAuth, runID uint64, totalPackets uint32, missingCh chan<- []uint32, doneCh chan<- struct{}, helloCh chan<- struct{}, errCh chan<- error, repairRequests *atomic.Int64) {
	buf := make([]byte, externalV2BulkPacketMaxSize)
	for {
		header, payload, ok, stop := readExternalV2BulkPacketControl(ctx, conn, auth, buf, errCh)
		if stop {
			return
		}
		if !ok {
			continue
		}
		if handleExternalV2BulkPacketControl(header, payload, runID, totalPackets, missingCh, doneCh, helloCh, repairRequests) {
			return
		}
	}
}

func readExternalV2BulkPacketControl(ctx context.Context, conn net.PacketConn, auth externalV2BulkPacketAuth, buf []byte, errCh chan<- error) (externalV2BulkPacketHeader, []byte, bool, bool) {
	n, ok, stop := readExternalV2BulkPacketBytes(ctx, conn, buf, errCh)
	if !ok {
		return externalV2BulkPacketHeader{}, nil, false, stop
	}
	header, payload, opened := openExternalV2BulkPacket(auth.control, buf[:n])
	return header, payload, opened, false
}

func handleExternalV2BulkPacketControl(header externalV2BulkPacketHeader, payload []byte, runID uint64, totalPackets uint32, missingCh chan<- []uint32, doneCh chan<- struct{}, helloCh chan<- struct{}, repairRequests *atomic.Int64) bool {
	switch header.kind {
	case externalV2BulkPacketHello:
		handleExternalV2BulkPacketHello(header, totalPackets, helloCh)
	case externalV2BulkPacketMiss:
		handleExternalV2BulkPacketMissing(header, payload, runID, missingCh, repairRequests)
	case externalV2BulkPacketDone:
		return handleExternalV2BulkPacketDone(header, runID, doneCh)
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
	timer := time.NewTimer(externalV2StreamOpenWait)
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

func startExternalV2BulkPacketDataReaders(ctx context.Context, path externalV2BulkPacketPath, auth externalV2BulkPacketAuth, dataCh chan<- externalV2BulkPacketReceiveResult, errCh chan<- error) {
	for _, conn := range path.Conns {
		go readExternalV2BulkPacketDataLoop(ctx, conn, auth, dataCh, errCh)
	}
}

func readExternalV2BulkPacketDataLoop(ctx context.Context, conn net.PacketConn, auth externalV2BulkPacketAuth, dataCh chan<- externalV2BulkPacketReceiveResult, errCh chan<- error) {
	buf := make([]byte, externalV2BulkPacketMaxSize)
	for {
		result, ok, stop := readExternalV2BulkPacketData(ctx, conn, auth, buf, errCh)
		if stop {
			return
		}
		if !ok {
			continue
		}
		select {
		case dataCh <- result:
		case <-ctx.Done():
			return
		}
	}
}

func readExternalV2BulkPacketData(ctx context.Context, conn net.PacketConn, auth externalV2BulkPacketAuth, buf []byte, errCh chan<- error) (externalV2BulkPacketReceiveResult, bool, bool) {
	n, ok, stop := readExternalV2BulkPacketBytes(ctx, conn, buf, errCh)
	if !ok {
		return externalV2BulkPacketReceiveResult{}, false, stop
	}
	header, payload, opened := openExternalV2BulkPacket(auth.data, buf[:n])
	if !opened || header.kind != externalV2BulkPacketData {
		return externalV2BulkPacketReceiveResult{}, false, false
	}
	data := append([]byte(nil), payload...)
	return externalV2BulkPacketReceiveResult{header: header, data: data}, true, false
}

func readExternalV2BulkPacketBytes(ctx context.Context, conn net.PacketConn, buf []byte, errCh chan<- error) (int, bool, bool) {
	if err := conn.SetReadDeadline(time.Now().Add(externalV2BulkPacketReadIdle)); err != nil {
		if errCh != nil {
			offerExternalV2BulkPacketRepairError(errCh, err)
		}
		return 0, false, true
	}
	n, _, err := conn.ReadFrom(buf)
	if err == nil {
		return n, true, false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
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
	packet, err := sealExternalV2BulkPacket(auth.control, header, payload)
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
	if aead == nil {
		return nil, errors.New("nil bulk packet AEAD")
	}
	if len(payload) > externalV2BulkPacketPayloadSize && header.kind == externalV2BulkPacketData {
		return nil, fmt.Errorf("bulk packet payload too large: %d", len(payload))
	}
	header.length = uint16(len(payload))
	out := make([]byte, externalV2BulkPacketHeaderSize, externalV2BulkPacketHeaderSize+len(payload)+aead.Overhead())
	fillExternalV2BulkPacketHeader(out, header)
	nonce := externalV2BulkPacketNonce(header)
	out = aead.Seal(out, nonce[:], payload, out[:externalV2BulkPacketHeaderSize])
	return out, nil
}

func openExternalV2BulkPacket(aead cipher.AEAD, packet []byte) (externalV2BulkPacketHeader, []byte, bool) {
	header, ok := parseExternalV2BulkPacketHeader(packet)
	if !ok || aead == nil {
		return externalV2BulkPacketHeader{}, nil, false
	}
	ciphertextLen := len(packet) - externalV2BulkPacketHeaderSize
	if ciphertextLen != int(header.length)+aead.Overhead() {
		return externalV2BulkPacketHeader{}, nil, false
	}
	nonce := externalV2BulkPacketNonce(header)
	payload, err := aead.Open(nil, nonce[:], header.payload, packet[:externalV2BulkPacketHeaderSize])
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

func externalV2BulkPacketNonce(header externalV2BulkPacketHeader) [chacha20poly1305.NonceSizeX]byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	binary.BigEndian.PutUint64(nonce[:8], header.runID)
	nonce[8] = header.kind
	binary.BigEndian.PutUint32(nonce[9:13], header.index)
	binary.BigEndian.PutUint32(nonce[13:17], header.total)
	binary.BigEndian.PutUint16(nonce[17:19], header.length)
	return nonce
}

func encodeExternalV2BulkPacketMissing(missing []uint32) []byte {
	out := make([]byte, len(missing)*4)
	for i, index := range missing {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], index)
	}
	return out
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

func externalV2BulkPacketMissingBatches(seen []bool, limit uint32) [][]uint32 {
	limit = min(limit, uint32(len(seen)))
	var batches [][]uint32
	current := make([]uint32, 0, externalV2BulkPacketMaxMissing)
	for index := range int(limit) {
		if seen[index] {
			continue
		}
		current = append(current, uint32(index))
		if len(current) == externalV2BulkPacketMaxMissing {
			batches = append(batches, append([]uint32(nil), current...))
			current = current[:0]
		}
	}
	if len(current) > 0 {
		batches = append(batches, append([]uint32(nil), current...))
	}
	return batches
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

func externalV2BulkPacketReceiveStats(payloadSize int64, receivedPayload int64, repairRequests int64, lanes int) externalDirectTransferStats {
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
		},
	}
}
