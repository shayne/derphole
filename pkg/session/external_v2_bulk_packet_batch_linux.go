// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	externalV2BulkPacketMaxIPv4Payload = 1<<16 - 1 - 20 - 8
	// Keep each software-segmented skb to a few qdisc quanta so a single local
	// queue drop cannot discard a large fraction of the sender window. All GSO
	// messages still share one sendmmsg call per logical batch.
	externalV2BulkPacketLinuxGSOSegmentsPerMessage = 3
)

type externalV2BulkPacketLinuxBatchConn struct {
	conn               net.PacketConn
	rawConn            syscall.RawConn
	stats              *externalV2BulkPacketAtomicBatchStats
	gsoCapable         atomic.Bool
	connected          bool
	candidateConfig    externalV2BulkPacketCandidateConfig
	candidateErr       error
	sendMMsg           externalV2BulkPacketLinuxSendSyscall
	sendScratch        *externalV2BulkPacketLinuxSendScratch
	connectedWriteGate chan struct{}
	connectedGateOnce  sync.Once
	writeCancelMu      sync.Mutex
	writeCancelSet     bool
	writeCancelDone    <-chan struct{}
	writeCancelStop    func() bool
	writeCancelFinish  chan struct{}
	readHeaders        [externalV2BulkPacketMaxBatch]externalV2BulkPacketMMsgHdr
	readIovecs         [externalV2BulkPacketMaxBatch]unix.Iovec
	readDeadline       time.Time
	readDeadlineArmed  bool
}

type externalV2BulkPacketMMsgHdr struct {
	hdr unix.Msghdr
	len uint32
}

func newExternalV2BulkPacketBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	candidateConfig, candidateErr := externalV2BulkPacketConfiguredCandidate()
	if candidateErr != nil {
		return &externalV2BulkPacketLinuxBatchConn{
			conn:         conn,
			stats:        newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
			candidateErr: candidateErr,
		}
	}
	if _, ok := conn.(net.Conn); !ok {
		return newExternalV2BulkPacketPortableBatchConn(conn)
	}
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return newExternalV2BulkPacketPortableBatchConn(conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return newExternalV2BulkPacketPortableBatchConn(conn)
	}
	batch := &externalV2BulkPacketLinuxBatchConn{
		conn:               conn,
		rawConn:            rawConn,
		stats:              newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		candidateConfig:    candidateConfig,
		candidateErr:       candidateErr,
		sendMMsg:           externalV2BulkPacketLinuxSendMMsgSyscall,
		sendScratch:        newExternalV2BulkPacketLinuxSendScratch(),
		connectedWriteGate: newExternalV2BulkPacketConnectedWriteGate(),
	}
	batch.stats.setCandidateID(candidateConfig.ID)
	batch.gsoCapable.Store(externalV2BulkPacketLinuxGSOCapable(conn))
	return batch
}

func (c *externalV2BulkPacketLinuxBatchConn) enableFixedPeerConnect(peer net.Addr) error {
	if c.candidateErr != nil {
		return c.candidateErr
	}
	if !c.candidateConfig.NativeConnectedSend {
		return nil
	}
	if err := externalV2BulkPacketLinuxConnectFixedPeer(c.rawConn, peer); err != nil {
		return err
	}
	c.connected = true
	return nil
}

func (c *externalV2BulkPacketLinuxBatchConn) WriteBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.candidateErr != nil {
		return 0, c.candidateErr
	}
	if len(messages) == 0 {
		return 0, nil
	}
	if err := c.acquireConnectedWriteGate(ctx); err != nil {
		return 0, err
	}
	defer c.releaseConnectedWriteGate()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.armConnectedWriteCancellation(ctx)
	if err := externalV2BulkPacketArmWriteDeadline(ctx, c.conn); err != nil {
		return 0, err
	}
	written, err := c.writePreparedBatch(messages)
	if err != nil && ctx.Err() != nil {
		return written, ctx.Err()
	}
	return written, err
}

func newExternalV2BulkPacketConnectedWriteGate() chan struct{} {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return gate
}

func (c *externalV2BulkPacketLinuxBatchConn) initializedConnectedWriteGate() chan struct{} {
	c.connectedGateOnce.Do(func() {
		if c.connectedWriteGate == nil {
			c.connectedWriteGate = newExternalV2BulkPacketConnectedWriteGate()
		}
	})
	return c.connectedWriteGate
}

func (c *externalV2BulkPacketLinuxBatchConn) acquireConnectedWriteGate(ctx context.Context) error {
	gate := c.initializedConnectedWriteGate()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate:
	}
	if err := ctx.Err(); err != nil {
		gate <- struct{}{}
		return err
	}
	return nil
}

func (c *externalV2BulkPacketLinuxBatchConn) releaseConnectedWriteGate() {
	c.initializedConnectedWriteGate() <- struct{}{}
}

func (c *externalV2BulkPacketLinuxBatchConn) armConnectedWriteCancellation(ctx context.Context) {
	done := ctx.Done()
	c.writeCancelMu.Lock()
	defer c.writeCancelMu.Unlock()
	if c.writeCancelSet && done == c.writeCancelDone {
		return
	}
	if !c.writeCancelSet && done == nil {
		return
	}
	if c.writeCancelSet {
		c.stopConnectedWriteCancellationLocked()
		if c.conn != nil {
			_ = c.conn.SetWriteDeadline(time.Time{})
		}
	}
	if done == nil || c.conn == nil {
		return
	}
	finished := make(chan struct{})
	conn := c.conn
	c.writeCancelSet = true
	c.writeCancelDone = done
	c.writeCancelFinish = finished
	c.writeCancelStop = context.AfterFunc(ctx, func() {
		_ = conn.SetWriteDeadline(time.Now())
		close(finished)
	})
}

func (c *externalV2BulkPacketLinuxBatchConn) disarmWriteCancellation() {
	gate := c.initializedConnectedWriteGate()
	<-gate
	defer func() { gate <- struct{}{} }()
	c.writeCancelMu.Lock()
	defer c.writeCancelMu.Unlock()
	c.stopConnectedWriteCancellationLocked()
}

func (c *externalV2BulkPacketLinuxBatchConn) stopConnectedWriteCancellationLocked() {
	if !c.writeCancelSet {
		return
	}
	if !c.writeCancelStop() {
		<-c.writeCancelFinish
	}
	c.writeCancelSet = false
	c.writeCancelDone = nil
	c.writeCancelStop = nil
	c.writeCancelFinish = nil
}

func (c *externalV2BulkPacketLinuxBatchConn) writePreparedBatch(messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.connected {
		segments := c.candidateConfig.GSOSegments
		if segments == 0 {
			segments = 1
		}
		if segments > 1 && c.gsoCapable.Load() {
			return c.writeConnectedGSO(messages, segments)
		}
		return c.writeConnectedSendMMsg(messages)
	}
	if !c.gsoCapable.Load() {
		return c.writeSendMMsg(messages)
	}
	if !externalV2BulkPacketCanGSO(messages) {
		return c.writeSendMMsg(messages)
	}
	if handled, written, err := c.tryWriteGSO(messages); handled {
		return written, err
	}
	return c.writeSendMMsg(messages)
}

func (c *externalV2BulkPacketLinuxBatchConn) writeConnectedGSO(messages []externalV2BulkPacketBatchMessage, segments int) (int, error) {
	if c.sendScratch == nil {
		c.sendScratch = newExternalV2BulkPacketLinuxSendScratch()
	}
	headers, groupEnds, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, segments, c.sendScratch)
	if err != nil {
		return 0, err
	}
	preparedMessages := messages[:groupEnds[len(groupEnds)-1]]
	c.stats.gsoAttempted.Store(true)
	writtenGroups, sendErr := c.sendScratch.sendMMsg(c.rawConn, headers, c.sendMMsg, c.stats)
	written := externalV2BulkPacketLinuxGSOWritten(writtenGroups, groupEnds)
	c.stats.observeNativeAccepted(preparedMessages, written, writtenGroups, segments)
	for index := range preparedMessages {
		runtime.KeepAlive(preparedMessages[index].Buffers[0])
	}
	runtime.KeepAlive(messages)
	runtime.KeepAlive(headers)
	runtime.KeepAlive(&c.sendScratch.iovecs)
	runtime.KeepAlive(c.sendScratch.control)
	runtime.KeepAlive(c.sendScratch)
	externalV2BulkPacketResetLinuxConnectedSendScratch(c.sendScratch)
	if written > 0 {
		c.observeGSOSuccess(written)
		for index := range written {
			messages[index].N = len(messages[index].Buffers[0])
		}
	}
	if sendErr == nil {
		return written, nil
	}
	if !externalV2BulkPacketShouldDisableGSO(sendErr) {
		return written, sendErr
	}
	c.disableGSO()
	if written >= len(preparedMessages) {
		return written, nil
	}
	fallbackWritten, fallbackErr := c.writeConnectedSendMMsg(preparedMessages[written:])
	return written + fallbackWritten, fallbackErr
}

func (c *externalV2BulkPacketLinuxBatchConn) writeConnectedSendMMsg(messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.sendScratch == nil {
		c.sendScratch = newExternalV2BulkPacketLinuxSendScratch()
	}
	headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, c.sendScratch)
	if err != nil {
		return 0, err
	}
	preparedMessages := messages[:len(headers)]
	written, sendErr := c.sendScratch.sendMMsg(c.rawConn, headers, c.sendMMsg, c.stats)
	c.stats.observeNativeAccepted(preparedMessages, written, 0, 0)
	for index := range preparedMessages {
		runtime.KeepAlive(preparedMessages[index].Buffers[0])
	}
	runtime.KeepAlive(messages)
	runtime.KeepAlive(headers)
	runtime.KeepAlive(&c.sendScratch.iovecs)
	runtime.KeepAlive(c.sendScratch)
	externalV2BulkPacketResetLinuxConnectedSendScratch(c.sendScratch)
	if written > 0 {
		c.stats.setBackend("linux-sendmmsg")
		c.stats.observeSend(written)
		for index := range written {
			messages[index].N = len(messages[index].Buffers[0])
		}
	}
	return written, sendErr
}

func (c *externalV2BulkPacketLinuxBatchConn) tryWriteGSO(messages []externalV2BulkPacketBatchMessage) (bool, int, error) {
	c.stats.gsoAttempted.Store(true)
	written, err := c.writeGSO(messages)
	if written > 0 {
		c.observeGSOSuccess(written)
		return true, written, err
	}
	if err == nil {
		return true, 0, nil
	}
	if !externalV2BulkPacketShouldDisableGSO(err) {
		return true, 0, err
	}
	c.disableGSO()
	return false, 0, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) observeGSOSuccess(count int) {
	c.stats.gsoActive.Store(true)
	c.stats.gsoSegments.Add(uint64(count))
	c.stats.setBackend("linux-gso")
	c.stats.observeSend(count)
}

func (c *externalV2BulkPacketLinuxBatchConn) disableGSO() {
	c.gsoCapable.Store(false)
	c.stats.gsoActive.Store(false)
	c.stats.setBackend("linux-sendmmsg")
}

func (c *externalV2BulkPacketLinuxBatchConn) writeSendMMsg(messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.sendScratch == nil {
		c.sendScratch = newExternalV2BulkPacketLinuxSendScratch()
	}
	headers, err := externalV2BulkPacketPrepareLinuxAddressedSend(messages, c.sendScratch)
	if err != nil {
		return 0, err
	}
	preparedMessages := messages[:len(headers)]
	written, sendErr := c.sendScratch.sendMMsg(c.rawConn, headers, c.sendMMsg, c.stats)
	c.stats.observeNativeAccepted(preparedMessages, written, 0, 0)
	for index := range preparedMessages {
		runtime.KeepAlive(preparedMessages[index].Buffers[0])
	}
	runtime.KeepAlive(messages)
	runtime.KeepAlive(headers)
	runtime.KeepAlive(&c.sendScratch.iovecs)
	runtime.KeepAlive(&c.sendScratch.sockaddrs)
	runtime.KeepAlive(c.sendScratch)
	externalV2BulkPacketResetLinuxConnectedSendScratch(c.sendScratch)
	if written > 0 {
		c.stats.setBackend("linux-sendmmsg")
		c.stats.observeSend(written)
		for index := 0; index < written; index++ {
			messages[index].N = externalV2BulkPacketMessageLength(messages[index].Buffers)
		}
	}
	return written, sendErr
}

func (c *externalV2BulkPacketLinuxBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.candidateErr != nil {
		return 0, c.candidateErr
	}
	messages, headers, err := externalV2BulkPacketPrepareRead(messages, c.readHeaders[:], c.readIovecs[:])
	if err != nil || len(messages) == 0 {
		return 0, err
	}
	return c.readPreparedBatch(ctx, messages, headers)
}

func externalV2BulkPacketPrepareRead(
	messages []externalV2BulkPacketBatchMessage,
	headers []externalV2BulkPacketMMsgHdr,
	iovecs []unix.Iovec,
) ([]externalV2BulkPacketBatchMessage, []externalV2BulkPacketMMsgHdr, error) {
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	if len(headers) < len(messages) || len(iovecs) < len(messages) {
		return nil, nil, errors.New("bulk packet receive scratch is too small")
	}
	headers = headers[:len(messages)]
	iovecs = iovecs[:len(messages)]
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 {
			return nil, nil, errors.New("bulk packet connected receive requires one non-empty buffer")
		}
		buffer := messages[index].Buffers[0]
		iovecs[index].Base = &buffer[0]
		iovecs[index].SetLen(len(buffer))
		headers[index] = externalV2BulkPacketMMsgHdr{hdr: unix.Msghdr{
			Iov: &iovecs[index], Iovlen: 1,
		}}
		messages[index].Addr = nil
		messages[index].N = 0
		messages[index].NN = 0
		messages[index].Flags = 0
	}
	return messages, headers, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) readPreparedBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage, headers []externalV2BulkPacketMMsgHdr) (int, error) {
	for {
		read, retry, err := c.readBatchAttempt(ctx, headers)
		if err != nil {
			return 0, err
		}
		if retry {
			continue
		}
		return c.finishReadBatch(messages, headers, read)
	}
}

func (c *externalV2BulkPacketLinuxBatchConn) finishReadBatch(messages []externalV2BulkPacketBatchMessage, headers []externalV2BulkPacketMMsgHdr, read int) (int, error) {
	if err := externalV2BulkPacketCopyReadBatch(messages, headers, read); err != nil {
		return 0, err
	}
	c.stats.setBackend("linux-recvmmsg")
	c.stats.observeReceive(read)
	return read, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) readBatchAttempt(ctx context.Context, headers []externalV2BulkPacketMMsgHdr) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	deadline := externalV2BulkPacketBatchDeadline(ctx, time.Now())
	if !c.readDeadlineArmed || deadline.Before(c.readDeadline) {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return 0, false, err
		}
		c.readDeadline = deadline
		c.readDeadlineArmed = true
	}
	read, err := externalV2BulkPacketRecvMMsg(c.rawConn, headers)
	if err == nil {
		return read, false, nil
	}
	c.readDeadlineArmed = false
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	return externalV2BulkPacketClassifyReadError(ctx, err)
}

func externalV2BulkPacketRecvMMsg(rawConn syscall.RawConn, headers []externalV2BulkPacketMMsgHdr) (int, error) {
	if rawConn == nil || len(headers) == 0 {
		return 0, errors.New("bulk packet recvmmsg has no socket or buffers")
	}
	read := 0
	var receiveErr error
	err := rawConn.Read(func(fd uintptr) bool {
		count, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&headers[0])),
			uintptr(len(headers)),
			0,
			0,
			0,
		)
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false
		}
		if errno != 0 {
			receiveErr = errno
		} else {
			read = int(count)
		}
		return true
	})
	runtime.KeepAlive(headers)
	if err != nil {
		return 0, err
	}
	return read, receiveErr
}

func externalV2BulkPacketClassifyReadError(ctx context.Context, err error) (int, bool, error) {
	networkError, ok := err.(net.Error)
	if !ok {
		return 0, false, err
	}
	if !networkError.Timeout() {
		return 0, false, err
	}
	if ctx.Err() != nil {
		return 0, false, ctx.Err()
	}
	return 0, true, nil
}

func externalV2BulkPacketCopyReadBatch(messages []externalV2BulkPacketBatchMessage, headers []externalV2BulkPacketMMsgHdr, read int) error {
	for index := 0; index < read; index++ {
		if int(headers[index].hdr.Flags)&unix.MSG_TRUNC != 0 {
			return errors.New("bulk packet receive batch contained a truncated datagram")
		}
		messages[index].N = int(headers[index].len)
		messages[index].NN = 0
		messages[index].Flags = int(headers[index].hdr.Flags)
		messages[index].Addr = nil
	}
	return nil
}

func (c *externalV2BulkPacketLinuxBatchConn) Stats() externalV2BulkPacketBatchStats {
	return c.stats.snapshot()
}

func (c *externalV2BulkPacketLinuxBatchConn) writeGSO(messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.sendScratch == nil {
		c.sendScratch = newExternalV2BulkPacketLinuxSendScratch()
	}
	headers, groupEnds, err := externalV2BulkPacketPrepareLinuxAddressedGSO(messages, externalV2BulkPacketLinuxGSOSegmentsPerMessage, c.sendScratch)
	if err != nil {
		return 0, err
	}
	preparedMessages := messages[:groupEnds[len(groupEnds)-1]]
	writtenGroups, sendErr := c.sendScratch.sendMMsg(c.rawConn, headers, c.sendMMsg, c.stats)
	written := externalV2BulkPacketLinuxGSOWritten(writtenGroups, groupEnds)
	c.stats.observeNativeAccepted(preparedMessages, written, writtenGroups, externalV2BulkPacketLinuxGSOSegmentsPerMessage)
	for index := range preparedMessages {
		runtime.KeepAlive(preparedMessages[index].Buffers[0])
	}
	runtime.KeepAlive(messages)
	runtime.KeepAlive(headers)
	runtime.KeepAlive(&c.sendScratch.iovecs)
	runtime.KeepAlive(&c.sendScratch.sockaddrs)
	runtime.KeepAlive(c.sendScratch.control)
	runtime.KeepAlive(c.sendScratch)
	externalV2BulkPacketResetLinuxConnectedSendScratch(c.sendScratch)
	for index := range written {
		messages[index].N = externalV2BulkPacketMessageLength(messages[index].Buffers)
	}
	return written, sendErr
}

func externalV2BulkPacketLinuxGSOWritten(writtenGroups int, groupEnds []int) int {
	if writtenGroups <= 0 || len(groupEnds) == 0 {
		return 0
	}
	return groupEnds[min(writtenGroups, len(groupEnds))-1]
}

func externalV2BulkPacketCanGSO(messages []externalV2BulkPacketBatchMessage) bool {
	if !externalV2BulkPacketGSOCountValid(len(messages)) {
		return false
	}
	segmentSize, destination, ok := externalV2BulkPacketGSOTemplate(messages[0])
	if !ok {
		return false
	}
	total, ok := externalV2BulkPacketGSOMessageTotal(messages, destination, segmentSize)
	if !ok {
		return false
	}
	return total <= externalV2BulkPacketMaxIPv4Payload
}

func externalV2BulkPacketGSOMessageTotal(messages []externalV2BulkPacketBatchMessage, destination string, segmentSize int) (int, bool) {
	total := 0
	shortSeen := false
	for index, message := range messages {
		length, ok := externalV2BulkPacketGSOMessageLength(message, destination, segmentSize)
		if !ok {
			return 0, false
		}
		if !externalV2BulkPacketGSOOrderValid(length, segmentSize, shortSeen, index == len(messages)-1) {
			return 0, false
		}
		shortSeen = length < segmentSize
		total += length
	}
	return total, true
}

func externalV2BulkPacketGSOCountValid(count int) bool {
	return count >= 2 && count <= externalV2BulkPacketMaxBatch
}

func externalV2BulkPacketGSOTemplate(message externalV2BulkPacketBatchMessage) (int, string, bool) {
	if len(message.Buffers) != 1 {
		return 0, "", false
	}
	if message.Addr == nil {
		return 0, "", false
	}
	segmentSize := len(message.Buffers[0])
	return segmentSize, message.Addr.String(), segmentSize > 0
}

func externalV2BulkPacketGSOMessageLength(message externalV2BulkPacketBatchMessage, destination string, segmentSize int) (int, bool) {
	if !externalV2BulkPacketGSOTargetMatches(message, destination) {
		return 0, false
	}
	length := len(message.Buffers[0])
	return length, length > 0 && length <= segmentSize
}

func externalV2BulkPacketGSOTargetMatches(message externalV2BulkPacketBatchMessage, destination string) bool {
	if len(message.Buffers) != 1 {
		return false
	}
	if len(message.OOB) != 0 {
		return false
	}
	if message.Addr == nil {
		return false
	}
	return message.Addr.String() == destination
}

func externalV2BulkPacketGSOOrderValid(length, segmentSize int, shortSeen, last bool) bool {
	if shortSeen {
		return false
	}
	if length < segmentSize {
		return last
	}
	return true
}

func externalV2BulkPacketLinuxGSOCapable(conn net.PacketConn) bool {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return false
	}
	capable := false
	if err := raw.Control(func(fd uintptr) {
		_, socketErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		capable = socketErr == nil
	}); err != nil {
		return false
	}
	return capable
}

func externalV2BulkPacketShouldDisableGSO(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EIO)
}

func externalV2BulkPacketSetGSOSize(control *[]byte, size uint16) {
	*control = (*control)[:0]
	if cap(*control) < unix.CmsgSpace(2) {
		return
	}
	*control = (*control)[:cap(*control)]
	header := (*unix.Cmsghdr)(unsafe.Pointer(&(*control)[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16((*control)[unix.SizeofCmsghdr:], size)
	*control = (*control)[:unix.CmsgSpace(2)]
}
