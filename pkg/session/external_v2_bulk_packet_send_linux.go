// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type externalV2BulkPacketLinuxSendScratch struct {
	headers       [externalV2BulkPacketMaxBatch]externalV2BulkPacketMMsgHdr
	iovecs        [externalV2BulkPacketMaxBatch]unix.Iovec
	groupEnds     [externalV2BulkPacketMaxBatch]int
	sockaddrs     [externalV2BulkPacketMaxBatch]unix.RawSockaddrInet6
	control       []byte
	activeHeaders int
	activeIovecs  int
	activeAddrs   int
	nativeSend    externalV2BulkPacketLinuxNativeSend
}

type externalV2BulkPacketLinuxSendSyscall func(uintptr, []externalV2BulkPacketMMsgHdr) (int, syscall.Errno)

type externalV2BulkPacketLinuxNativeSend struct {
	headers    []externalV2BulkPacketMMsgHdr
	send       externalV2BulkPacketLinuxSendSyscall
	stats      *externalV2BulkPacketAtomicBatchStats
	written    int
	syscallErr error
	callback   func(uintptr) bool
}

func newExternalV2BulkPacketLinuxSendScratch() *externalV2BulkPacketLinuxSendScratch {
	scratch := &externalV2BulkPacketLinuxSendScratch{
		control: make([]byte, 0, externalV2BulkPacketMaxBatch*unix.CmsgSpace(2)),
	}
	scratch.nativeSend.callback = scratch.nativeSend.write
	return scratch
}

func externalV2BulkPacketPrepareLinuxConnectedSend(
	messages []externalV2BulkPacketBatchMessage,
	scratch *externalV2BulkPacketLinuxSendScratch,
) ([]externalV2BulkPacketMMsgHdr, error) {
	if scratch == nil {
		return nil, errors.New("bulk packet connected send has no scratch")
	}
	externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 {
			externalV2BulkPacketSetLinuxSendScratchActive(scratch, index, index, 0)
			externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
			return nil, errors.New("bulk packet connected send requires one non-empty buffer")
		}
		if len(messages[index].OOB) != 0 {
			externalV2BulkPacketSetLinuxSendScratchActive(scratch, index, index, 0)
			externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
			return nil, errors.New("bulk packet connected send does not accept control data")
		}
		buffer := messages[index].Buffers[0]
		scratch.iovecs[index] = unix.Iovec{Base: &buffer[0]}
		scratch.iovecs[index].SetLen(len(buffer))
		scratch.headers[index] = externalV2BulkPacketMMsgHdr{hdr: unix.Msghdr{
			Iov:    &scratch.iovecs[index],
			Iovlen: 1,
		}}
		scratch.groupEnds[index] = index + 1
	}
	externalV2BulkPacketSetLinuxSendScratchActive(scratch, len(messages), len(messages), 0)
	return scratch.headers[:len(messages)], nil
}

func externalV2BulkPacketPrepareLinuxAddressedSend(
	messages []externalV2BulkPacketBatchMessage,
	scratch *externalV2BulkPacketLinuxSendScratch,
) ([]externalV2BulkPacketMMsgHdr, error) {
	if scratch == nil {
		return nil, errors.New("bulk packet addressed send has no scratch")
	}
	externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 {
			externalV2BulkPacketSetLinuxSendScratchActive(scratch, index, index, index)
			externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
			return nil, errors.New("bulk packet addressed send requires one non-empty buffer")
		}
		if len(messages[index].OOB) != 0 {
			externalV2BulkPacketSetLinuxSendScratchActive(scratch, index, index, index)
			externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
			return nil, errors.New("bulk packet addressed send does not accept control data")
		}
		name, nameLen, err := externalV2BulkPacketLinuxRawSockaddr(&scratch.sockaddrs[index], messages[index].Addr)
		if err != nil {
			externalV2BulkPacketSetLinuxSendScratchActive(scratch, index, index, index+1)
			externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
			return nil, err
		}
		buffer := messages[index].Buffers[0]
		scratch.iovecs[index] = unix.Iovec{Base: &buffer[0]}
		scratch.iovecs[index].SetLen(len(buffer))
		scratch.headers[index] = externalV2BulkPacketMMsgHdr{hdr: unix.Msghdr{
			Name: name, Namelen: nameLen, Iov: &scratch.iovecs[index], Iovlen: 1,
		}}
		scratch.groupEnds[index] = index + 1
	}
	externalV2BulkPacketSetLinuxSendScratchActive(scratch, len(messages), len(messages), len(messages))
	return scratch.headers[:len(messages)], nil
}

func externalV2BulkPacketPrepareLinuxConnectedGSO(
	messages []externalV2BulkPacketBatchMessage,
	segments int,
	scratch *externalV2BulkPacketLinuxSendScratch,
) ([]externalV2BulkPacketMMsgHdr, []int, error) {
	if scratch == nil {
		return nil, nil, errors.New("bulk packet connected GSO send has no scratch")
	}
	externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
	if !externalV2BulkPacketConnectedGSOSegmentsAllowed(segments) {
		return nil, nil, fmt.Errorf("invalid bulk packet connected GSO segment count %d", segments)
	}
	if segments == 1 {
		headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, scratch)
		return headers, scratch.groupEnds[:len(headers)], err
	}
	messages = externalV2BulkPacketLimitLinuxGSOMessages(messages)
	if len(messages) == 0 {
		return nil, nil, errors.New("bulk packet connected GSO send has no messages")
	}
	segmentSize, _, err := externalV2BulkPacketValidateLinuxGSOMessages(messages, "connected")
	if err != nil {
		return nil, nil, err
	}
	if err := externalV2BulkPacketValidateLinuxGSOGroups(messages, segments, "connected"); err != nil {
		return nil, nil, err
	}
	externalV2BulkPacketPopulateLinuxGSOIovecs(messages, scratch)
	controlStorage := externalV2BulkPacketLinuxGSOControlStorage(scratch)
	groupCount := externalV2BulkPacketBuildLinuxConnectedGSOHeaders(messages, segments, segmentSize, scratch, controlStorage)
	externalV2BulkPacketSetLinuxSendScratchActive(scratch, groupCount, len(messages), 0)
	return scratch.headers[:groupCount], scratch.groupEnds[:groupCount], nil
}

func externalV2BulkPacketPrepareLinuxAddressedGSO(
	messages []externalV2BulkPacketBatchMessage,
	segments int,
	scratch *externalV2BulkPacketLinuxSendScratch,
) ([]externalV2BulkPacketMMsgHdr, []int, error) {
	if scratch == nil {
		return nil, nil, errors.New("bulk packet addressed GSO send has no scratch")
	}
	externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
	if !externalV2BulkPacketAddressedGSOSegmentsAllowed(segments) {
		return nil, nil, fmt.Errorf("invalid bulk packet addressed GSO segment count %d", segments)
	}
	messages = externalV2BulkPacketLimitLinuxGSOMessages(messages)
	if len(messages) == 0 {
		return nil, nil, errors.New("bulk packet addressed GSO send has no messages")
	}
	segmentSize, invalidIndex, err := externalV2BulkPacketValidateLinuxGSOMessages(messages, "addressed")
	if err != nil {
		return externalV2BulkPacketFailLinuxAddressedGSO(scratch, 0, invalidIndex, 0, err)
	}
	if err := externalV2BulkPacketValidateLinuxGSOGroups(messages, segments, "addressed"); err != nil {
		return externalV2BulkPacketFailLinuxAddressedGSO(scratch, 0, 0, 0, err)
	}
	externalV2BulkPacketPopulateLinuxGSOIovecs(messages, scratch)
	controlStorage := externalV2BulkPacketLinuxGSOControlStorage(scratch)
	groupCount := 0
	for start := 0; start < len(messages); start += segments {
		end := min(start+segments, len(messages))
		externalV2BulkPacketSetLinuxSendScratchActive(scratch, groupCount, len(messages), groupCount+1)
		name, nameLen, err := externalV2BulkPacketLinuxRawSockaddr(&scratch.sockaddrs[groupCount], messages[start].Addr)
		if err != nil {
			return externalV2BulkPacketFailLinuxAddressedGSO(scratch, groupCount, len(messages), groupCount+1, err)
		}
		controlStart := groupCount * unix.CmsgSpace(2)
		controlEnd := controlStart + unix.CmsgSpace(2)
		control := controlStorage[controlStart:controlStart:controlEnd]
		externalV2BulkPacketSetGSOSize(&control, uint16(segmentSize))
		scratch.headers[groupCount] = externalV2BulkPacketMMsgHdr{hdr: unix.Msghdr{
			Name:       name,
			Namelen:    nameLen,
			Iov:        &scratch.iovecs[start],
			Iovlen:     uint64(end - start),
			Control:    &control[0],
			Controllen: uint64(len(control)),
		}}
		scratch.groupEnds[groupCount] = end
		groupCount++
		externalV2BulkPacketSetLinuxSendScratchActive(scratch, groupCount, len(messages), groupCount)
	}
	externalV2BulkPacketSetLinuxSendScratchActive(scratch, groupCount, len(messages), groupCount)
	return scratch.headers[:groupCount], scratch.groupEnds[:groupCount], nil
}

func externalV2BulkPacketLimitLinuxGSOMessages(messages []externalV2BulkPacketBatchMessage) []externalV2BulkPacketBatchMessage {
	if len(messages) > externalV2BulkPacketMaxBatch {
		return messages[:externalV2BulkPacketMaxBatch]
	}
	return messages
}

func externalV2BulkPacketValidateLinuxGSOMessages(messages []externalV2BulkPacketBatchMessage, mode string) (int, int, error) {
	segmentSize := 0
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 {
			return 0, index, fmt.Errorf("bulk packet %s GSO send requires one non-empty buffer", mode)
		}
		if len(messages[index].OOB) != 0 {
			return 0, index, fmt.Errorf("bulk packet %s GSO send does not accept control data", mode)
		}
		length := len(messages[index].Buffers[0])
		if index == 0 {
			segmentSize = length
		}
		if length > segmentSize || index != len(messages)-1 && length != segmentSize {
			return 0, index, fmt.Errorf("bulk packet %s GSO send requires equal segments with only a short final segment", mode)
		}
	}
	return segmentSize, len(messages), nil
}

func externalV2BulkPacketValidateLinuxGSOGroups(messages []externalV2BulkPacketBatchMessage, segments int, mode string) error {
	for start := 0; start < len(messages); start += segments {
		end := min(start+segments, len(messages))
		groupBytes := 0
		for index := start; index < end; index++ {
			groupBytes += len(messages[index].Buffers[0])
		}
		if groupBytes > externalV2BulkPacketMaxIPv4Payload {
			return fmt.Errorf("bulk packet %s GSO message exceeds maximum IPv4 payload", mode)
		}
	}
	return nil
}

func externalV2BulkPacketPopulateLinuxGSOIovecs(messages []externalV2BulkPacketBatchMessage, scratch *externalV2BulkPacketLinuxSendScratch) {
	for index := range messages {
		buffer := messages[index].Buffers[0]
		scratch.iovecs[index] = unix.Iovec{Base: &buffer[0]}
		scratch.iovecs[index].SetLen(len(buffer))
	}
}

func externalV2BulkPacketLinuxGSOControlStorage(scratch *externalV2BulkPacketLinuxSendScratch) []byte {
	controlBytes := externalV2BulkPacketMaxBatch * unix.CmsgSpace(2)
	if cap(scratch.control) < controlBytes {
		scratch.control = make([]byte, 0, controlBytes)
	}
	return scratch.control[:cap(scratch.control)]
}

func externalV2BulkPacketBuildLinuxConnectedGSOHeaders(
	messages []externalV2BulkPacketBatchMessage,
	segments int,
	segmentSize int,
	scratch *externalV2BulkPacketLinuxSendScratch,
	controlStorage []byte,
) int {
	groupCount := 0
	for start := 0; start < len(messages); start += segments {
		end := min(start+segments, len(messages))
		controlStart := groupCount * unix.CmsgSpace(2)
		controlEnd := controlStart + unix.CmsgSpace(2)
		control := controlStorage[controlStart:controlStart:controlEnd]
		externalV2BulkPacketSetGSOSize(&control, uint16(segmentSize))
		scratch.headers[groupCount] = externalV2BulkPacketMMsgHdr{hdr: unix.Msghdr{
			Iov:        &scratch.iovecs[start],
			Iovlen:     uint64(end - start),
			Control:    &control[0],
			Controllen: uint64(len(control)),
		}}
		scratch.groupEnds[groupCount] = end
		groupCount++
	}
	return groupCount
}

func externalV2BulkPacketAddressedGSOSegmentsAllowed(segments int) bool {
	return segments != 1 && externalV2BulkPacketConnectedGSOSegmentsAllowed(segments)
}

func externalV2BulkPacketFailLinuxAddressedGSO(
	scratch *externalV2BulkPacketLinuxSendScratch,
	headers int,
	iovecs int,
	addrs int,
	err error,
) ([]externalV2BulkPacketMMsgHdr, []int, error) {
	externalV2BulkPacketSetLinuxSendScratchActive(scratch, headers, iovecs, addrs)
	externalV2BulkPacketResetLinuxConnectedSendScratch(scratch)
	return nil, nil, err
}

func externalV2BulkPacketLinuxRawSockaddr(storage *unix.RawSockaddrInet6, addr net.Addr) (*byte, uint32, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port < 0 || udpAddr.Port > 1<<16-1 {
		return nil, 0, fmt.Errorf("invalid bulk packet destination %v", addr)
	}
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		raw := (*unix.RawSockaddrInet4)(unsafe.Pointer(storage))
		*raw = unix.RawSockaddrInet4{Family: unix.AF_INET}
		externalV2BulkPacketLinuxSetPort(&raw.Port, udpAddr.Port)
		copy(raw.Addr[:], ip4)
		return (*byte)(unsafe.Pointer(raw)), unix.SizeofSockaddrInet4, nil
	}
	ip6 := udpAddr.IP.To16()
	if ip6 == nil {
		return nil, 0, fmt.Errorf("invalid bulk packet destination %v", addr)
	}
	*storage = unix.RawSockaddrInet6{Family: unix.AF_INET6}
	externalV2BulkPacketLinuxSetPort(&storage.Port, udpAddr.Port)
	copy(storage.Addr[:], ip6)
	if udpAddr.Zone != "" {
		iface, err := net.InterfaceByName(udpAddr.Zone)
		if err != nil {
			return nil, 0, fmt.Errorf("resolve bulk packet destination zone %q: %w", udpAddr.Zone, err)
		}
		storage.Scope_id = uint32(iface.Index)
	}
	return (*byte)(unsafe.Pointer(storage)), unix.SizeofSockaddrInet6, nil
}

func externalV2BulkPacketLinuxSetPort(port *uint16, value int) {
	bytes := (*[2]byte)(unsafe.Pointer(port))
	bytes[0] = byte(value >> 8)
	bytes[1] = byte(value)
}

func externalV2BulkPacketConnectedGSOSegmentsAllowed(segments int) bool {
	switch segments {
	case 1, 2, 3, 4, 6, 8, 12:
		return true
	default:
		return false
	}
}

func externalV2BulkPacketSetLinuxSendScratchActive(scratch *externalV2BulkPacketLinuxSendScratch, headers, iovecs, addrs int) {
	scratch.activeHeaders = min(headers, externalV2BulkPacketMaxBatch)
	scratch.activeIovecs = min(iovecs, externalV2BulkPacketMaxBatch)
	scratch.activeAddrs = min(addrs, externalV2BulkPacketMaxBatch)
}

func externalV2BulkPacketResetLinuxConnectedSendScratch(scratch *externalV2BulkPacketLinuxSendScratch) {
	if scratch == nil {
		return
	}
	for index := range scratch.activeHeaders {
		scratch.headers[index] = externalV2BulkPacketMMsgHdr{}
		scratch.groupEnds[index] = 0
	}
	for index := range scratch.activeIovecs {
		scratch.iovecs[index] = unix.Iovec{}
	}
	for index := range scratch.activeAddrs {
		scratch.sockaddrs[index] = unix.RawSockaddrInet6{}
	}
	scratch.activeHeaders = 0
	scratch.activeIovecs = 0
	scratch.activeAddrs = 0
}

func externalV2BulkPacketSendMMsg(
	raw syscall.RawConn,
	headers []externalV2BulkPacketMMsgHdr,
	send externalV2BulkPacketLinuxSendSyscall,
	stats *externalV2BulkPacketAtomicBatchStats,
) (int, error) {
	state := &externalV2BulkPacketLinuxNativeSend{}
	state.callback = state.write
	return state.sendMMsg(raw, headers, send, stats)
}

func (s *externalV2BulkPacketLinuxSendScratch) sendMMsg(
	raw syscall.RawConn,
	headers []externalV2BulkPacketMMsgHdr,
	send externalV2BulkPacketLinuxSendSyscall,
	stats *externalV2BulkPacketAtomicBatchStats,
) (int, error) {
	if s == nil {
		return 0, errors.New("bulk packet sendmmsg has no scratch")
	}
	if s.nativeSend.callback == nil {
		s.nativeSend.callback = s.nativeSend.write
	}
	return s.nativeSend.sendMMsg(raw, headers, send, stats)
}

func (s *externalV2BulkPacketLinuxNativeSend) sendMMsg(
	raw syscall.RawConn,
	headers []externalV2BulkPacketMMsgHdr,
	send externalV2BulkPacketLinuxSendSyscall,
	stats *externalV2BulkPacketAtomicBatchStats,
) (int, error) {
	if raw == nil || send == nil || len(headers) == 0 {
		return 0, errors.New("bulk packet sendmmsg has no socket, syscall, or messages")
	}
	s.headers = headers
	s.send = send
	s.stats = stats
	s.written = 0
	s.syscallErr = nil
	err := raw.Write(s.callback)
	runtime.KeepAlive(headers)
	written := s.written
	syscallErr := s.syscallErr
	s.headers = nil
	s.send = nil
	s.stats = nil
	s.written = 0
	s.syscallErr = nil
	if err != nil || syscallErr != nil {
		return written, errors.Join(syscallErr, err)
	}
	if written == 0 {
		return 0, errExternalV2BulkPacketBatchNoProgress
	}
	return written, nil
}

func (s *externalV2BulkPacketLinuxNativeSend) write(fd uintptr) bool {
	if s.stats != nil {
		s.stats.observeNativeAttempt()
	}
	candidate, errno := s.send(fd, s.headers)
	if s.stats != nil {
		s.stats.observeNativeSyscall()
	}
	if candidate < 0 || candidate > len(s.headers) {
		s.syscallErr = fmt.Errorf("bulk packet sendmmsg wrote %d of %d messages", candidate, len(s.headers))
		return true
	}
	s.written = candidate
	if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
		if s.written != 0 {
			s.syscallErr = fmt.Errorf("bulk packet sendmmsg returned EAGAIN after writing %d messages", s.written)
			return true
		}
		return false
	}
	if errno != 0 {
		s.syscallErr = errno
	}
	return true
}

func externalV2BulkPacketLinuxSendMMsgSyscall(fd uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
	count, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		fd,
		uintptr(unsafe.Pointer(&headers[0])),
		uintptr(len(headers)),
		uintptr(unix.MSG_DONTWAIT),
		0,
		0,
	)
	runtime.KeepAlive(headers)
	if errno != 0 {
		return 0, errno
	}
	return int(count), 0
}
