// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type xnetBatchReaderWriter interface {
	ReadBatch([]ipv6.Message, int) (int, error)
	WriteBatch([]ipv6.Message, int) (int, error)
}

type linuxBatcher struct {
	conn *net.UDPConn
	xpc  xnetBatchReaderWriter
	caps TransportCaps
	pool sync.Pool
}

func newPlatformBatcher(conn net.PacketConn, requested string) packetBatcher {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil
	}
	addr, _ := udpConn.LocalAddr().(*net.UDPAddr)
	var xpc xnetBatchReaderWriter
	if addr != nil && addr.IP != nil && addr.IP.To4() == nil {
		xpc = ipv6.NewPacketConn(udpConn)
	} else {
		xpc = ipv4.NewPacketConn(udpConn)
	}

	b := &linuxBatcher{
		conn: udpConn,
		xpc:  xpc,
		caps: tuneSocketCaps(udpConn, TransportCaps{
			Kind:          probeTransportBatched,
			RequestedKind: requested,
			BatchSize:     probeIdealBatchSize,
		}),
		pool: sync.Pool{
			New: func() any {
				msgs := make([]ipv6.Message, probeIdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make([][]byte, 1)
				}
				return &msgs
			},
		},
	}
	b.caps.TXOffload = hasSocketOption(udpConn, unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	b.caps.RXQOverflow = enableRXQOverflow(udpConn)
	return b
}

func (b *linuxBatcher) Capabilities() TransportCaps { return b.caps }
func (b *linuxBatcher) MaxBatch() int               { return probeIdealBatchSize }

func (b *linuxBatcher) WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil || b.xpc == nil {
		return 0, errors.New("nil packet conn")
	}
	deadline, err := batchWriteDeadline(ctx)
	if err != nil {
		return 0, err
	}
	if err := b.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer b.conn.SetWriteDeadline(time.Time{})

	msgs := b.getMessages()
	defer b.putMessages(msgs)

	sent := 0
	for sent < len(packets) {
		chunk := len(packets) - sent
		if chunk > len(*msgs) {
			chunk = len(*msgs)
		}
		for i := 0; i < chunk; i++ {
			(*msgs)[i].Buffers[0] = packets[sent+i]
			(*msgs)[i].Addr = peer
			(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
			(*msgs)[i].N = 0
			(*msgs)[i].NN = 0
			(*msgs)[i].Flags = 0
		}

		n, err := b.xpc.WriteBatch((*msgs)[:chunk], 0)
		sent += n
		if err != nil {
			return sent, err
		}
		if n == 0 {
			return sent, errors.New("write batch made no progress")
		}
	}
	return sent, nil
}

func (b *linuxBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil || b.xpc == nil {
		return 0, errors.New("nil packet conn")
	}
	deadline, err := batchReadDeadline(ctx, timeout)
	if err != nil {
		return 0, err
	}
	if err := b.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	defer b.conn.SetReadDeadline(time.Time{})

	msgs := b.getMessages()
	defer b.putMessages(msgs)

	limit := len(bufs)
	if limit > len(*msgs) {
		limit = len(*msgs)
	}
	for i := 0; i < limit; i++ {
		(*msgs)[i].Buffers[0] = bufs[i].Bytes
		(*msgs)[i].Addr = nil
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i].N = 0
		(*msgs)[i].NN = 0
		(*msgs)[i].Flags = 0
	}

	n, err := b.xpc.ReadBatch((*msgs)[:limit], 0)
	if err != nil {
		return 0, err
	}
	for i := 0; i < n; i++ {
		bufs[i].N = (*msgs)[i].N
		bufs[i].Addr = cloneAddr((*msgs)[i].Addr)
	}
	for i := n; i < len(bufs); i++ {
		bufs[i].N = 0
		bufs[i].Addr = nil
	}
	return n, nil
}

func (b *linuxBatcher) getMessages() *[]ipv6.Message {
	return b.pool.Get().(*[]ipv6.Message)
}

func (b *linuxBatcher) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers[:1], OOB: (*msgs)[i].OOB[:0]}
	}
	b.pool.Put(msgs)
}

func platformSetSocketBuffers(conn net.PacketConn, caps *TransportCaps, size int) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok || udpConn == nil {
		return
	}
	rawConn, err := udpConn.SyscallConn()
	if err == nil {
		_ = rawConn.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, size)
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, size)
		})
	}
	type readBufferSetter interface {
		SetReadBuffer(int) error
	}
	type writeBufferSetter interface {
		SetWriteBuffer(int) error
	}
	if setter, ok := conn.(readBufferSetter); ok {
		_ = setter.SetReadBuffer(size)
	}
	if setter, ok := conn.(writeBufferSetter); ok {
		_ = setter.SetWriteBuffer(size)
	}
	_ = caps
}

func platformSetSocketPacing(conn net.PacketConn, bytesPerSecond uint64) bool {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok || udpConn == nil || bytesPerSecond == 0 {
		return false
	}
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return false
	}
	enabled := false
	_ = rawConn.Control(func(fd uintptr) {
		enabled = unix.SetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_MAX_PACING_RATE, bytesPerSecond) == nil
	})
	return enabled
}

func platformConnectUDP(conn *net.UDPConn, peer *net.UDPAddr) error {
	if conn == nil || peer == nil {
		return errors.New("nil udp conn or peer")
	}
	sa, err := udpSockaddr(conn.LocalAddr(), peer)
	if err != nil {
		return err
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var connectErr error
	if err := rawConn.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), sa)
	}); err != nil {
		return err
	}
	return connectErr
}

func udpSockaddr(local net.Addr, peer *net.UDPAddr) (unix.Sockaddr, error) {
	ap := peer.AddrPort()
	if !ap.IsValid() {
		return nil, errors.New("invalid udp peer")
	}
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		if localUDPAddrIs6(local) {
			v4 := addr.As4()
			var v6 [16]byte
			v6[10] = 0xff
			v6[11] = 0xff
			copy(v6[12:], v4[:])
			return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: v6}, nil
		}
		v4 := addr.As4()
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: v4}, nil
	}
	if addr.Is6() {
		v6 := addr.As16()
		return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: v6, ZoneId: zoneID(addr)}, nil
	}
	return nil, errors.New("unsupported udp peer address")
}

func localUDPAddrIs6(addr net.Addr) bool {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return false
	}
	ap := udpAddr.AddrPort()
	return ap.IsValid() && ap.Addr().Is6()
}

func zoneID(addr netip.Addr) uint32 {
	zone := addr.Zone()
	if zone == "" {
		return 0
	}
	if id, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(id)
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		return uint32(iface.Index)
	}
	return 0
}

func enableRXQOverflow(conn *net.UDPConn) bool {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	enabled := false
	_ = rawConn.Control(func(fd uintptr) {
		enabled = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1) == nil
	})
	return enabled
}

func hasSocketOption(conn *net.UDPConn, level, opt int) bool {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = rawConn.Control(func(fd uintptr) {
		_, err := syscall.GetsockoptInt(int(fd), level, opt)
		ok = err == nil
	})
	return ok
}
