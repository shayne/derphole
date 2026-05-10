// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package traversal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

const stunReadInterval = 100 * time.Millisecond

type STUNPacket struct {
	Payload []byte
	Addr    netip.AddrPort
}

func GatherCandidates(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, mapped func() (netip.AddrPort, bool)) ([]string, error) {
	return gatherCandidatesWithReceiver(ctx, conn, dm, mapped, func(readCtx context.Context, recv func([]byte, netip.AddrPort)) {
		if conn == nil {
			<-readCtx.Done()
			return
		}
		receiveSTUNPackets(readCtx, conn, recv)
	})
}

func GatherCandidatesFromSTUNPackets(
	ctx context.Context,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	mapped func() (netip.AddrPort, bool),
	packets <-chan STUNPacket,
) ([]string, error) {
	return gatherCandidatesWithReceiver(ctx, conn, dm, mapped, func(readCtx context.Context, recv func([]byte, netip.AddrPort)) {
		receiveSTUNPacketsFromChan(readCtx, packets, recv)
	})
}

func gatherCandidatesWithReceiver(
	ctx context.Context,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	mapped func() (netip.AddrPort, bool),
	receive func(context.Context, func([]byte, netip.AddrPort)),
) ([]string, error) {
	client := &netcheck.Client{
		Logf:   logger.Discard,
		NetMon: netmon.NewStatic(),
		SendPacket: func(pkt []byte, dst netip.AddrPort) (int, error) {
			if conn == nil {
				return 0, errors.New("nil packet conn")
			}
			return conn.WriteTo(pkt, net.UDPAddrFromAddrPort(dst))
		},
	}

	readCtx, cancelRead := context.WithCancel(ctx)
	var readWG sync.WaitGroup
	if receive != nil {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			receive(readCtx, client.ReceiveSTUNPacket)
		}()
	}
	defer func() {
		cancelRead()
		readWG.Wait()
	}()

	report, err := client.GetReport(ctx, dm, nil)
	if err != nil {
		return nil, err
	}

	v4, v6 := report.GetGlobalAddrs()
	return gatherCandidates(v4, v6, mapped), nil
}

func receiveSTUNPacketsFromChan(ctx context.Context, packets <-chan STUNPacket, recv func([]byte, netip.AddrPort)) {
	if packets == nil {
		<-ctx.Done()
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if len(packet.Payload) == 0 || !packet.Addr.IsValid() {
				continue
			}
			recv(append([]byte(nil), packet.Payload...), packet.Addr)
		}
	}
}

func gatherCandidates(v4, v6 []netip.AddrPort, mapped func() (netip.AddrPort, bool)) []string {
	candidates := make([]string, 0, len(v4)+len(v6)+1)
	for _, addr := range v4 {
		candidates = append(candidates, addr.String())
	}
	for _, addr := range v6 {
		candidates = append(candidates, addr.String())
	}

	if mapped == nil {
		return candidates
	}

	mappedAddr, ok := mapped()
	return appendMappedCandidate(candidates, mappedAddr, ok)
}

func receiveSTUNPackets(ctx context.Context, conn net.PacketConn, recv func([]byte, netip.AddrPort)) {
	buf := make([]byte, 64<<10)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(stunReadInterval)); err != nil {
			return
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			continue
		}
		if !stun.Is(buf[:n]) {
			continue
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		addrPort, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			continue
		}
		recv(append([]byte(nil), buf[:n]...), netip.AddrPortFrom(addrPort.Unmap(), uint16(udpAddr.Port)))
	}
}

func appendMappedCandidate(candidates []string, mapped netip.AddrPort, ok bool) []string {
	if !ok || !mapped.IsValid() {
		return candidates
	}

	mappedStr := mapped.String()
	for _, candidate := range candidates {
		if candidate == mappedStr {
			return candidates
		}
	}

	return append(candidates, mappedStr)
}
