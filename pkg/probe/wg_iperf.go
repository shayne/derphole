// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"net"
	"time"
)

type WireGuardOSIperfServer struct {
	node        *wireGuardOSNode
	punchCancel context.CancelFunc
	wait        func() (TransferStats, error)
}

func StartWireGuardOSIperfServer(ctx context.Context, conn net.PacketConn, cfg WireGuardConfig) (*WireGuardOSIperfServer, error) {
	node, resolved, err := newWireGuardOSNode(conn, cfg)
	if err != nil {
		return nil, err
	}
	punchCtx, punchCancel := context.WithCancel(ctx)
	if len(cfg.PeerCandidates) > 0 {
		go PunchAddrs(punchCtx, conn, cfg.PeerCandidates, nil, defaultPunchInterval)
	}
	handle, err := startIperf3Server(ctx, resolved.localAddr.String(), int(resolved.port))
	if err != nil {
		punchCancel()
		_ = node.Close()
		return nil, err
	}
	startedAt := time.Now()
	return &WireGuardOSIperfServer{
		node:        node,
		punchCancel: punchCancel,
		wait: func() (TransferStats, error) {
			result, err := handle.Wait()
			if err != nil {
				return TransferStats{}, err
			}
			return TransferStats{
				StartedAt:     startedAt,
				CompletedAt:   startedAt.Add(time.Duration(result.DurationMS) * time.Millisecond),
				BytesReceived: result.Bytes,
				Transport:     PreviewTransportCaps(conn, cfg.Transport),
			}, nil
		},
	}, nil
}

func (s *WireGuardOSIperfServer) Wait() (TransferStats, error) {
	if s == nil || s.wait == nil {
		return TransferStats{}, context.Canceled
	}
	return s.wait()
}

func (s *WireGuardOSIperfServer) Close() error {
	if s == nil {
		return nil
	}
	if s.punchCancel != nil {
		s.punchCancel()
	}
	if s.node != nil {
		return s.node.Close()
	}
	return nil
}

func SendWireGuardOSIperf(ctx context.Context, conn net.PacketConn, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardOSNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer node.Close()

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	if len(cfg.PeerCandidates) > 0 {
		go PunchAddrs(punchCtx, conn, cfg.PeerCandidates, nil, defaultPunchInterval)
	}

	stats := TransferStats{
		StartedAt: time.Now(),
		Transport: PreviewTransportCaps(conn, cfg.Transport),
	}
	result, err := runIperf3Client(ctx, iperf3ClientConfig{
		BindAddr:  resolved.localAddr.String(),
		Target:    resolved.peerAddr.String(),
		Port:      int(resolved.port),
		SizeBytes: cfg.SizeBytes,
		Parallel:  wireGuardStreamCount(cfg),
		Reverse:   cfg.Reverse,
	})
	if err != nil {
		return TransferStats{}, err
	}
	stats.CompletedAt = stats.StartedAt.Add(time.Duration(result.DurationMS) * time.Millisecond)
	stats.BytesSent = result.Bytes
	stats.BytesReceived = result.Bytes
	return stats, nil
}
