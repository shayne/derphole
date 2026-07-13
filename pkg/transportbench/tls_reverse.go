// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// TLSSendListenConfig describes the test-only topology where the file sender
// owns the reachable TLS listener and the receiver initiates each connection.
type TLSSendListenConfig struct {
	ListenAddr string
	InputPath  string
	ReadyFile  string
	TracePath  string
	Timeout    time.Duration
}

// TLSReceiveConnectConfig describes the test-only topology where the file
// receiver dials a pinned TLS listener and requests the eight payload lanes.
type TLSReceiveConnectConfig struct {
	PeerAddr          string
	FingerprintSHA256 string
	TransferID        [16]byte
	OutputPath        string
	TracePath         string
	Timeout           time.Duration
}

func SendTLSListening(parent context.Context, cfg TLSSendListenConfig) (summary TransferSummary, retErr error) {
	commandStarted := time.Now()
	if err := validateTLSSendListenConfig(cfg); err != nil {
		return TransferSummary{}, err
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	counters := &tlsTransferCounters{}
	trace, err := startTLSTrace(cfg.TracePath, "sender", commandStarted, counters)
	if err != nil {
		return TransferSummary{}, err
	}
	defer func() {
		retErr = errors.Join(retErr, trace.stop(retErr))
	}()

	input, expectedHash, size, ranges, err := prepareTLSSendListenInput(cfg.InputPath)
	if err != nil {
		return TransferSummary{}, err
	}
	defer func() { _ = input.Close() }()

	setup, err := prepareTLSReceiver(TLSReceiveConfig{ListenAddr: cfg.ListenAddr, ReadyFile: cfg.ReadyFile}, commandStarted)
	if err != nil {
		return TransferSummary{}, err
	}
	defer func() { _ = setup.listener.Close() }()
	listenerDone := closeListenerOnContext(ctx, setup.listener)
	defer func() {
		cancel()
		<-listenerDone
	}()

	lanes, err := acceptTLSLaneRequests(ctx, setup)
	if err != nil {
		return TransferSummary{}, err
	}
	connections := laneConnections(lanes)
	defer closeConnections(connections)
	if err := sendAcceptedTLSLanes(ctx, cancel, lanes, input, setup.transferID, expectedHash, size, ranges, counters); err != nil {
		return TransferSummary{}, err
	}
	summary = buildTransferSummary("sender", size, expectedHash, commandStarted, lanes[0].state, counters, connections)
	return summary, nil
}

func ReceiveTLSConnecting(parent context.Context, cfg TLSReceiveConnectConfig) (summary TransferSummary, retErr error) {
	commandStarted := time.Now()
	if err := validateTLSReceiveConnectConfig(cfg); err != nil {
		return TransferSummary{}, err
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	counters := &tlsTransferCounters{}
	trace, err := startTLSTrace(cfg.TracePath, "receiver", commandStarted, counters)
	if err != nil {
		return TransferSummary{}, err
	}
	defer func() {
		retErr = errors.Join(retErr, trace.stop(retErr))
	}()

	clientConfig, err := newPinnedTLSClientConfig(cfg.FingerprintSHA256)
	if err != nil {
		return TransferSummary{}, err
	}
	connections := newTLSConnectionSet()
	defer connections.closeAll()
	interruptDone := connections.interruptOnContext(ctx)
	defer func() {
		cancel()
		<-interruptDone
	}()

	lanes, headers, err := connectAndRequestTLSLanes(ctx, cancel, cfg, clientConfig, connections)
	if err != nil {
		return TransferSummary{}, err
	}
	actualHash, size, err := receiveAndVerifyTLSFile(ctx, cfg.OutputPath, lanes, headers[0], counters)
	if err != nil {
		return TransferSummary{}, err
	}
	summary = buildTransferSummary("receiver", size, actualHash, commandStarted, lanes[0].state, counters, connections.snapshot())
	return summary, nil
}

func prepareTLSSendListenInput(path string) (*os.File, [sha256.Size]byte, int64, []ByteRange, error) {
	input, err := os.Open(path)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, fmt.Errorf("open input: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = input.Close()
		}
	}()
	info, err := input.Stat()
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, [sha256.Size]byte{}, 0, nil, errors.New("input must be a regular file")
	}
	expectedHash, size, err := hashOpenFile(input)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, err
	}
	ranges, err := SplitRanges(size, TLSLaneCount)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, err
	}
	success = true
	return input, expectedHash, size, ranges, nil
}

func acceptTLSLaneRequests(ctx context.Context, setup tlsReceiverSetup) ([]tlsAcceptedLane, error) {
	lanes := make([]tlsAcceptedLane, TLSLaneCount)
	seen := make([]bool, TLSLaneCount)
	for accepted := 0; accepted < TLSLaneCount; accepted++ {
		rawConn, err := setup.listener.Accept()
		if err != nil {
			closeAcceptedLanes(lanes)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("accept lane request: %w", err)
		}
		conn := tls.Server(rawConn, setup.serverConfig)
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, fmt.Errorf("handshake requested lane %d: %w", accepted, err)
		}
		var rawRequest [TLSLaneRequestSize]byte
		if _, err := io.ReadFull(conn, rawRequest[:]); err != nil {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, fmt.Errorf("read lane request %d: %w", accepted, err)
		}
		request, err := DecodeLaneRequest(rawRequest[:])
		if err != nil {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, err
		}
		if request.TransferID != setup.transferID {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, errors.New("lane request transfer ID does not match ready descriptor")
		}
		if seen[request.Lane] {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, fmt.Errorf("duplicate lane request %d", request.Lane)
		}
		seen[request.Lane] = true
		lanes[request.Lane] = tlsAcceptedLane{conn: conn, state: conn.ConnectionState()}
	}
	return lanes, nil
}

func sendAcceptedTLSLanes(ctx context.Context, cancel context.CancelFunc, lanes []tlsAcceptedLane, input *os.File, transferID [16]byte, expectedHash [sha256.Size]byte, size int64, ranges []ByteRange, counters *tlsTransferCounters) error {
	schedule := newTLSChunkSchedule(size)
	errCh := make(chan error, TLSLaneCount)
	var workers sync.WaitGroup
	workers.Add(TLSLaneCount)
	for lane, byteRange := range ranges {
		go func() {
			defer workers.Done()
			conn := lanes[lane].conn
			header := LaneHeader{TransferID: transferID, Lane: uint16(lane), Lanes: TLSLaneCount, Framed: true, TotalSize: uint64(size), Offset: uint64(byteRange.Offset), Length: uint64(byteRange.Length), SHA256: expectedHash}
			rawHeader := EncodeLaneHeader(header)
			if err := writeFull(conn, rawHeader[:]); err != nil {
				offerTLSError(errCh, fmt.Errorf("lane %d header: %w", lane, err))
				cancel()
				return
			}
			if err := sendTLSFramedRanges(ctx, conn, input, lane, schedule, counters); err != nil {
				offerTLSError(errCh, fmt.Errorf("lane %d payload: %w", lane, err))
				cancel()
			}
		}()
	}
	workers.Wait()
	close(errCh)
	if err := joinTLSErrors(errCh); err != nil {
		return err
	}
	return ctx.Err()
}

func connectAndRequestTLSLanes(ctx context.Context, cancel context.CancelFunc, cfg TLSReceiveConnectConfig, clientConfig *tls.Config, connections *tlsConnectionSet) ([]tlsAcceptedLane, []LaneHeader, error) {
	lanes := make([]tlsAcceptedLane, TLSLaneCount)
	headers := make([]LaneHeader, TLSLaneCount)
	errCh := make(chan error, TLSLaneCount)
	var workers sync.WaitGroup
	workers.Add(TLSLaneCount)
	for lane := 0; lane < TLSLaneCount; lane++ {
		go func() {
			defer workers.Done()
			accepted, err := connectAndRequestTLSLane(ctx, cfg, clientConfig, connections, lane)
			if err != nil {
				offerTLSError(errCh, err)
				cancel()
				return
			}
			headers[lane] = accepted.header
			lanes[lane] = accepted
		}()
	}
	workers.Wait()
	close(errCh)
	if err := joinTLSErrors(errCh); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := ValidateLaneHeaders(headers); err != nil {
		return nil, nil, err
	}
	return lanes, headers, nil
}

func connectAndRequestTLSLane(ctx context.Context, cfg TLSReceiveConnectConfig, clientConfig *tls.Config, connections *tlsConnectionSet, lane int) (tlsAcceptedLane, error) {
	conn, err := dialPinnedTLS(ctx, cfg.PeerAddr, clientConfig)
	if err != nil {
		return tlsAcceptedLane{}, fmt.Errorf("lane %d dial: %w", lane, err)
	}
	connections.set(lane, conn)
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != TLSProtocol {
		return tlsAcceptedLane{}, fmt.Errorf("lane %d negotiated ALPN %q", lane, state.NegotiatedProtocol)
	}
	request := EncodeLaneRequest(LaneRequest{TransferID: cfg.TransferID, Lane: uint16(lane), Lanes: TLSLaneCount})
	if err := writeFull(conn, request[:]); err != nil {
		return tlsAcceptedLane{}, fmt.Errorf("lane %d request: %w", lane, err)
	}
	var rawHeader [TLSLaneHeaderSize]byte
	if _, err := io.ReadFull(conn, rawHeader[:]); err != nil {
		return tlsAcceptedLane{}, fmt.Errorf("lane %d header: %w", lane, err)
	}
	header, err := DecodeLaneHeader(rawHeader[:])
	if err != nil {
		return tlsAcceptedLane{}, fmt.Errorf("lane %d header: %w", lane, err)
	}
	if header.TransferID != cfg.TransferID || int(header.Lane) != lane {
		return tlsAcceptedLane{}, fmt.Errorf("lane %d response identity does not match request", lane)
	}
	return tlsAcceptedLane{conn: conn, header: header, state: state}, nil
}

func validateTLSSendListenConfig(cfg TLSSendListenConfig) error {
	if cfg.ListenAddr == "" {
		return errors.New("listen address is required")
	}
	if cfg.InputPath == "" {
		return errors.New("input path is required")
	}
	if cfg.ReadyFile == "" {
		return errors.New("ready file is required")
	}
	if cfg.TracePath == "" {
		return errors.New("trace path is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	return nil
}

func validateTLSReceiveConnectConfig(cfg TLSReceiveConnectConfig) error {
	if cfg.PeerAddr == "" {
		return errors.New("peer address is required")
	}
	if cfg.OutputPath == "" {
		return errors.New("output path is required")
	}
	if cfg.TracePath == "" {
		return errors.New("trace path is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	return nil
}
