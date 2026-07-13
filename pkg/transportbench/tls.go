// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const tlsTransferBufferSize = 1 << 20

type TLSReceiveConfig struct {
	ListenAddr string
	OutputPath string
	ReadyFile  string
	TracePath  string
	Timeout    time.Duration
}

type TLSSendConfig struct {
	PeerAddr          string
	FingerprintSHA256 string
	TransferID        [16]byte
	InputPath         string
	TracePath         string
	Timeout           time.Duration
}

type Ready struct {
	SchemaVersion     int    `json:"schema_version"`
	Address           string `json:"address"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	TransferID        string `json:"transfer_id"`
}

type TransferSummary struct {
	SchemaVersion        int                 `json:"schema_version"`
	Engine               Engine              `json:"engine"`
	Role                 string              `json:"role"`
	SizeBytes            int64               `json:"size_bytes"`
	SHA256               string              `json:"sha256"`
	TransferElapsedMS    int64               `json:"transfer_elapsed_ms"`
	CommandElapsedMS     int64               `json:"command_elapsed_ms"`
	CanonicalGoodputMbps float64             `json:"canonical_goodput_mbps"`
	WallGoodputMbps      float64             `json:"wall_goodput_mbps"`
	Connections          int                 `json:"connections"`
	TLSVersion           string              `json:"tls_version"`
	TLSCipher            string              `json:"tls_cipher"`
	ALPN                 string              `json:"alpn"`
	PinVerified          bool                `json:"pin_verified"`
	TCPInfoSupported     bool                `json:"tcp_info_supported"`
	TCPRetransmits       *uint64             `json:"tcp_retransmits"`
	TCPCwndSegments      *uint32             `json:"tcp_cwnd_segments"`
	ReadCalls            uint64              `json:"read_calls"`
	WriteCalls           uint64              `json:"write_calls"`
	BytesPerReadCall     float64             `json:"bytes_per_read_call"`
	BytesPerWriteCall    float64             `json:"bytes_per_write_call"`
	LaneBytes            [TLSLaneCount]int64 `json:"lane_bytes"`
}

type tlsAcceptedLane struct {
	conn   *tls.Conn
	header LaneHeader
	state  tls.ConnectionState
}

type tlsTransferCounters struct {
	lanes      [TLSLaneCount]atomic.Int64
	firstNS    atomic.Int64
	lastNS     atomic.Int64
	readCalls  atomic.Uint64
	readBytes  atomic.Int64
	writeCalls atomic.Uint64
	writeBytes atomic.Int64
}

func (c *tlsTransferCounters) recordCommitted(lane int, bytes int, at time.Time) {
	if bytes <= 0 {
		return
	}
	nanos := at.UnixNano()
	c.firstNS.CompareAndSwap(0, nanos)
	c.lastNS.Store(nanos)
	c.lanes[lane].Add(int64(bytes))
}

func (c *tlsTransferCounters) snapshotLanes() [TLSLaneCount]int64 {
	var result [TLSLaneCount]int64
	for lane := range result {
		result[lane] = c.lanes[lane].Load()
	}
	return result
}

func ReceiveTLS(parent context.Context, cfg TLSReceiveConfig) (summary TransferSummary, retErr error) {
	commandStarted := time.Now()
	if err := validateTLSReceiveConfig(cfg); err != nil {
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

	setup, err := prepareTLSReceiver(cfg, commandStarted)
	if err != nil {
		return TransferSummary{}, err
	}
	defer func() { _ = setup.listener.Close() }()
	listenerDone := closeListenerOnContext(ctx, setup.listener)
	defer func() {
		cancel()
		<-listenerDone
	}()

	lanes, headers, err := acceptAndValidateTLSLanes(ctx, setup)
	if err != nil {
		return TransferSummary{}, err
	}
	connections := laneConnections(lanes)
	defer closeConnections(connections)

	actualHash, size, err := receiveAndVerifyTLSFile(ctx, cfg.OutputPath, lanes, headers[0], counters)
	if err != nil {
		return TransferSummary{}, err
	}
	summary = buildTransferSummary("receiver", size, actualHash, commandStarted, lanes[0].state, counters, connections)
	return summary, nil
}

type tlsReceiverSetup struct {
	listener     net.Listener
	serverConfig *tls.Config
	transferID   [16]byte
}

func prepareTLSReceiver(cfg TLSReceiveConfig, commandStarted time.Time) (tlsReceiverSetup, error) {
	certificate, fingerprint, err := newEphemeralTLSCertificate(commandStarted)
	if err != nil {
		return tlsReceiverSetup{}, err
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return tlsReceiverSetup{}, err
	}
	var transferID [16]byte
	if _, err := rand.Read(transferID[:]); err != nil {
		_ = listener.Close()
		return tlsReceiverSetup{}, fmt.Errorf("generate transfer ID: %w", err)
	}
	ready := Ready{SchemaVersion: ResultSchemaVersion, Address: listener.Addr().String(), FingerprintSHA256: fingerprint, TransferID: hex.EncodeToString(transferID[:])}
	if err := writeReadyFile(cfg.ReadyFile, ready); err != nil {
		_ = listener.Close()
		return tlsReceiverSetup{}, err
	}
	return tlsReceiverSetup{
		listener:   listener,
		transferID: transferID,
		serverConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{TLSProtocol},
		},
	}, nil
}

func acceptAndValidateTLSLanes(ctx context.Context, setup tlsReceiverSetup) ([]tlsAcceptedLane, []LaneHeader, error) {
	lanes, err := acceptTLSLanes(ctx, setup.listener, setup.serverConfig, setup.transferID)
	if err != nil {
		return nil, nil, err
	}
	headers := make([]LaneHeader, len(lanes))
	for index, lane := range lanes {
		headers[index] = lane.header
	}
	if err := ValidateLaneHeaders(headers); err != nil {
		closeAcceptedLanes(lanes)
		return nil, nil, err
	}
	if headers[0].TransferID != setup.transferID {
		closeAcceptedLanes(lanes)
		return nil, nil, errors.New("lane transfer ID does not match ready descriptor")
	}
	return lanes, headers, nil
}

func receiveAndVerifyTLSFile(ctx context.Context, outputPath string, lanes []tlsAcceptedLane, header LaneHeader, counters *tlsTransferCounters) (hash [sha256.Size]byte, size int64, retErr error) {
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return hash, 0, fmt.Errorf("open output: %w", err)
	}
	outputClosed := false
	defer func() {
		if !outputClosed {
			retErr = errors.Join(retErr, output.Close())
		}
	}()
	if err := output.Truncate(int64(header.TotalSize)); err != nil {
		return hash, 0, fmt.Errorf("size output: %w", err)
	}
	if err := receiveTLSPayloads(ctx, lanes, output, counters); err != nil {
		return hash, 0, err
	}
	if err := output.Close(); err != nil {
		return hash, 0, fmt.Errorf("close output: %w", err)
	}
	outputClosed = true
	hash, size, err = hashFile(outputPath)
	if err != nil {
		return hash, 0, err
	}
	if size != int64(header.TotalSize) {
		return hash, size, fmt.Errorf("received size %d, want %d", size, header.TotalSize)
	}
	if hash != header.SHA256 {
		return hash, size, errors.New("received SHA-256 does not match lane header")
	}
	return hash, size, nil
}

func SendTLS(parent context.Context, cfg TLSSendConfig) (summary TransferSummary, retErr error) {
	commandStarted := time.Now()
	if err := validateTLSSendConfig(cfg); err != nil {
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

	input, expectedHash, size, ranges, clientConfig, err := prepareTLSSendInput(cfg)
	if err != nil {
		return TransferSummary{}, err
	}
	defer func() { _ = input.Close() }()

	connections := newTLSConnectionSet()
	defer connections.closeAll()
	interruptDone := connections.interruptOnContext(ctx)
	defer func() {
		cancel()
		<-interruptDone
	}()

	states, err := sendTLSLanes(ctx, cancel, cfg, input, expectedHash, size, ranges, clientConfig, connections, counters)
	if err != nil {
		return TransferSummary{}, err
	}
	summary = buildTransferSummary("sender", size, expectedHash, commandStarted, states[0], counters, connections.snapshot())
	return summary, nil
}

func prepareTLSSendInput(cfg TLSSendConfig) (*os.File, [sha256.Size]byte, int64, []ByteRange, *tls.Config, error) {
	input, err := os.Open(cfg.InputPath)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, nil, fmt.Errorf("open input: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = input.Close()
		}
	}()
	info, err := input.Stat()
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, [sha256.Size]byte{}, 0, nil, nil, errors.New("input must be a regular file")
	}
	expectedHash, size, err := hashOpenFile(input)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, nil, err
	}
	ranges, err := SplitRanges(size, TLSLaneCount)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, nil, err
	}
	clientConfig, err := newPinnedTLSClientConfig(cfg.FingerprintSHA256)
	if err != nil {
		return nil, [sha256.Size]byte{}, 0, nil, nil, err
	}
	success = true
	return input, expectedHash, size, ranges, clientConfig, nil
}

func sendTLSLanes(ctx context.Context, cancel context.CancelFunc, cfg TLSSendConfig, input *os.File, expectedHash [sha256.Size]byte, size int64, ranges []ByteRange, clientConfig *tls.Config, connections *tlsConnectionSet, counters *tlsTransferCounters) ([]tls.ConnectionState, error) {
	states := make([]tls.ConnectionState, TLSLaneCount)
	schedule := newTLSChunkSchedule(size)
	errCh := make(chan error, TLSLaneCount)
	var workers sync.WaitGroup
	workers.Add(TLSLaneCount)
	for lane, byteRange := range ranges {
		go func() {
			defer workers.Done()
			sendTLSLane(ctx, cancel, cfg, input, expectedHash, size, lane, byteRange, schedule, clientConfig, connections, counters, states, errCh)
		}()
	}
	workers.Wait()
	close(errCh)
	if err := joinTLSErrors(errCh); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return states, nil
}

func sendTLSLane(ctx context.Context, cancel context.CancelFunc, cfg TLSSendConfig, input *os.File, expectedHash [sha256.Size]byte, size int64, lane int, byteRange ByteRange, schedule *tlsChunkSchedule, clientConfig *tls.Config, connections *tlsConnectionSet, counters *tlsTransferCounters, states []tls.ConnectionState, errCh chan<- error) {
	conn, err := dialPinnedTLS(ctx, cfg.PeerAddr, clientConfig)
	if err != nil {
		offerTLSError(errCh, fmt.Errorf("lane %d dial: %w", lane, err))
		cancel()
		return
	}
	connections.set(lane, conn)
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	states[lane] = state
	if state.NegotiatedProtocol != TLSProtocol {
		offerTLSError(errCh, fmt.Errorf("lane %d negotiated ALPN %q", lane, state.NegotiatedProtocol))
		cancel()
		return
	}
	header := LaneHeader{TransferID: cfg.TransferID, Lane: uint16(lane), Lanes: TLSLaneCount, Framed: true, TotalSize: uint64(size), Offset: uint64(byteRange.Offset), Length: uint64(byteRange.Length), SHA256: expectedHash}
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
}

func validateTLSReceiveConfig(cfg TLSReceiveConfig) error {
	if cfg.ListenAddr == "" {
		return errors.New("listen address is required")
	}
	if cfg.OutputPath == "" {
		return errors.New("output path is required")
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

func validateTLSSendConfig(cfg TLSSendConfig) error {
	if cfg.PeerAddr == "" {
		return errors.New("peer address is required")
	}
	if cfg.InputPath == "" {
		return errors.New("input path is required")
	}
	if cfg.TracePath == "" {
		return errors.New("trace path is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	return nil
}

func newEphemeralTLSCertificate(now time.Time) (tls.Certificate, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate certificate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "derphole transport feasibility"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create certificate: %w", err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("parse certificate: %w", err)
	}
	certificate.Leaf = parsed
	fingerprint := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return certificate, hex.EncodeToString(fingerprint[:]), nil
}

func newPinnedTLSClientConfig(fingerprintHex string) (*tls.Config, error) {
	expected, err := hex.DecodeString(fingerprintHex)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("certificate fingerprint must be 64 hexadecimal characters")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{TLSProtocol},
		InsecureSkipVerify: true, // VerifyConnection pins the authenticated session certificate.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return fmt.Errorf("certificate fingerprint verification received %d certificates", len(state.PeerCertificates))
			}
			actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return errors.New("certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}

func dialPinnedTLS(ctx context.Context, address string, config *tls.Config) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    config,
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("TLS dial returned %T", conn)
	}
	return tlsConn, nil
}

func acceptTLSLanes(ctx context.Context, listener net.Listener, config *tls.Config, transferID [16]byte) ([]tlsAcceptedLane, error) {
	lanes := make([]tlsAcceptedLane, 0, TLSLaneCount)
	for len(lanes) < TLSLaneCount {
		rawConn, err := listener.Accept()
		if err != nil {
			closeAcceptedLanes(lanes)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("accept lane: %w", err)
		}
		conn := tls.Server(rawConn, config)
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, fmt.Errorf("handshake lane %d: %w", len(lanes), err)
		}
		var rawHeader [TLSLaneHeaderSize]byte
		if _, err := io.ReadFull(conn, rawHeader[:]); err != nil {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, fmt.Errorf("read lane %d header: %w", len(lanes), err)
		}
		header, err := DecodeLaneHeader(rawHeader[:])
		if err != nil {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, err
		}
		if header.TransferID != transferID {
			_ = conn.Close()
			closeAcceptedLanes(lanes)
			return nil, errors.New("lane transfer ID does not match ready descriptor")
		}
		lanes = append(lanes, tlsAcceptedLane{conn: conn, header: header, state: conn.ConnectionState()})
	}
	return lanes, nil
}

func receiveTLSPayloads(ctx context.Context, lanes []tlsAcceptedLane, output io.WriterAt, counters *tlsTransferCounters) error {
	if len(lanes) == 0 {
		return errors.New("TLS payload requires at least one lane")
	}
	if !lanes[0].header.Framed {
		return errors.New("unframed TLS payloads are unsupported")
	}
	return receiveTLSFramedPayloads(ctx, lanes, output, int64(lanes[0].header.TotalSize), counters)
}

func buildTransferSummary(role string, size int64, hash [sha256.Size]byte, commandStarted time.Time, state tls.ConnectionState, counters *tlsTransferCounters, connections []net.Conn) TransferSummary {
	first := counters.firstNS.Load()
	last := counters.lastNS.Load()
	transferDuration := time.Duration(max(int64(1), last-first))
	commandDuration := time.Since(commandStarted)
	retransmits, cwnd, tcpInfoSupported := aggregateTCPInfo(connections)
	readCalls := counters.readCalls.Load()
	writeCalls := counters.writeCalls.Load()
	return TransferSummary{
		SchemaVersion:        ResultSchemaVersion,
		Engine:               EngineTLS8,
		Role:                 role,
		SizeBytes:            size,
		SHA256:               hex.EncodeToString(hash[:]),
		TransferElapsedMS:    roundedUpMilliseconds(transferDuration),
		CommandElapsedMS:     roundedUpMilliseconds(commandDuration),
		CanonicalGoodputMbps: goodputMbps(size, transferDuration),
		WallGoodputMbps:      goodputMbps(size, commandDuration),
		Connections:          TLSLaneCount,
		TLSVersion:           tlsVersionName(state.Version),
		TLSCipher:            tls.CipherSuiteName(state.CipherSuite),
		ALPN:                 state.NegotiatedProtocol,
		PinVerified:          true,
		TCPInfoSupported:     tcpInfoSupported,
		TCPRetransmits:       retransmits,
		TCPCwndSegments:      cwnd,
		ReadCalls:            readCalls,
		WriteCalls:           writeCalls,
		BytesPerReadCall:     averageBytes(counters.readBytes.Load(), readCalls),
		BytesPerWriteCall:    averageBytes(counters.writeBytes.Load(), writeCalls),
		LaneBytes:            counters.snapshotLanes(),
	}
}

func hashFile(path string) ([sha256.Size]byte, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, 0, fmt.Errorf("open file for hashing: %w", err)
	}
	defer func() { _ = file.Close() }()
	return hashOpenFile(file)
}

func hashOpenFile(file *os.File) ([sha256.Size]byte, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, 0, fmt.Errorf("seek file for hashing: %w", err)
	}
	hasher := sha256.New()
	size, err := io.CopyBuffer(hasher, file, make([]byte, tlsTransferBufferSize))
	if err != nil {
		return [sha256.Size]byte{}, 0, fmt.Errorf("hash file: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, 0, fmt.Errorf("rewind file after hashing: %w", err)
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result, size, nil
}

func writeReadyFile(path string, ready Ready) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create ready file: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set ready file mode: %w", err)
	}
	encoder := json.NewEncoder(temp)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(ready); err != nil {
		return fmt.Errorf("encode ready file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync ready file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close ready file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish ready file: %w", err)
	}
	removeTemp = false
	return nil
}

type tlsConnectionSet struct {
	mu    sync.Mutex
	conns [TLSLaneCount]*tls.Conn
}

func newTLSConnectionSet() *tlsConnectionSet { return &tlsConnectionSet{} }

func (s *tlsConnectionSet) set(lane int, conn *tls.Conn) {
	s.mu.Lock()
	s.conns[lane] = conn
	s.mu.Unlock()
}

func (s *tlsConnectionSet) snapshot() []net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]net.Conn, 0, len(s.conns))
	for _, conn := range s.conns {
		if conn != nil {
			result = append(result, conn)
		}
	}
	return result
}

func (s *tlsConnectionSet) closeAll() { closeConnections(s.snapshot()) }

func (s *tlsConnectionSet) interruptOnContext(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		for _, conn := range s.snapshot() {
			_ = conn.SetDeadline(time.Now())
		}
	}()
	return done
}

func closeListenerOnContext(ctx context.Context, listener net.Listener) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		_ = listener.Close()
	}()
	return done
}

func laneConnections(lanes []tlsAcceptedLane) []net.Conn {
	result := make([]net.Conn, len(lanes))
	for index, lane := range lanes {
		result[index] = lane.conn
	}
	return result
}

func closeAcceptedLanes(lanes []tlsAcceptedLane) {
	closeConnections(laneConnections(lanes))
}

func closeConnections(connections []net.Conn) {
	for _, conn := range connections {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func offerTLSError(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func joinTLSErrors(ch <-chan error) error {
	var errs []error
	for err := range ch {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func roundedUpMilliseconds(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	return (duration.Nanoseconds() + int64(time.Millisecond) - 1) / int64(time.Millisecond)
}

func goodputMbps(bytes int64, duration time.Duration) float64 {
	if bytes <= 0 || duration <= 0 {
		return 0
	}
	return float64(bytes*8) / duration.Seconds() / 1_000_000
}

func averageBytes(bytes int64, calls uint64) float64 {
	if calls == 0 {
		return 0
	}
	return float64(bytes) / float64(calls)
}

func tlsVersionName(version uint16) string {
	if version == tls.VersionTLS13 {
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", version)
}

type tlsTraceRecorder struct {
	file     *os.File
	stopOnce sync.Once
	stopCh   chan string
	done     chan struct{}
	errMu    sync.Mutex
	err      error
}

func startTLSTrace(path, role string, started time.Time, counters *tlsTransferCounters) (*tlsTraceRecorder, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open TLS trace: %w", err)
	}
	recorder := &tlsTraceRecorder{
		file:   file,
		stopCh: make(chan string, 1),
		done:   make(chan struct{}),
	}
	go recorder.run(role, started, counters)
	return recorder, nil
}

func (r *tlsTraceRecorder) run(role string, started time.Time, counters *tlsTransferCounters) {
	defer close(r.done)
	defer func() { _ = r.file.Close() }()
	w := csv.NewWriter(r.file)
	if err := writeTLSTraceHeader(w); err != nil {
		r.setError(err)
		return
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	sampler := tlsTraceSampler{recorder: r, writer: w, role: role, started: started, previousAt: started, counters: counters}
	for {
		select {
		case at := <-ticker.C:
			if !sampler.write(at, "") {
				return
			}
		case lastError := <-r.stopCh:
			sampler.write(time.Now(), lastError)
			return
		}
	}
}

func writeTLSTraceHeader(w *csv.Writer) error {
	header := []string{"timestamp_unix_ms", "elapsed_ms", "role"}
	for lane := 0; lane < TLSLaneCount; lane++ {
		header = append(header, fmt.Sprintf("lane_%d_bytes", lane))
	}
	header = append(header, "total_bytes", "delta_bytes", "mbps", "tcp_retransmits", "tcp_cwnd_segments", "last_error")
	if err := w.Write(header); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

type tlsTraceSampler struct {
	recorder      *tlsTraceRecorder
	writer        *csv.Writer
	role          string
	started       time.Time
	previousAt    time.Time
	previousBytes int64
	counters      *tlsTransferCounters
}

func (s *tlsTraceSampler) write(at time.Time, lastError string) bool {
	lanes := s.counters.snapshotLanes()
	var total int64
	row := []string{strconv.FormatInt(at.UnixMilli(), 10), strconv.FormatInt(at.Sub(s.started).Milliseconds(), 10), s.role}
	for _, value := range lanes {
		total += value
		row = append(row, strconv.FormatInt(value, 10))
	}
	delta := total - s.previousBytes
	row = append(row,
		strconv.FormatInt(total, 10),
		strconv.FormatInt(delta, 10),
		strconv.FormatFloat(goodputMbps(delta, at.Sub(s.previousAt)), 'f', 3, 64),
		"", "", lastError,
	)
	if err := s.writer.Write(row); err != nil {
		s.recorder.setError(err)
		return false
	}
	s.writer.Flush()
	if err := s.writer.Error(); err != nil {
		s.recorder.setError(err)
		return false
	}
	s.previousAt = at
	s.previousBytes = total
	return true
}

func (r *tlsTraceRecorder) stop(transferErr error) error {
	lastError := ""
	if transferErr != nil {
		lastError = transferErr.Error()
	}
	r.stopOnce.Do(func() { r.stopCh <- lastError })
	<-r.done
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

func (r *tlsTraceRecorder) setError(err error) {
	r.errMu.Lock()
	r.err = errors.Join(r.err, err)
	r.errMu.Unlock()
}

func aggregateTCPInfo(connections []net.Conn) (*uint64, *uint32, bool) {
	var totalRetransmits uint64
	var minimumCwnd uint32
	supportedCount := 0
	for _, conn := range connections {
		info, ok := tcpInfoForConn(conn)
		if !ok {
			continue
		}
		supportedCount++
		totalRetransmits += info.retransmits
		if minimumCwnd == 0 || info.cwndSegments < minimumCwnd {
			minimumCwnd = info.cwndSegments
		}
	}
	if supportedCount != len(connections) || len(connections) == 0 {
		return nil, nil, false
	}
	return &totalRetransmits, &minimumCwnd, true
}
