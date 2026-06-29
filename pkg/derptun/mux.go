// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type MuxRole string

const (
	MuxRoleClient MuxRole = "client"
	MuxRoleServer MuxRole = "server"

	frameTypeOpen  = "open"
	frameTypeData  = "data"
	frameTypeClose = "close"
	frameTypeAck   = "ack"
	frameTypePing  = "ping"
	frameTypePong  = "pong"
)

const (
	maxFrameHeaderBytes  = 64 << 10
	maxFramePayloadBytes = 1 << 20
)

var errInvalidFrame = errors.New("invalid derptun mux frame")

type MuxConfig struct {
	Role             MuxRole
	ReconnectTimeout time.Duration
}

type Mux struct {
	cfg MuxConfig

	mu            sync.Mutex
	carrier       io.ReadWriteCloser
	carrierGen    uint64
	carrierChange chan struct{}
	streams       map[uint64]*muxStream
	nextStreamID  uint64
	closed        bool

	writeMu  sync.Mutex
	acceptCh chan net.Conn
	closeCh  chan struct{}

	pingMu      sync.Mutex
	nextPingID  uint64
	pongWaiters map[uint64]chan struct{}

	lastPeerActivityUnixNano atomic.Int64
}

type muxStream struct {
	id       uint64
	mux      *Mux
	conn     net.Conn
	sendLock sync.Mutex

	stateMu sync.Mutex
	sendSeq uint64
	recvSeq uint64
	pending []*pendingWrite
	inbound chan inboundFrame

	openAck       chan struct{}
	openAckOnce   sync.Once
	closeOnce     sync.Once
	inboundClosed chan struct{}
	inboundOnce   sync.Once
	deliverMu     sync.Mutex
}

type pendingWrite struct {
	startSeq    uint64
	endSeq      uint64
	lastSentGen uint64
	payload     []byte
}

type inboundFrame struct {
	header  frameHeader
	payload []byte
}

type frameHeader struct {
	Type     string `json:"type"`
	StreamID uint64 `json:"stream_id,omitempty"`
	Seq      uint64 `json:"seq,omitempty"`
	Length   int    `json:"length,omitempty"`
}

func NewMux(cfg MuxConfig) *Mux {
	nextID := uint64(1)
	if cfg.Role == MuxRoleServer {
		nextID = 2
	}

	return &Mux{
		cfg:           cfg,
		carrierChange: make(chan struct{}),
		streams:       make(map[uint64]*muxStream),
		nextStreamID:  nextID,
		acceptCh:      make(chan net.Conn, 16),
		closeCh:       make(chan struct{}),
		pongWaiters:   make(map[uint64]chan struct{}),
	}
}

func (m *Mux) ReplaceCarrier(carrier io.ReadWriteCloser) {
	var old io.ReadWriteCloser
	var generation uint64

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		if carrier != nil {
			_ = carrier.Close()
		}
		return
	}

	old = m.carrier
	m.carrier = carrier
	m.carrierGen++
	generation = m.carrierGen
	m.signalCarrierChangeLocked()
	m.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}

	if carrier != nil {
		go m.readLoop(generation, carrier)
		m.replayPendingStreams()
	}
}

func (m *Mux) OpenStream(ctx context.Context) (net.Conn, error) {
	stream, appConn := m.newStream()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = appConn.Close()
		_ = stream.conn.Close()
		return nil, net.ErrClosed
	}
	stream.id = m.nextStreamID
	m.nextStreamID += 2
	m.streams[stream.id] = stream
	m.mu.Unlock()

	if err := stream.sendOpen(ctx); err != nil {
		m.mu.Lock()
		delete(m.streams, stream.id)
		m.mu.Unlock()
		_ = appConn.Close()
		_ = stream.conn.Close()
		return nil, err
	}

	go stream.outboundPump()
	return appConn, nil
}

func (m *Mux) Accept(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case conn := <-m.acceptCh:
			return conn, nil
		default:
		}

		carrier, _, changed, closed := m.carrierSnapshot()
		if closed || carrier == nil {
			return nil, net.ErrClosed
		}

		select {
		case conn := <-m.acceptCh:
			return conn, nil
		case <-changed:
			continue
		case <-m.closeCh:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *Mux) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	carrier := m.carrier
	m.carrier = nil
	streams := make([]*muxStream, 0, len(m.streams))
	for _, stream := range m.streams {
		streams = append(streams, stream)
	}
	m.signalCarrierChangeLocked()
	close(m.closeCh)
	m.mu.Unlock()

	if carrier != nil {
		_ = carrier.Close()
	}
	for _, stream := range streams {
		stream.closeInbound()
		_ = stream.conn.Close()
	}
	return nil
}

func (m *Mux) LastPeerActivity() time.Time {
	nano := m.lastPeerActivityUnixNano.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

func (m *Mux) ActiveStreamCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.streams)
}

func (m *Mux) Ping(ctx context.Context, timeout time.Duration) error {
	deadline := m.pingDeadline(ctx, timeout)
	id := m.nextPing()
	pong := m.registerPongWaiter(id)
	defer m.removePongWaiter(id)

	if err := m.writeFrameUntilContext(ctx, frameHeader{Type: frameTypePing, Seq: id}, nil, deadline); err != nil {
		return fmt.Errorf("send ping: %w", err)
	}
	return m.waitPong(ctx, pong, deadline)
}

func (m *Mux) pingDeadline(ctx context.Context, timeout time.Duration) time.Time {
	if timeout <= 0 {
		timeout = m.cfg.ReconnectTimeout
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func (m *Mux) waitPong(ctx context.Context, pong <-chan struct{}, deadline time.Time) error {
	wait := time.Until(deadline)
	if wait <= 0 {
		return context.DeadlineExceeded
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-pong:
		return nil
	case <-m.closeCh:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("wait pong: %w", context.DeadlineExceeded)
	}
}

func (m *Mux) newStream() (*muxStream, net.Conn) {
	appConn, muxConn := net.Pipe()
	stream := &muxStream{
		mux:           m,
		conn:          muxConn,
		inbound:       make(chan inboundFrame, 128),
		openAck:       make(chan struct{}),
		inboundClosed: make(chan struct{}),
	}
	go stream.inboundPump()
	return stream, appConn
}

func (m *Mux) nextPing() uint64 {
	m.pingMu.Lock()
	defer m.pingMu.Unlock()
	m.nextPingID++
	if m.nextPingID == 0 {
		m.nextPingID++
	}
	return m.nextPingID
}

func (m *Mux) registerPongWaiter(id uint64) <-chan struct{} {
	ch := make(chan struct{})
	m.pingMu.Lock()
	m.pongWaiters[id] = ch
	m.pingMu.Unlock()
	return ch
}

func (m *Mux) removePongWaiter(id uint64) {
	m.pingMu.Lock()
	delete(m.pongWaiters, id)
	m.pingMu.Unlock()
}

func (m *Mux) handlePong(id uint64) {
	m.pingMu.Lock()
	ch := m.pongWaiters[id]
	delete(m.pongWaiters, id)
	m.pingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (m *Mux) getOrCreateRemoteStream(id uint64) (*muxStream, net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing := m.streams[id]; existing != nil {
		return existing, nil
	}

	stream, appConn := m.newStream()
	stream.id = id
	m.streams[id] = stream
	go stream.outboundPump()
	return stream, appConn
}

func (m *Mux) getStream(id uint64) *muxStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[id]
}

func (m *Mux) removeStream(id uint64, stream *muxStream) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if stream == nil || m.streams[id] == stream {
		delete(m.streams, id)
	}
}

func (m *Mux) signalCarrierChangeLocked() {
	close(m.carrierChange)
	m.carrierChange = make(chan struct{})
}

func (m *Mux) deadline() time.Time {
	if m.cfg.ReconnectTimeout <= 0 {
		return time.Now()
	}
	return time.Now().Add(m.cfg.ReconnectTimeout)
}

func (m *Mux) writeFrameUntil(header frameHeader, payload []byte, deadline time.Time) error {
	_, err := m.writeFrameUntilContextGeneration(context.Background(), header, payload, deadline)
	return err
}

func (m *Mux) writeFrameUntilContext(ctx context.Context, header frameHeader, payload []byte, deadline time.Time) error {
	_, err := m.writeFrameUntilContextGeneration(ctx, header, payload, deadline)
	return err
}

func (m *Mux) writeFrameUntilGeneration(header frameHeader, payload []byte, deadline time.Time) (uint64, error) {
	return m.writeFrameUntilContextGeneration(context.Background(), header, payload, deadline)
}

func (m *Mux) writeFrameUntilContextGeneration(ctx context.Context, header frameHeader, payload []byte, deadline time.Time) (uint64, error) {
	for {
		carrier, generation, changed, closed := m.carrierSnapshot()
		if closed {
			return 0, net.ErrClosed
		}
		if carrier == nil {
			if err := m.waitForCarrier(ctx, changed, deadline); err != nil {
				return 0, err
			}
			continue
		}

		err := m.writeOnCarrier(carrier, generation, header, payload, deadline)
		if err == nil {
			return generation, nil
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			if time.Now().After(deadline) {
				return 0, err
			}
		}
	}
}

func (m *Mux) carrierSnapshot() (io.ReadWriteCloser, uint64, chan struct{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.carrier, m.carrierGen, m.carrierChange, m.closed
}

func (m *Mux) waitForCarrier(ctx context.Context, changed <-chan struct{}, deadline time.Time) error {
	wait := time.Until(deadline)
	if wait <= 0 {
		return context.DeadlineExceeded
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-changed:
		return nil
	case <-m.closeCh:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func (m *Mux) writeOnCarrier(carrier io.ReadWriteCloser, generation uint64, header frameHeader, payload []byte, deadline time.Time) error {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(headerBytes)))

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	currentCarrier, currentGeneration, _, closed := m.carrierSnapshot()
	if closed {
		return net.ErrClosed
	}
	if currentCarrier != carrier || currentGeneration != generation {
		return io.EOF
	}
	if deadlineSetter, ok := carrier.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = deadlineSetter.SetWriteDeadline(deadline)
		defer func() { _ = deadlineSetter.SetWriteDeadline(time.Time{}) }()
	}

	if _, err := carrier.Write(prefix[:]); err != nil {
		m.markCarrierDead(generation, carrier)
		return err
	}
	if _, err := carrier.Write(headerBytes); err != nil {
		m.markCarrierDead(generation, carrier)
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := carrier.Write(payload); err != nil {
		m.markCarrierDead(generation, carrier)
		return err
	}
	return nil
}

func (m *Mux) markCarrierDead(generation uint64, carrier io.ReadWriteCloser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.carrierGen != generation || m.carrier != carrier {
		return
	}
	m.carrier = nil
	m.signalCarrierChangeLocked()
}

func (m *Mux) readLoop(generation uint64, carrier io.ReadWriteCloser) {
	for {
		header, payload, err := readFrame(carrier)
		if err != nil {
			m.markCarrierDead(generation, carrier)
			return
		}
		m.lastPeerActivityUnixNano.Store(time.Now().UnixNano())
		if err := m.handleFrame(header, payload); err != nil {
			m.markCarrierDead(generation, carrier)
			return
		}
	}
}

func (m *Mux) handleFrame(header frameHeader, payload []byte) error {
	switch header.Type {
	case frameTypeOpen:
		return m.handleOpenFrame(header)
	case frameTypeData:
		return m.handleDataFrame(header, payload)
	case frameTypeAck:
		m.handleAckFrame(header)
		return nil
	case frameTypePing:
		return m.writeFrameUntil(frameHeader{Type: frameTypePong, Seq: header.Seq}, nil, m.deadline())
	case frameTypePong:
		m.handlePong(header.Seq)
		return nil
	case frameTypeClose:
		m.handleCloseFrame(header)
		return nil
	}

	return nil
}

func (m *Mux) handleOpenFrame(header frameHeader) error {
	_, appConn := m.getOrCreateRemoteStream(header.StreamID)
	if err := m.writeFrameUntil(frameHeader{
		Type:     frameTypeAck,
		StreamID: header.StreamID,
		Seq:      0,
	}, nil, m.deadline()); err != nil {
		return err
	}
	if appConn == nil {
		return nil
	}

	select {
	case m.acceptCh <- appConn:
		return nil
	case <-m.closeCh:
		_ = appConn.Close()
		return net.ErrClosed
	}
}

func (m *Mux) handleDataFrame(header frameHeader, payload []byte) error {
	stream := m.getStream(header.StreamID)
	if stream == nil {
		return nil
	}
	frame := inboundFrame{
		header:  header,
		payload: append([]byte(nil), payload...),
	}
	select {
	case stream.inbound <- frame:
		return nil
	case <-stream.inboundClosed:
		return net.ErrClosed
	case <-m.closeCh:
		return net.ErrClosed
	}
}

func (m *Mux) deliverDataFrame(stream *muxStream, header frameHeader, payload []byte) {
	ackSeq, err := stream.deliver(header.Seq, payload)
	if err != nil {
		stream.close()
		return
	}
	_ = m.writeFrameUntil(frameHeader{
		Type:     frameTypeAck,
		StreamID: header.StreamID,
		Seq:      ackSeq,
	}, nil, m.deadline())
}

func (m *Mux) handleAckFrame(header frameHeader) {
	stream := m.getStream(header.StreamID)
	if stream == nil {
		return
	}
	if header.Seq == 0 {
		stream.handleOpenAck()
	}
	stream.handleAck(header.Seq)
}

func (m *Mux) handleCloseFrame(header frameHeader) {
	stream := m.getStream(header.StreamID)
	if stream == nil {
		return
	}
	frame := inboundFrame{header: header}
	select {
	case stream.inbound <- frame:
	case <-stream.inboundClosed:
		stream.close()
	case <-m.closeCh:
		stream.close()
	}
}

func (m *Mux) replayPendingStreams() {
	streams := m.streamSnapshot()
	for _, stream := range streams {
		go stream.replayPending()
	}
}

func (m *Mux) streamSnapshot() []*muxStream {
	m.mu.Lock()
	defer m.mu.Unlock()

	streams := make([]*muxStream, 0, len(m.streams))
	for _, stream := range m.streams {
		streams = append(streams, stream)
	}
	return streams
}

func readFrame(r io.Reader) (frameHeader, []byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return frameHeader{}, nil, err
	}

	headerLen := binary.BigEndian.Uint32(prefix[:])
	if headerLen == 0 || headerLen > maxFrameHeaderBytes {
		return frameHeader{}, nil, errInvalidFrame
	}
	headerBytes := make([]byte, headerLen)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return frameHeader{}, nil, err
	}

	var header frameHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return frameHeader{}, nil, err
	}
	if header.Length < 0 || header.Length > maxFramePayloadBytes {
		return frameHeader{}, nil, errInvalidFrame
	}

	payload := make([]byte, header.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return frameHeader{}, nil, err
	}
	return header, payload, nil
}

func (s *muxStream) outboundPump() {
	defer func() {
		s.sendClose()
		s.mux.removeStream(s.id, s)
		s.closeInbound()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			if sendErr := s.sendChunk(payload); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *muxStream) inboundPump() {
	for {
		select {
		case frame := <-s.inbound:
			if frame.header.Type == frameTypeClose {
				s.close()
				return
			}
			s.mux.deliverDataFrame(s, frame.header, frame.payload)
		case <-s.inboundClosed:
			return
		}
	}
}

func (s *muxStream) sendOpen(ctx context.Context) error {
	header := frameHeader{Type: frameTypeOpen, StreamID: s.id}
	deadline := s.mux.deadline()
	for {
		carrierChanged := s.mux.currentCarrierChange()
		if err := s.mux.writeFrameUntilContext(ctx, header, nil, deadline); err != nil {
			return err
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return context.DeadlineExceeded
		}
		timer := time.NewTimer(wait)
		select {
		case <-s.openAck:
			timer.Stop()
			return nil
		case <-carrierChanged:
			timer.Stop()
		case <-s.mux.closeCh:
			timer.Stop()
			return net.ErrClosed
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			return context.DeadlineExceeded
		}
	}
}

func (s *muxStream) sendChunk(payload []byte) error {
	s.sendLock.Lock()
	defer s.sendLock.Unlock()

	if err := s.replayStalePendingLocked(); err != nil {
		return err
	}

	payload = append([]byte(nil), payload...)

	s.stateMu.Lock()
	startSeq := s.sendSeq
	s.sendSeq += uint64(len(payload))
	s.pending = append(s.pending, &pendingWrite{
		startSeq: startSeq,
		endSeq:   startSeq + uint64(len(payload)),
		payload:  payload,
	})
	s.stateMu.Unlock()

	header := frameHeader{
		Type:     frameTypeData,
		StreamID: s.id,
		Seq:      startSeq,
		Length:   len(payload),
	}
	generation, err := s.mux.writeFrameUntilGeneration(header, payload, s.mux.deadline())
	if err != nil {
		return err
	}
	s.markPendingSentGeneration(startSeq, startSeq+uint64(len(payload)), generation)
	return nil
}

func (s *muxStream) replayPending() {
	s.sendLock.Lock()
	defer s.sendLock.Unlock()

	_ = s.replayStalePendingLocked()
}

func (s *muxStream) replayStalePendingLocked() error {
	for _, pending := range s.pendingSnapshotForGeneration(s.mux.currentCarrierGeneration()) {
		header := frameHeader{
			Type:     frameTypeData,
			StreamID: s.id,
			Seq:      pending.startSeq,
			Length:   len(pending.payload),
		}
		generation, err := s.mux.writeFrameUntilGeneration(header, pending.payload, s.mux.deadline())
		if err != nil {
			return err
		}
		s.markPendingSentGeneration(pending.startSeq, pending.endSeq, generation)
	}
	return nil
}

func (s *muxStream) pendingSnapshotForGeneration(generation uint64) []*pendingWrite {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	pending := make([]*pendingWrite, 0, len(s.pending))
	for _, write := range s.pending {
		if write.lastSentGen == generation {
			continue
		}
		pending = append(pending, &pendingWrite{
			startSeq:    write.startSeq,
			endSeq:      write.endSeq,
			lastSentGen: write.lastSentGen,
			payload:     write.payload,
		})
	}
	return pending
}

func (s *muxStream) markPendingSentGeneration(startSeq, endSeq, generation uint64) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	for _, write := range s.pending {
		if write.startSeq == startSeq && write.endSeq == endSeq {
			write.lastSentGen = generation
			return
		}
	}
}

func (s *muxStream) sendClose() {
	s.closeOnce.Do(func() {
		_ = s.mux.writeFrameUntil(frameHeader{Type: frameTypeClose, StreamID: s.id}, nil, s.mux.deadline())
	})
}

func (s *muxStream) closeInbound() {
	s.inboundOnce.Do(func() {
		close(s.inboundClosed)
	})
}

func (s *muxStream) close() {
	s.mux.removeStream(s.id, s)
	s.closeInbound()
	_ = s.conn.Close()
}

func (s *muxStream) deliver(seq uint64, payload []byte) (uint64, error) {
	s.deliverMu.Lock()
	defer s.deliverMu.Unlock()

	s.stateMu.Lock()
	switch {
	case seq < s.recvSeq:
		ack := s.recvSeq
		s.stateMu.Unlock()
		return ack, nil
	case seq > s.recvSeq:
		ack := s.recvSeq
		s.stateMu.Unlock()
		return ack, nil
	default:
	}
	s.stateMu.Unlock()

	if _, err := s.conn.Write(payload); err != nil {
		return 0, err
	}

	s.stateMu.Lock()
	s.recvSeq += uint64(len(payload))
	ack := s.recvSeq
	s.stateMu.Unlock()
	return ack, nil
}

func (s *muxStream) handleOpenAck() {
	s.openAckOnce.Do(func() {
		close(s.openAck)
	})
}

func (s *muxStream) handleAck(ack uint64) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	cut := 0
	for cut < len(s.pending) && ack >= s.pending[cut].endSeq {
		cut++
	}
	if cut == 0 {
		return
	}
	copy(s.pending, s.pending[cut:])
	for i := len(s.pending) - cut; i < len(s.pending); i++ {
		s.pending[i] = nil
	}
	s.pending = s.pending[:len(s.pending)-cut]
}

func (m *Mux) currentCarrierChange() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.carrierChange
}

func (m *Mux) currentCarrierGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.carrierGen
}
