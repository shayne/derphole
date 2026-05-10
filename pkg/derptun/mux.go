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
	pending *pendingWrite

	openAck     chan struct{}
	openAckOnce sync.Once
	closeOnce   sync.Once
	deliverMu   sync.Mutex
}

type pendingWrite struct {
	endSeq uint64
	acked  chan struct{}
	once   sync.Once
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
	if timeout <= 0 {
		timeout = m.cfg.ReconnectTimeout
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	id := m.nextPing()
	pong := m.registerPongWaiter(id)
	defer m.removePongWaiter(id)

	if err := m.writeFrameUntilContext(ctx, frameHeader{Type: frameTypePing, Seq: id}, nil, deadline); err != nil {
		return fmt.Errorf("send ping: %w", err)
	}

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
	return &muxStream{
		mux:     m,
		conn:    muxConn,
		openAck: make(chan struct{}),
	}, appConn
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
	return m.writeFrameUntilContext(context.Background(), header, payload, deadline)
}

func (m *Mux) writeFrameUntilContext(ctx context.Context, header frameHeader, payload []byte, deadline time.Time) error {
	for {
		carrier, generation, changed, closed := m.carrierSnapshot()
		if closed {
			return net.ErrClosed
		}
		if carrier == nil {
			if err := m.waitForCarrier(ctx, changed, deadline); err != nil {
				return err
			}
			continue
		}

		err := m.writeOnCarrier(carrier, generation, header, payload, deadline)
		if err == nil {
			return nil
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			if time.Now().After(deadline) {
				return err
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
		defer deadlineSetter.SetWriteDeadline(time.Time{})
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

	case frameTypeData:
		stream := m.getStream(header.StreamID)
		if stream == nil {
			return nil
		}
		go func() {
			ackSeq, err := stream.deliver(header.Seq, payload)
			if err != nil {
				m.removeStream(header.StreamID, stream)
				_ = stream.conn.Close()
				return
			}
			_ = m.writeFrameUntil(frameHeader{
				Type:     frameTypeAck,
				StreamID: header.StreamID,
				Seq:      ackSeq,
			}, nil, m.deadline())
		}()
		return nil

	case frameTypeAck:
		stream := m.getStream(header.StreamID)
		if stream != nil {
			if header.Seq == 0 {
				stream.handleOpenAck()
			}
			stream.handleAck(header.Seq)
		}
		return nil

	case frameTypePing:
		return m.writeFrameUntil(frameHeader{Type: frameTypePong, Seq: header.Seq}, nil, m.deadline())

	case frameTypePong:
		m.handlePong(header.Seq)
		return nil

	case frameTypeClose:
		stream := m.getStream(header.StreamID)
		if stream != nil {
			m.removeStream(header.StreamID, stream)
			_ = stream.conn.Close()
		}
		return nil
	}

	return nil
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

	s.stateMu.Lock()
	startSeq := s.sendSeq
	s.sendSeq += uint64(len(payload))
	pending := &pendingWrite{
		endSeq: startSeq + uint64(len(payload)),
		acked:  make(chan struct{}),
	}
	s.pending = pending
	s.stateMu.Unlock()

	defer func() {
		s.stateMu.Lock()
		if s.pending == pending {
			s.pending = nil
		}
		s.stateMu.Unlock()
	}()

	header := frameHeader{
		Type:     frameTypeData,
		StreamID: s.id,
		Seq:      startSeq,
		Length:   len(payload),
	}
	deadline := s.mux.deadline()

	for {
		carrierChanged := s.mux.currentCarrierChange()
		if err := s.mux.writeFrameUntil(header, payload, deadline); err != nil {
			return err
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return context.DeadlineExceeded
		}

		timer := time.NewTimer(wait)
		select {
		case <-pending.acked:
			timer.Stop()
			return nil
		case <-carrierChanged:
			timer.Stop()
		case <-s.mux.closeCh:
			timer.Stop()
			return net.ErrClosed
		case <-timer.C:
			return context.DeadlineExceeded
		}
	}
}

func (s *muxStream) sendClose() {
	s.closeOnce.Do(func() {
		_ = s.mux.writeFrameUntil(frameHeader{Type: frameTypeClose, StreamID: s.id}, nil, s.mux.deadline())
	})
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

	if s.pending == nil || ack < s.pending.endSeq {
		return
	}
	s.pending.once.Do(func() {
		close(s.pending.acked)
	})
}

func (m *Mux) currentCarrierChange() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.carrierChange
}
