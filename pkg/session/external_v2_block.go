// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/transport"
)

const (
	externalV2TransferModeBlocks       = "blocks-v1"
	externalV2TransferModeBulkPackets  = "bulk-packets-v1"
	externalV2BlockFrameSize           = 12
	externalV2DefaultBlockChunkSize    = 256 << 10
	externalV2BulkPacketCandidateLimit = 4
)

type externalV2BlockChunk struct {
	offset int64
	data   []byte
	frame  []byte
}

type externalV2BlockReceiveConfig struct {
	PayloadSize int64
	ChunkSize   int
	HeaderBytes int64
}

func externalV2BlockChunkSize(chunkSize int) int {
	if chunkSize > 0 {
		return chunkSize
	}
	return externalV2DefaultBlockChunkSize
}

func validExternalV2BlockSource(src *BlockSource) bool {
	return src != nil && src.Payload != nil && src.PayloadSize >= 0
}

func externalV2BlockSourceHeader(src *BlockSource) []byte {
	if src == nil {
		return nil
	}
	if src.HeaderFunc != nil {
		return append([]byte(nil), src.HeaderFunc()...)
	}
	return append([]byte(nil), src.Header...)
}

func externalV2BlockSourceClaim(src *BlockSource, claim *externalV2Claim) {
	if !validExternalV2BlockSource(src) || claim == nil {
		return
	}
	claim.TransferMode = externalV2TransferModeBlocks
	claim.BlockHeader = externalV2BlockSourceHeader(src)
	claim.BlockSize = src.PayloadSize
	claim.BlockChunkSize = externalV2BlockChunkSize(src.ChunkSize)
	claim.BlockPacketCapable = true
}

func externalV2BlockSourceAccept(src *BlockSource, accept *externalV2Accept) {
	if !validExternalV2BlockSource(src) || accept == nil {
		return
	}
	accept.TransferMode = externalV2TransferModeBlocks
	accept.BlockHeader = externalV2BlockSourceHeader(src)
	accept.BlockSize = src.PayloadSize
	accept.BlockChunkSize = externalV2BlockChunkSize(src.ChunkSize)
}

func externalV2AcceptsBlockTransfer(accept externalV2Accept) bool {
	return accept.TransferMode == externalV2TransferModeBlocks || accept.TransferMode == externalV2TransferModeBulkPackets
}

func externalV2AcceptCarriesBlockTransfer(accept externalV2Accept) bool {
	return externalV2AcceptsBlockTransfer(accept) && accept.BlockSize >= 0 && accept.BlockChunkSize > 0
}

func externalV2ClaimRequestsBlockTransfer(claim externalV2Claim) bool {
	return claim.TransferMode == externalV2TransferModeBlocks && claim.BlockSize >= 0 && claim.BlockChunkSize > 0
}

func externalV2AcceptedBlockTransferMode(claim externalV2Claim, blockTransfer bool, acceptCandidates []string) string {
	if !blockTransfer {
		return ""
	}
	if externalV2ClaimPrefersBulkPacketTransfer(claim, acceptCandidates) {
		return externalV2TransferModeBulkPackets
	}
	return externalV2TransferModeBlocks
}

func externalV2ClaimPrefersBulkPacketTransfer(claim externalV2Claim, acceptCandidates []string) bool {
	return claim.BlockPacketCapable && len(acceptCandidates) <= externalV2BulkPacketCandidateLimit
}

func externalV2UsesBulkPacketTransfer(mode string) bool {
	return mode == externalV2TransferModeBulkPackets
}

func (rt *externalV2ListenRuntime) openBlockReceive(ctx context.Context, claim externalV2Claim) (*countingBlockReceiveSink, externalV2BlockReceiveConfig, error) {
	if rt.cfg.BlockReceiver == nil {
		return nil, externalV2BlockReceiveConfig{}, errors.New("block receiver is not configured")
	}
	chunkSize := externalV2BlockChunkSize(claim.BlockChunkSize)
	req := BlockReceiveRequest{
		Header:      append([]byte(nil), claim.BlockHeader...),
		PayloadSize: claim.BlockSize,
		ChunkSize:   chunkSize,
	}
	sink, err := rt.cfg.BlockReceiver(ctx, req)
	if err != nil {
		return nil, externalV2BlockReceiveConfig{}, err
	}
	if sink == nil {
		return nil, externalV2BlockReceiveConfig{}, errors.New("block receiver returned nil sink")
	}
	cfg := externalV2BlockReceiveConfig{
		PayloadSize: claim.BlockSize,
		ChunkSize:   chunkSize,
		HeaderBytes: int64(len(claim.BlockHeader)),
	}
	return newCountingBlockReceiveSink(sink, cfg.HeaderBytes), cfg, nil
}

func (rt *externalV2OfferReceiveRuntime) openBlockReceive(ctx context.Context, accept externalV2Accept) (*countingBlockReceiveSink, externalV2BlockReceiveConfig, error) {
	if rt.cfg.BlockReceiver == nil {
		return nil, externalV2BlockReceiveConfig{}, errors.New("block receiver is not configured")
	}
	chunkSize := externalV2BlockChunkSize(accept.BlockChunkSize)
	req := BlockReceiveRequest{
		Header:      append([]byte(nil), accept.BlockHeader...),
		PayloadSize: accept.BlockSize,
		ChunkSize:   chunkSize,
	}
	sink, err := rt.cfg.BlockReceiver(ctx, req)
	if err != nil {
		return nil, externalV2BlockReceiveConfig{}, err
	}
	if sink == nil {
		return nil, externalV2BlockReceiveConfig{}, errors.New("block receiver returned nil sink")
	}
	cfg := externalV2BlockReceiveConfig{
		PayloadSize: accept.BlockSize,
		ChunkSize:   chunkSize,
		HeaderBytes: int64(len(accept.BlockHeader)),
	}
	return newCountingBlockReceiveSink(sink, cfg.HeaderBytes), cfg, nil
}

func (rt *externalV2ListenRuntime) receiveQUICBlock(ctx context.Context, accepted externalV2AcceptedClaim, transferMode string, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, sink BlockReceiveSink, blockCfg externalV2BlockReceiveConfig, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	server := dataplane.NewQUICServer(tr.manager, rt.session.quicIdentity, accepted.claim.QUICPublic)
	server.SetManagerConnectionCount(managerConnections)
	streamCount := externalV2StreamCount(policy)
	rawPath, err := negotiateExternalV2DirectPacketPath(streamCtx, rt.session.derp, accepted.peerDERP, tr.manager, rt.session.derpMap, rt.auth, rt.cfg.Emitter, streamCount, 0, rawDirectBudget, tr.relayOnly)
	if err != nil {
		return err
	}
	defer rawPath.Close()
	if rawPath.raw {
		if externalV2UsesBulkPacketTransfer(transferMode) {
			emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=bulk-packets")
			abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, cancelStream)
			defer stopAbortWatch()
			return rt.receiveBulkPacketBlock(streamCtx, ctx, accepted, rawPath, sink, blockCfg, metrics, pathEmitter, tr.manager, abortErrCh)
		}
		server = dataplane.NewQUICServerOnPacketConns(rawPath.conns, rt.session.quicIdentity, accepted.claim.QUICPublic)
		server.SetManagerConnectionCount(managerConnections)
	}
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, func() {
		cancelStream()
		_ = server.CloseWithError(1, "peer aborted transfer")
	})
	defer stopAbortWatch()
	openCtx := streamCtx
	cancelOpen := func() {}
	boundedOpen := rawPath.raw
	if rawPath.raw {
		openCtx, cancelOpen = context.WithTimeout(streamCtx, externalV2StreamOpenWait)
	}
	streams, err := server.AcceptStreamsWithReady(openCtx, streamCount, nil)
	cancelOpen()
	if err != nil {
		err = externalV2PreferPeerAbort(ctx, abortErrCh, err)
		if boundedOpen {
			err = externalV2StreamOpenFailure(err)
		}
		return err
	}
	bytesReceived, err := receiveExternalV2BlockStreams(streamCtx, sink, blockCfg, streams, metrics)
	if err != nil {
		_ = server.CloseWithError(1, err.Error())
		return externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}
	if err := rt.sendComplete(ctx, accepted.peerDERP, bytesReceived); err != nil {
		_ = server.CloseWithError(1, err.Error())
		return err
	}
	if err := server.CloseWithError(0, "complete"); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

func (rt *externalV2ListenRuntime) receiveBulkPacketBlock(streamCtx context.Context, completeCtx context.Context, accepted externalV2AcceptedClaim, path externalV2DirectPacketPath, sink BlockReceiveSink, blockCfg externalV2BlockReceiveConfig, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter, manager *transport.Manager, abortErrCh <-chan error) error {
	auth, err := externalV2BulkPacketAuthForToken(rt.session.token, accepted.peerDERP, rt.session.derp.PublicKey())
	if err != nil {
		return err
	}
	bytesReceived, stats, err := receiveExternalV2BulkBlockPackets(streamCtx, sink, blockCfg, externalV2BulkPacketPathFromRaw(path), auth, metrics)
	metrics.SetDirectStats(stats)
	if err != nil {
		return externalV2PreferPeerAbort(completeCtx, abortErrCh, err)
	}
	if err := rt.sendComplete(completeCtx, accepted.peerDERP, bytesReceived); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(manager)
	return nil
}

func (rt *externalV2OfferReceiveRuntime) receiveQUICBlock(ctx context.Context, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, transferMode string, sink BlockReceiveSink, blockCfg externalV2BlockReceiveConfig, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	if externalV2UsesBulkPacketTransfer(transferMode) {
		if ok, err := rt.receiveBulkPacketBlock(ctx, tr, policy, rawDirectBudget, sink, blockCfg, metrics, pathEmitter); ok || err != nil {
			return err
		}
	}
	endpoint, streams, rawPath, err := rt.acceptReceiveStreams(tr, externalV2StreamCount(policy), managerConnections, rawDirectBudget)
	if err != nil {
		return err
	}
	defer rawPath.Close()
	bytesReceived, err := receiveExternalV2BlockStreams(ctx, sink, blockCfg, streams, metrics)
	if err != nil {
		return rt.receiveStreamError(endpoint, err)
	}
	if err := rt.finishReceiveStream(ctx, endpoint, bytesReceived); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

func (rt *externalV2OfferReceiveRuntime) receiveBulkPacketBlock(ctx context.Context, tr externalV2ListenTransport, policy ParallelPolicy, rawDirectBudget time.Duration, sink BlockReceiveSink, blockCfg externalV2BlockReceiveConfig, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) (bool, error) {
	streamCount := externalV2StreamCount(policy)
	rawPath, err := negotiateExternalV2DirectPacketPath(tr.ctx, rt.derp, rt.listenerDERP, tr.manager, rt.dm, rt.auth, rt.cfg.Emitter, streamCount, 0, rawDirectBudget, tr.relayOnly)
	if err != nil {
		return true, err
	}
	defer rawPath.Close()
	if !rawPath.raw {
		return false, nil
	}
	emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=bulk-packets")
	auth, err := externalV2BulkPacketAuthForToken(rt.tok, rt.listenerDERP, rt.derp.PublicKey())
	if err != nil {
		return true, err
	}
	bytesReceived, stats, err := receiveExternalV2BulkBlockPackets(ctx, sink, blockCfg, externalV2BulkPacketPathFromRaw(rawPath), auth, metrics)
	metrics.SetDirectStats(stats)
	if err != nil {
		return true, err
	}
	if err := rt.sendComplete(ctx, bytesReceived); err != nil {
		return true, err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return true, nil
}

func writeExternalV2BlockFrame(w io.Writer, offset int64, data []byte) error {
	if offset < 0 {
		return fmt.Errorf("negative block offset %d", offset)
	}
	frame := make([]byte, externalV2BlockFrameSize+len(data))
	binary.BigEndian.PutUint64(frame[:8], uint64(offset))
	binary.BigEndian.PutUint32(frame[8:externalV2BlockFrameSize], uint32(len(data)))
	copy(frame[externalV2BlockFrameSize:], data)
	return writeExternalV2BlockFrameBytes(w, frame)
}

func writeExternalV2BlockChunkFrame(w io.Writer, chunk externalV2BlockChunk) error {
	if len(chunk.frame) > 0 {
		return writeExternalV2BlockFrameBytes(w, chunk.frame)
	}
	return writeExternalV2BlockFrame(w, chunk.offset, chunk.data)
}

func writeExternalV2BlockFrameBytes(w io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n > 0 {
			frame = frame[n:]
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

func readExternalV2BlockFrame(r io.Reader, maxChunkSize int) (externalV2BlockChunk, error) {
	var header [externalV2BlockFrameSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return externalV2BlockChunk{}, io.EOF
		}
		return externalV2BlockChunk{}, err
	}
	n := int(binary.BigEndian.Uint32(header[8:]))
	if n < 0 || n > maxChunkSize {
		return externalV2BlockChunk{}, io.ErrUnexpectedEOF
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return externalV2BlockChunk{}, err
	}
	return externalV2BlockChunk{
		offset: int64(binary.BigEndian.Uint64(header[:8])),
		data:   data,
	}, nil
}

func copyExternalV2SendBlockStreams(ctx context.Context, src *BlockSource, streams []io.WriteCloser, metrics *externalTransferMetrics) error {
	if !validExternalV2BlockSource(src) {
		return errors.New("invalid block source")
	}
	if len(streams) == 0 {
		return errors.New("no block streams")
	}
	defer closeExternalV2BlockWriters(streams)

	chunkSize := externalV2BlockChunkSize(src.ChunkSize)
	jobs := make(chan externalV2BlockChunk, len(streams)*2)
	errCh := make(chan error, len(streams)+1)
	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(w io.Writer) {
			defer wg.Done()
			for chunk := range jobs {
				if err := writeExternalV2BlockChunkFrame(w, chunk); err != nil {
					errCh <- err
					return
				}
				if metrics != nil {
					metrics.RecordDirectPathSend(int64(len(chunk.data)), time.Now())
				}
			}
		}(stream)
	}

	readErr := sendExternalV2BlockChunks(ctx, src, chunkSize, jobs, errCh)
	close(jobs)
	wg.Wait()
	if readErr != nil {
		return readErr
	}
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func sendExternalV2BlockChunks(ctx context.Context, src *BlockSource, chunkSize int, jobs chan<- externalV2BlockChunk, errCh <-chan error) error {
	for offset := int64(0); offset < src.PayloadSize; {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, read, want, err := readExternalV2BlockChunk(src, chunkSize, offset)
		if read > 0 {
			select {
			case jobs <- chunk:
			case writeErr := <-errCh:
				return writeErr
			case <-ctx.Done():
				return ctx.Err()
			}
			offset += int64(read)
		}
		if err := externalV2BlockReadError(err, read, want, offset, src.PayloadSize); err != nil {
			return err
		}
	}
	return nil
}

func readExternalV2BlockChunk(src *BlockSource, chunkSize int, offset int64) (externalV2BlockChunk, int, int, error) {
	n := min(chunkSize, int(src.PayloadSize-offset))
	frame := make([]byte, externalV2BlockFrameSize+n)
	data := frame[externalV2BlockFrameSize:]
	read, err := src.Payload.ReadAt(data, offset)
	if read <= 0 {
		return externalV2BlockChunk{}, read, n, err
	}
	frame = frame[:externalV2BlockFrameSize+read]
	data = data[:read]
	binary.BigEndian.PutUint64(frame[:8], uint64(offset))
	binary.BigEndian.PutUint32(frame[8:externalV2BlockFrameSize], uint32(read))
	return externalV2BlockChunk{offset: offset, data: data, frame: frame}, read, n, err
}

func externalV2BlockReadError(err error, read int, want int, offset int64, payloadSize int64) error {
	if err == nil {
		if read != want {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	if errors.Is(err, io.EOF) && offset == payloadSize {
		return nil
	}
	return err
}

func receiveExternalV2BlockStreams(ctx context.Context, sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, streams []io.ReadCloser, metrics *externalTransferMetrics) (int64, error) {
	if sink == nil {
		return 0, errors.New("nil block sink")
	}
	if len(streams) == 0 {
		return 0, errors.New("no block streams")
	}
	chunkSize := externalV2BlockChunkSize(cfg.ChunkSize)
	tracker, err := newExternalV2BlockReceiveTracker(cfg.PayloadSize, chunkSize)
	if err != nil {
		return 0, err
	}

	receiveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	closeReaders := externalV2BlockReaderCloser(streams)
	receiver := externalV2BlockStreamReceiver{
		ctx:          receiveCtx,
		cancel:       cancel,
		closeReaders: closeReaders,
		sink:         sink,
		tracker:      tracker,
		chunkSize:    chunkSize,
		metrics:      metrics,
		errCh:        make(chan error, len(streams)+1),
	}
	done := receiver.start(streams)

	select {
	case <-done:
	case <-ctx.Done():
		closeReaders()
		<-done
		return cfg.HeaderBytes + tracker.receivedBytes(), ctx.Err()
	}
	if err := receiver.err(); err != nil {
		return cfg.HeaderBytes + tracker.receivedBytes(), err
	}
	if err := tracker.complete(); err != nil {
		return cfg.HeaderBytes + tracker.receivedBytes(), err
	}
	return cfg.HeaderBytes + tracker.receivedBytes(), nil
}

type externalV2BlockStreamReceiver struct {
	ctx          context.Context
	cancel       context.CancelFunc
	closeReaders func()
	sink         BlockReceiveSink
	tracker      *externalV2BlockReceiveTracker
	chunkSize    int
	metrics      *externalTransferMetrics
	errCh        chan error
}

func externalV2BlockReaderCloser(streams []io.ReadCloser) func() {
	closeOnce := sync.Once{}
	return func() {
		closeOnce.Do(func() {
			for _, stream := range streams {
				_ = stream.Close()
			}
		})
	}
}

func (r externalV2BlockStreamReceiver) start(streams []io.ReadCloser) <-chan struct{} {
	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(stream io.ReadCloser) {
			defer wg.Done()
			r.receive(stream)
		}(stream)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

func (r externalV2BlockStreamReceiver) receive(stream io.ReadCloser) {
	defer func() { _ = stream.Close() }()
	for {
		if err := r.ctx.Err(); err != nil {
			return
		}
		if err := r.receiveNext(stream); errors.Is(err, io.EOF) {
			return
		} else if err != nil {
			r.fail(err)
			return
		}
	}
}

func (r externalV2BlockStreamReceiver) receiveNext(stream io.Reader) error {
	chunk, err := readExternalV2BlockFrame(stream, r.chunkSize)
	if err != nil {
		return err
	}
	return r.tracker.writeChunk(r.sink, chunk, r.metrics)
}

func (r externalV2BlockStreamReceiver) fail(err error) {
	select {
	case r.errCh <- err:
	default:
	}
	r.cancel()
	r.closeReaders()
}

func (r externalV2BlockStreamReceiver) err() error {
	select {
	case err := <-r.errCh:
		return err
	default:
		return nil
	}
}

type externalV2BlockReceiveTracker struct {
	mu          sync.Mutex
	payloadSize int64
	chunkSize   int
	seen        []bool
	received    int64
}

func newExternalV2BlockReceiveTracker(payloadSize int64, chunkSize int) (*externalV2BlockReceiveTracker, error) {
	if payloadSize < 0 {
		return nil, fmt.Errorf("negative block payload size %d", payloadSize)
	}
	if chunkSize <= 0 {
		return nil, errors.New("block chunk size must be positive")
	}
	chunks := int((payloadSize + int64(chunkSize) - 1) / int64(chunkSize))
	return &externalV2BlockReceiveTracker{
		payloadSize: payloadSize,
		chunkSize:   chunkSize,
		seen:        make([]bool, chunks),
	}, nil
}

func (t *externalV2BlockReceiveTracker) writeChunk(sink BlockReceiveSink, chunk externalV2BlockChunk, metrics *externalTransferMetrics) error {
	if err := t.mark(chunk.offset, len(chunk.data)); err != nil {
		return err
	}
	n, err := sink.WriteAt(chunk.data, chunk.offset)
	if n > 0 && metrics != nil {
		metrics.RecordDirectPathReceive(int64(n), time.Now())
	}
	if err != nil {
		return err
	}
	if n != len(chunk.data) {
		return io.ErrShortWrite
	}
	return nil
}

func (t *externalV2BlockReceiveTracker) mark(offset int64, n int) error {
	if offset < 0 {
		return fmt.Errorf("negative block offset %d", offset)
	}
	if n <= 0 {
		return errors.New("empty block frame")
	}
	if offset%int64(t.chunkSize) != 0 {
		return fmt.Errorf("misaligned block offset %d", offset)
	}
	if offset+int64(n) > t.payloadSize {
		return fmt.Errorf("block offset %d length %d exceeds payload size %d", offset, n, t.payloadSize)
	}
	idx := int(offset / int64(t.chunkSize))
	if idx < 0 || idx >= len(t.seen) {
		return fmt.Errorf("block offset %d outside payload size %d", offset, t.payloadSize)
	}
	want := min(t.chunkSize, int(t.payloadSize-offset))
	if n != want {
		return fmt.Errorf("block offset %d length %d, want %d", offset, n, want)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen[idx] {
		return fmt.Errorf("duplicate block offset %d", offset)
	}
	t.seen[idx] = true
	t.received += int64(n)
	return nil
}

func (t *externalV2BlockReceiveTracker) complete() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.received != t.payloadSize {
		return fmt.Errorf("incomplete block transfer: received %d of %d", t.received, t.payloadSize)
	}
	for idx, seen := range t.seen {
		if !seen {
			return fmt.Errorf("missing block offset %d", idx*t.chunkSize)
		}
	}
	return nil
}

func (t *externalV2BlockReceiveTracker) receivedBytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.received
}

type countingBlockReceiveSink struct {
	sink              BlockReceiveSink
	headerBytes       int64
	payloadBytes      atomic.Int64
	firstByteUnixNano atomic.Int64
}

func newCountingBlockReceiveSink(sink BlockReceiveSink, headerBytes int64) *countingBlockReceiveSink {
	if headerBytes < 0 {
		headerBytes = 0
	}
	return &countingBlockReceiveSink{sink: sink, headerBytes: headerBytes}
}

func (s *countingBlockReceiveSink) WriteAt(p []byte, off int64) (int, error) {
	n, err := s.sink.WriteAt(p, off)
	if n > 0 {
		s.payloadBytes.Add(int64(n))
		s.firstByteUnixNano.CompareAndSwap(0, time.Now().UnixNano())
	}
	return n, err
}

func (s *countingBlockReceiveSink) Close() error {
	return s.sink.Close()
}

func (s *countingBlockReceiveSink) Count() int64 {
	if s == nil {
		return 0
	}
	return s.headerBytes + s.payloadBytes.Load()
}

func (s *countingBlockReceiveSink) FirstByteAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	n := s.firstByteUnixNano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func closeExternalV2BlockWriters(writers []io.WriteCloser) {
	for _, writer := range writers {
		_ = writer.Close()
	}
}
