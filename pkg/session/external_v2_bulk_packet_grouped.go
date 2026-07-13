// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	externalV2BulkPacketGroupedData             byte = 10
	externalV2BulkPacketGroupedFragments             = 45
	externalV2BulkPacketGroupedCiphertextBytes       = externalV2BulkPacketMaxSize - externalV2BulkPacketHeaderSize
	externalV2BulkPacketGroupedPlaintextBytes        = externalV2BulkPacketGroupedFragments*externalV2BulkPacketGroupedCiphertextBytes - 16
	externalV2BulkPacketGroupedGroupsPerSlab         = 16
	externalV2BulkPacketGroupedMinimumFileBytes      = int64(64 << 20)
)

func (s *externalV2BulkPacketSender) sendGroupedInitialPacketsBatched() error {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	slabPool := s.slabPool
	if slabPool == nil {
		slabPool = &sync.Pool{New: func() any { return newExternalV2BulkPacketSlab() }}
	}
	jobs := make(chan externalV2BulkPacketPrepareJob, externalV2BulkPacketMaximumWorkers)
	prepared := make(chan externalV2BulkPacketPreparedSlab, externalV2BulkPacketPreparedBatches)
	startExternalV2BulkPacketGroupedPrepareJobs(ctx, s.groupCount, jobs)
	startExternalV2BulkPacketGroupedPrepareWorkers(ctx, s, jobs, prepared, slabPool)
	laneQueues, writerErrs, writersDone := startExternalV2BulkPacketLaneWriters(ctx, cancel, s)
	return s.consumeExternalV2BulkPacketPreparedSlabs(ctx, cancel, prepared, slabPool, laneQueues, writerErrs, writersDone)
}

func startExternalV2BulkPacketGroupedPrepareJobs(ctx context.Context, groupCount uint32, jobs chan<- externalV2BulkPacketPrepareJob) {
	go func() {
		defer close(jobs)
		sequence := 0
		for start := uint32(0); start < groupCount; start += externalV2BulkPacketGroupedGroupsPerSlab {
			job := externalV2BulkPacketPrepareJob{
				sequence: sequence,
				start:    start,
				count:    min(uint32(externalV2BulkPacketGroupedGroupsPerSlab), groupCount-start),
			}
			select {
			case jobs <- job:
				sequence++
			case <-ctx.Done():
				return
			}
		}
	}()
}

func startExternalV2BulkPacketGroupedPrepareWorkers(
	ctx context.Context,
	s *externalV2BulkPacketSender,
	jobs <-chan externalV2BulkPacketPrepareJob,
	prepared chan<- externalV2BulkPacketPreparedSlab,
	slabPool externalV2BulkPacketSlabPool,
) {
	workerCount := externalV2BulkPacketWorkerCount(runtime.GOMAXPROCS(0))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				slab := slabPool.Get().(*externalV2BulkPacketSlab)
				result := s.prepareGroupedPacketSlab(ctx, job, slab)
				select {
				case prepared <- result:
					externalV2BulkPacketAtomicMaxUint32(&s.batchCryptoQueuePeak, uint32(len(prepared)))
					if result.err != nil {
						return
					}
				case <-ctx.Done():
					slabPool.Put(slab)
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(prepared)
	}()
}

func (s *externalV2BulkPacketSender) prepareGroupedPacketSlab(
	ctx context.Context,
	job externalV2BulkPacketPrepareJob,
	slab *externalV2BulkPacketSlab,
) externalV2BulkPacketPreparedSlab {
	result := externalV2BulkPacketPreparedSlab{
		sequence: job.sequence,
		byLane:   make([][]externalV2BulkPacketBatchMessage, s.laneCount),
		slab:     slab,
	}
	packetSlot := 0
	for localGroup := uint32(0); localGroup < job.count; localGroup++ {
		if err := ctx.Err(); err != nil {
			result.err = err
			return result
		}
		groupID := job.start + localGroup
		plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, s.src.PayloadSize)
		plainOffset := int(localGroup) * externalV2BulkPacketGroupedPlaintextBytes
		plaintext := slab.input[plainOffset : plainOffset+plainBytes]
		n, readErr := s.src.Payload.ReadAt(plaintext, plainStart)
		if err := externalV2BlockReadError(readErr, n, plainBytes, plainStart+int64(n), s.src.PayloadSize); err != nil {
			result.err = err
			return result
		}
		cipherOffset := int(localGroup) * (externalV2BulkPacketGroupedPlaintextBytes + s.auth.grouped.Overhead())
		ciphertext, err := sealExternalV2BulkPacketGroup(
			s.auth.grouped,
			slab.ciphertext[cipherOffset:cipherOffset:cipherOffset+plainBytes+s.auth.grouped.Overhead()],
			s.runID,
			groupID,
			s.groupCount,
			plaintext[:n],
		)
		if err != nil {
			result.err = err
			return result
		}
		firstFragment, fragments := externalV2BulkPacketGroupedFragmentRange(groupID, s.src.PayloadSize, s.auth.grouped.Overhead())
		for localFragment := uint32(0); localFragment < fragments; localFragment++ {
			fragmentIndex := firstFragment + localFragment
			cipherStart, cipherEnd := externalV2BulkPacketGroupedFragmentCiphertextRange(fragmentIndex, len(ciphertext))
			packetStart := packetSlot * externalV2BulkPacketMaxSize
			packet, err := encodeExternalV2BulkPacketGroupedFragment(
				slab.sealed[packetStart:packetStart:packetStart+externalV2BulkPacketMaxSize],
				s.runID,
				fragmentIndex,
				s.totalPackets,
				ciphertext[cipherStart:cipherEnd],
			)
			if err != nil {
				result.err = err
				return result
			}
			lane := externalV2BulkPacketPrimaryLane(fragmentIndex, s.laneCount)
			result.byLane[lane] = append(result.byLane[lane], externalV2BulkPacketBatchMessage{
				Buffers:      [][]byte{packet},
				Addr:         s.path.Addrs[lane],
				PayloadBytes: externalV2BulkPacketGroupedFragmentPlaintextBytes(fragmentIndex, len(ciphertext), s.auth.grouped.Overhead()),
			})
			packetSlot++
		}
	}
	return result
}

func externalV2BulkPacketGroupedFragmentPlaintextBytes(fragmentIndex uint32, ciphertextBytes int, overhead int) int {
	start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(fragmentIndex, ciphertextBytes)
	bytes := end - start
	if end == ciphertextBytes {
		bytes -= overhead
	}
	return max(0, bytes)
}

func (s *externalV2BulkPacketSender) prepareGroupedRepairPacketSlab(
	ctx context.Context,
	repairs []externalV2BulkPacketRepair,
	slab *externalV2BulkPacketSlab,
) ([][]externalV2BulkPacketBatchMessage, error) {
	if len(repairs) > externalV2BulkPacketSlabPackets {
		return nil, fmt.Errorf("bulk packet grouped repair batch contains %d fragments, maximum %d", len(repairs), externalV2BulkPacketSlabPackets)
	}
	byLane := make([][]externalV2BulkPacketBatchMessage, s.laneCount)
	groups := make(map[uint32][]byte)
	for slot, repair := range repairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if repair.index >= s.totalPackets || repair.lane < 0 || repair.lane >= s.laneCount {
			return nil, fmt.Errorf("bulk packet grouped repair fragment %d lane %d is invalid", repair.index, repair.lane)
		}
		groupID := repair.index / externalV2BulkPacketGroupedFragments
		ciphertext := groups[groupID]
		if ciphertext == nil {
			var err error
			ciphertext, err = s.sealGroupedSourceGroup(groupID)
			if err != nil {
				return nil, err
			}
			groups[groupID] = ciphertext
		}
		cipherStart, cipherEnd := externalV2BulkPacketGroupedFragmentCiphertextRange(repair.index, len(ciphertext))
		packetStart := slot * externalV2BulkPacketMaxSize
		packet, err := encodeExternalV2BulkPacketGroupedFragment(
			slab.sealed[packetStart:packetStart:packetStart+externalV2BulkPacketMaxSize],
			s.runID,
			repair.index,
			s.totalPackets,
			ciphertext[cipherStart:cipherEnd],
		)
		if err != nil {
			return nil, err
		}
		byLane[repair.lane] = append(byLane[repair.lane], externalV2BulkPacketBatchMessage{
			Buffers:      [][]byte{packet},
			Addr:         s.path.Addrs[repair.lane],
			PayloadBytes: externalV2BulkPacketGroupedFragmentPlaintextBytes(repair.index, len(ciphertext), s.auth.grouped.Overhead()),
		})
	}
	return byLane, nil
}

func (s *externalV2BulkPacketSender) sealGroupedSourceGroup(groupID uint32) ([]byte, error) {
	plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, s.src.PayloadSize)
	if plainBytes == 0 {
		return nil, fmt.Errorf("bulk packet grouped repair group %d is outside source", groupID)
	}
	plaintext := make([]byte, plainBytes)
	n, readErr := s.src.Payload.ReadAt(plaintext, plainStart)
	if err := externalV2BlockReadError(readErr, n, plainBytes, plainStart+int64(n), s.src.PayloadSize); err != nil {
		return nil, err
	}
	return sealExternalV2BulkPacketGroup(s.auth.grouped, nil, s.runID, groupID, s.groupCount, plaintext[:n])
}

const externalV2BulkPacketGroupedAssemblerShards = 64

type externalV2BulkPacketGroupAssembler struct {
	payloadSize     int64
	aead            cipher.AEAD
	arrivals        *externalV2BulkPacketArrivalTracker
	direct          []byte
	groupCount      uint32
	fragmentCount   uint32
	runID           atomic.Uint64
	activeGroups    atomic.Int64
	maxActiveGroups int64
	groupPool       sync.Pool
	shards          [externalV2BulkPacketGroupedAssemblerShards]externalV2BulkPacketGroupAssemblerShard
}

type externalV2BulkPacketGroupAssemblerShard struct {
	mu     sync.Mutex
	groups map[uint32]*externalV2BulkPacketCiphertextGroup
}

type externalV2BulkPacketCiphertextGroup struct {
	ciphertext    []byte
	seen          [externalV2BulkPacketGroupedFragments]bool
	received      uint32
	runID         uint64
	groupID       uint32
	plainStart    int64
	plainBytes    int
	fragmentStart uint32
	fragmentCount uint32
}

func newExternalV2BulkPacketGroupAssembler(
	payloadSize int64,
	aead cipher.AEAD,
	arrivals *externalV2BulkPacketArrivalTracker,
	direct []byte,
) *externalV2BulkPacketGroupAssembler {
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(payloadSize, aead.Overhead())
	receiveWindow := int64(externalV2BulkPacketBufferedReceiveWindow)
	if int64(len(direct)) == payloadSize {
		receiveWindow = externalV2BulkPacketDirectReceiveWindow
	}
	assembler := &externalV2BulkPacketGroupAssembler{
		payloadSize: payloadSize, aead: aead, arrivals: arrivals, direct: direct,
		groupCount: groupCount, fragmentCount: fragmentCount,
		maxActiveGroups: max(1, (receiveWindow+externalV2BulkPacketGroupedPlaintextBytes-1)/externalV2BulkPacketGroupedPlaintextBytes),
	}
	assembler.groupPool.New = func() any {
		return &externalV2BulkPacketCiphertextGroup{
			ciphertext: make([]byte, externalV2BulkPacketGroupedPlaintextBytes+aead.Overhead()),
		}
	}
	return assembler
}

func (a *externalV2BulkPacketGroupAssembler) add(packet []byte) (externalV2BulkPacketReceiveResult, bool, error) {
	group, _, err := a.addEncrypted(packet)
	if err != nil || group == nil {
		return externalV2BulkPacketReceiveResult{}, false, err
	}
	result, err := a.openGroup(group)
	return result, err == nil, err
}

func (a *externalV2BulkPacketGroupAssembler) addEncrypted(packet []byte) (*externalV2BulkPacketCiphertextGroup, bool, error) {
	header, fragment, ok := parseExternalV2BulkPacketGroupedFragment(packet)
	if !ok || header.total != a.fragmentCount || header.index >= a.fragmentCount {
		return nil, false, nil
	}
	groupID := header.index / externalV2BulkPacketGroupedFragments
	plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, a.payloadSize)
	firstFragment, fragmentCount := externalV2BulkPacketGroupedFragmentRange(groupID, a.payloadSize, a.aead.Overhead())
	if plainBytes == 0 || header.index < firstFragment || header.index >= firstFragment+fragmentCount {
		return nil, false, nil
	}
	ciphertextBytes := plainBytes + a.aead.Overhead()
	cipherStart, cipherEnd := externalV2BulkPacketGroupedFragmentCiphertextRange(header.index, ciphertextBytes)
	if len(fragment) != cipherEnd-cipherStart {
		return nil, false, nil
	}
	if !a.acceptRunID(header.runID) {
		return nil, false, nil
	}

	shard := &a.shards[groupID%externalV2BulkPacketGroupedAssemblerShards]
	shard.mu.Lock()
	if a.arrivals.contains(header.index) {
		shard.mu.Unlock()
		return nil, false, nil
	}
	if shard.groups == nil {
		shard.groups = make(map[uint32]*externalV2BulkPacketCiphertextGroup)
	}
	group := shard.groups[groupID]
	if group == nil {
		if a.activeGroups.Add(1) > a.maxActiveGroups {
			a.activeGroups.Add(-1)
			shard.mu.Unlock()
			return nil, false, nil
		}
		group = a.groupPool.Get().(*externalV2BulkPacketCiphertextGroup)
		group.ciphertext = group.ciphertext[:ciphertextBytes]
		shard.groups[groupID] = group
	}
	localFragment := header.index - firstFragment
	if group.seen[localFragment] {
		shard.mu.Unlock()
		return nil, false, nil
	}
	copy(group.ciphertext[cipherStart:cipherEnd], fragment)
	group.seen[localFragment] = true
	group.received++
	if !a.arrivals.markGroupedFragment(header) {
		group.seen[localFragment] = false
		group.received--
		shard.mu.Unlock()
		return nil, false, nil
	}
	if group.received < fragmentCount {
		shard.mu.Unlock()
		return nil, true, nil
	}
	delete(shard.groups, groupID)
	a.activeGroups.Add(-1)
	group.runID = header.runID
	group.groupID = groupID
	group.plainStart = plainStart
	group.plainBytes = plainBytes
	group.fragmentStart = firstFragment
	group.fragmentCount = fragmentCount
	shard.mu.Unlock()
	return group, true, nil
}

func (a *externalV2BulkPacketGroupAssembler) openGroup(group *externalV2BulkPacketCiphertextGroup) (externalV2BulkPacketReceiveResult, error) {
	if group == nil {
		return externalV2BulkPacketReceiveResult{}, errors.New("bulk packet grouped record is nil")
	}
	defer a.releaseGroup(group)

	direct := len(a.direct) == int(a.payloadSize)
	var destination []byte
	if direct {
		destination = a.direct[group.plainStart : group.plainStart : group.plainStart+int64(group.plainBytes)]
	} else {
		destination = make([]byte, 0, group.plainBytes)
	}
	plaintext, authenticated := openExternalV2BulkPacketGroup(
		a.aead, destination, group.runID, group.groupID, a.groupCount, group.plainBytes, group.ciphertext,
	)
	if !authenticated {
		return externalV2BulkPacketReceiveResult{}, fmt.Errorf("bulk packet grouped record %d failed authentication", group.groupID)
	}
	a.arrivals.addAuthenticatedPayload(group.plainBytes)
	a.arrivals.observeActivity(time.Now())
	return externalV2BulkPacketReceiveResult{
		header: externalV2BulkPacketHeader{
			kind: externalV2BulkPacketGroupedData, runID: group.runID, index: group.groupID,
			total: a.groupCount, length: uint16(group.plainBytes),
		},
		data: plaintext, direct: direct, grouped: true,
		fragmentStart: group.fragmentStart, fragmentCount: group.fragmentCount,
	}, nil
}

func (a *externalV2BulkPacketGroupAssembler) releaseGroup(group *externalV2BulkPacketCiphertextGroup) {
	if a == nil || group == nil {
		return
	}
	ciphertext := group.ciphertext[:cap(group.ciphertext)]
	*group = externalV2BulkPacketCiphertextGroup{ciphertext: ciphertext}
	a.groupPool.Put(group)
}

func (a *externalV2BulkPacketGroupAssembler) acceptRunID(candidate uint64) bool {
	if candidate == 0 {
		return false
	}
	current := a.runID.Load()
	if current == candidate {
		return true
	}
	return current == 0 && a.runID.CompareAndSwap(0, candidate)
}

func (a *externalV2BulkPacketGroupAssembler) setExpectedRunID(expected uint64) bool {
	if a == nil || expected == 0 {
		return false
	}
	current := a.runID.Load()
	return current == expected || current == 0 && a.runID.CompareAndSwap(0, expected)
}

func externalV2BulkPacketGroupedLayout(payloadSize int64, overhead int) (uint32, uint32) {
	if payloadSize <= 0 || overhead <= 0 || overhead >= externalV2BulkPacketGroupedCiphertextBytes {
		return 0, 0
	}
	groups := uint32((payloadSize + externalV2BulkPacketGroupedPlaintextBytes - 1) / externalV2BulkPacketGroupedPlaintextBytes)
	lastPlaintext := int(payloadSize - int64(groups-1)*externalV2BulkPacketGroupedPlaintextBytes)
	lastFragments := uint32((lastPlaintext + overhead + externalV2BulkPacketGroupedCiphertextBytes - 1) / externalV2BulkPacketGroupedCiphertextBytes)
	return groups, (groups-1)*externalV2BulkPacketGroupedFragments + lastFragments
}

func externalV2BulkPacketGroupedPlaintextRange(groupID uint32, payloadSize int64) (int64, int) {
	start := int64(groupID) * externalV2BulkPacketGroupedPlaintextBytes
	if start < 0 || start >= payloadSize {
		return start, 0
	}
	return start, int(min(int64(externalV2BulkPacketGroupedPlaintextBytes), payloadSize-start))
}

func externalV2BulkPacketGroupedFragmentRange(groupID uint32, payloadSize int64, overhead int) (uint32, uint32) {
	_, plaintextBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, payloadSize)
	if plaintextBytes == 0 || overhead <= 0 {
		return groupID * externalV2BulkPacketGroupedFragments, 0
	}
	fragments := uint32((plaintextBytes + overhead + externalV2BulkPacketGroupedCiphertextBytes - 1) / externalV2BulkPacketGroupedCiphertextBytes)
	return groupID * externalV2BulkPacketGroupedFragments, fragments
}

func externalV2BulkPacketGroupedFragmentCiphertextRange(fragmentIndex uint32, ciphertextBytes int) (int, int) {
	localIndex := int(fragmentIndex % externalV2BulkPacketGroupedFragments)
	start := localIndex * externalV2BulkPacketGroupedCiphertextBytes
	return start, min(ciphertextBytes, start+externalV2BulkPacketGroupedCiphertextBytes)
}

func sealExternalV2BulkPacketGroup(
	aead cipher.AEAD,
	dst []byte,
	runID uint64,
	groupID uint32,
	groupCount uint32,
	plaintext []byte,
) ([]byte, error) {
	if aead == nil {
		return nil, errors.New("nil bulk packet group AEAD")
	}
	if len(plaintext) == 0 || len(plaintext) > externalV2BulkPacketGroupedPlaintextBytes || len(plaintext) > int(^uint16(0)) {
		return nil, fmt.Errorf("bulk packet group plaintext length %d is invalid", len(plaintext))
	}
	header := externalV2BulkPacketHeader{
		kind: externalV2BulkPacketGroupedData, runID: runID, index: groupID, total: groupCount, length: uint16(len(plaintext)),
	}
	aad := externalV2BulkPacketGroupedAAD(header)
	nonce, err := externalV2BulkPacketGroupedNonce(aead, header)
	if err != nil {
		return nil, err
	}
	return aead.Seal(dst, nonce, plaintext, aad[:]), nil
}

func openExternalV2BulkPacketGroup(
	aead cipher.AEAD,
	dst []byte,
	runID uint64,
	groupID uint32,
	groupCount uint32,
	plaintextBytes int,
	ciphertext []byte,
) ([]byte, bool) {
	if aead == nil || plaintextBytes <= 0 || plaintextBytes > externalV2BulkPacketGroupedPlaintextBytes ||
		len(ciphertext) != plaintextBytes+aead.Overhead() {
		return nil, false
	}
	header := externalV2BulkPacketHeader{
		kind: externalV2BulkPacketGroupedData, runID: runID, index: groupID, total: groupCount, length: uint16(plaintextBytes),
	}
	aad := externalV2BulkPacketGroupedAAD(header)
	nonce, err := externalV2BulkPacketGroupedNonce(aead, header)
	if err != nil {
		return nil, false
	}
	opened, err := aead.Open(dst, nonce, ciphertext, aad[:])
	return opened, err == nil && len(opened) == plaintextBytes
}

func externalV2BulkPacketGroupedAAD(header externalV2BulkPacketHeader) [externalV2BulkPacketHeaderSize]byte {
	var aad [externalV2BulkPacketHeaderSize]byte
	fillExternalV2BulkPacketHeader(aad[:], header)
	return aad
}

func externalV2BulkPacketGroupedNonce(aead cipher.AEAD, header externalV2BulkPacketHeader) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if nonceSize < 12 || nonceSize > externalV2BulkPacketMaximumNonceSize {
		return nil, fmt.Errorf("unsupported bulk packet group AEAD nonce size %d", nonceSize)
	}
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	fillExternalV2BulkPacketNonce(nonce[:nonceSize], header)
	return nonce[:nonceSize], nil
}

func encodeExternalV2BulkPacketGroupedFragment(
	dst []byte,
	runID uint64,
	fragmentIndex uint32,
	fragmentCount uint32,
	ciphertext []byte,
) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext) > externalV2BulkPacketGroupedCiphertextBytes {
		return nil, fmt.Errorf("bulk packet grouped fragment length %d is invalid", len(ciphertext))
	}
	want := externalV2BulkPacketHeaderSize + len(ciphertext)
	if cap(dst) < want {
		dst = make([]byte, want)
	} else {
		dst = dst[:want]
		clear(dst[:externalV2BulkPacketHeaderSize])
	}
	fillExternalV2BulkPacketHeader(dst, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketGroupedData, runID: runID, index: fragmentIndex, total: fragmentCount, length: uint16(len(ciphertext)),
	})
	copy(dst[externalV2BulkPacketHeaderSize:], ciphertext)
	return dst, nil
}

func parseExternalV2BulkPacketGroupedFragment(packet []byte) (externalV2BulkPacketHeader, []byte, bool) {
	header, ok := parseExternalV2BulkPacketHeader(packet)
	if !ok || header.kind != externalV2BulkPacketGroupedData || header.length == 0 ||
		int(header.length) > externalV2BulkPacketGroupedCiphertextBytes ||
		len(packet) != externalV2BulkPacketHeaderSize+int(header.length) {
		return externalV2BulkPacketHeader{}, nil, false
	}
	return header, packet[externalV2BulkPacketHeaderSize:], true
}
