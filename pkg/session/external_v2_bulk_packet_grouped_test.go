// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
	"golang.org/x/time/rate"
	"tailscale.com/types/key"
)

type recordingReaderAt struct {
	io.ReaderAt
	reads []recordedReaderAtRead
}

type recordedReaderAtRead struct {
	offset int64
	length int
}

func useExternalV2BulkPacketCandidate(t *testing.T, candidate string) {
	t.Helper()
	previous := externalV2BulkPacketBenchmarkCandidate
	externalV2BulkPacketBenchmarkCandidate = candidate
	t.Cleanup(func() { externalV2BulkPacketBenchmarkCandidate = previous })
}

func (r *recordingReaderAt) ReadAt(payload []byte, offset int64) (int, error) {
	r.reads = append(r.reads, recordedReaderAtRead{offset: offset, length: len(payload)})
	return r.ReaderAt.ReadAt(payload, offset)
}

func TestExternalV2BulkPacketGroupedPrepareSlabReadsFullRangeOnce(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "coalesced-gso3")

	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: 0, count: 16},
		newExternalV2BulkPacketSlab(),
	)
	if result.err != nil || len(reader.reads) != 1 || reader.reads[0].offset != 0 || reader.reads[0].length != 989024 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketCandidateControlsGroupedSourceReads(t *testing.T) {
	for _, test := range []struct {
		candidate string
		wantReads int
	}{
		{candidate: "baseline-gso3", wantReads: 16},
		{candidate: "coalesced-gso3", wantReads: 1},
		{candidate: "connected-gso3", wantReads: 16},
		{candidate: "combined-gso3", wantReads: 1},
	} {
		t.Run(test.candidate, func(t *testing.T) {
			useExternalV2BulkPacketCandidate(t, test.candidate)

			payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
			reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
			sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
			result := sender.prepareGroupedPacketSlab(
				context.Background(),
				externalV2BulkPacketPrepareJob{start: 0, count: 16},
				newExternalV2BulkPacketSlab(),
			)
			if result.err != nil || len(reader.reads) != test.wantReads {
				t.Fatalf("candidate %q result=%v reads=%+v, want %d reads", test.candidate, result.err, reader.reads, test.wantReads)
			}
		})
	}
}

func TestExternalV2BulkPacketCandidateInvalidValueStopsGroupedSourceReads(t *testing.T) {
	previous := externalV2BulkPacketBenchmarkCandidate
	externalV2BulkPacketBenchmarkCandidate = "combined-gso5"
	t.Cleanup(func() { externalV2BulkPacketBenchmarkCandidate = previous })

	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: 0, count: 16},
		newExternalV2BulkPacketSlab(),
	)
	if result.err == nil || len(reader.reads) != 0 {
		t.Fatalf("invalid candidate result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabReadsPartialFinalRangeOnce(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "coalesced-gso3")

	const finalBytes = 731
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*15+finalBytes)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: 0, count: 16},
		newExternalV2BulkPacketSlab(),
	)
	wantLength := externalV2BulkPacketGroupedPlaintextBytes*15 + finalBytes
	if result.err != nil || len(reader.reads) != 1 || reader.reads[0].offset != 0 || reader.reads[0].length != wantLength {
		t.Fatalf("result=%v reads=%+v wantLength=%d", result.err, reader.reads, wantLength)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabReadsNonzeroRangeOnce(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "coalesced-gso3")

	const startGroup = 4
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*20)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: startGroup, count: 16},
		newExternalV2BulkPacketSlab(),
	)
	wantOffset := int64(startGroup * externalV2BulkPacketGroupedPlaintextBytes)
	if result.err != nil || len(reader.reads) != 1 || reader.reads[0].offset != wantOffset || reader.reads[0].length != 989024 {
		t.Fatalf("result=%v reads=%+v wantOffset=%d", result.err, reader.reads, wantOffset)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabRejectsShortRead(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "coalesced-gso3")

	payloadSize := int64(externalV2BulkPacketGroupedPlaintextBytes * 16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(make([]byte, payloadSize-1))}
	sender := newGroupedSlabTestSender(t, reader, payloadSize)
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: 0, count: 16},
		newExternalV2BulkPacketSlab(),
	)
	if !errors.Is(result.err, io.EOF) || len(reader.reads) != 1 || reader.reads[0].offset != 0 || reader.reads[0].length != 989024 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabSkipsReadWhenContextCanceled(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := sender.prepareGroupedPacketSlab(
		ctx,
		externalV2BulkPacketPrepareJob{start: 0, count: 16},
		newExternalV2BulkPacketSlab(),
	)
	if !errors.Is(result.err, context.Canceled) || len(reader.reads) != 0 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabRejectsZeroGroupCountBeforeRead(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: 0, count: 0},
		newExternalV2BulkPacketSlab(),
	)
	if result.err == nil || len(reader.reads) != 0 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabRejectsOutOfRangeBeforeRead(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*16)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	result := sender.prepareGroupedPacketSlab(
		context.Background(),
		externalV2BulkPacketPrepareJob{start: 16, count: 1},
		newExternalV2BulkPacketSlab(),
	)
	if result.err == nil || len(reader.reads) != 0 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabRejectsOversizedRangeBeforeRead(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*(externalV2BulkPacketGroupedGroupsPerSlab+1))
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	var result externalV2BulkPacketPreparedSlab
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("prepare panicked: %v", recovered)
			}
		}()
		result = sender.prepareGroupedPacketSlab(
			context.Background(),
			externalV2BulkPacketPrepareJob{start: 0, count: externalV2BulkPacketGroupedGroupsPerSlab + 1},
			newExternalV2BulkPacketSlab(),
		)
	}()
	if result.err == nil || len(reader.reads) != 0 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabRejectsOneByteSeventeenthGroupBeforeRead(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*externalV2BulkPacketGroupedGroupsPerSlab+1)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	var result externalV2BulkPacketPreparedSlab
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("prepare panicked: %v", recovered)
			}
		}()
		result = sender.prepareGroupedPacketSlab(
			context.Background(),
			externalV2BulkPacketPrepareJob{start: 0, count: externalV2BulkPacketGroupedGroupsPerSlab + 1},
			newExternalV2BulkPacketSlab(),
		)
	}()
	if result.err == nil || len(reader.reads) != 0 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func TestExternalV2BulkPacketGroupedSlabRangeRejectsWrappedGroupRange(t *testing.T) {
	payloadSize := (int64(^uint32(0)) + 2) * int64(externalV2BulkPacketGroupedPlaintextBytes)
	start, length := externalV2BulkPacketGroupedSlabRange(^uint32(0), 2, payloadSize)
	if length != 0 {
		t.Fatalf("range start=%d length=%d, want empty", start, length)
	}
}

func TestExternalV2BulkPacketGroupedPrepareSlabRejectsWrappedGroupRangeBeforeRead(t *testing.T) {
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes)
	reader := &recordingReaderAt{ReaderAt: bytes.NewReader(payload)}
	sender := newGroupedSlabTestSender(t, reader, int64(len(payload)))
	var result externalV2BulkPacketPreparedSlab
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("prepare panicked: %v", recovered)
			}
		}()
		result = sender.prepareGroupedPacketSlab(
			context.Background(),
			externalV2BulkPacketPrepareJob{start: ^uint32(0), count: 2},
			newExternalV2BulkPacketSlab(),
		)
	}()
	if result.err == nil || len(reader.reads) != 0 {
		t.Fatalf("result=%v reads=%+v", result.err, reader.reads)
	}
}

func newGroupedSlabTestSender(t *testing.T, reader io.ReaderAt, payloadSize int64) *externalV2BulkPacketSender {
	t.Helper()
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	groupCount, totalPackets := externalV2BulkPacketGroupedLayout(payloadSize, auth.grouped.Overhead())
	return &externalV2BulkPacketSender{
		src:          &BlockSource{Payload: reader, PayloadSize: payloadSize},
		path:         externalV2BulkPacketPath{Addrs: []net.Addr{&net.UDPAddr{}}},
		auth:         auth,
		runID:        1,
		totalPackets: totalPackets,
		groupCount:   groupCount,
		laneCount:    1,
	}
}

func TestExternalV2BulkPacketGroupedRecordRoundTrip(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*2+731)
	for index := range payload {
		payload[index] = byte((index*37 + 19) % 251)
	}
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	if groupCount != 3 || fragmentCount != 2*externalV2BulkPacketGroupedFragments+1 {
		t.Fatalf("layout groups=%d fragments=%d, want 3/%d", groupCount, fragmentCount, 2*externalV2BulkPacketGroupedFragments+1)
	}

	runID := uint64(0x0102030405060708)
	assembled := make([]byte, len(payload))
	for groupID := uint32(0); groupID < groupCount; groupID++ {
		start, plaintextBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, int64(len(payload)))
		ciphertext, err := sealExternalV2BulkPacketGroup(
			auth.grouped,
			nil,
			runID,
			groupID,
			groupCount,
			payload[start:start+int64(plaintextBytes)],
		)
		if err != nil {
			t.Fatal(err)
		}
		firstFragment, fragments := externalV2BulkPacketGroupedFragmentRange(groupID, int64(len(payload)), auth.grouped.Overhead())
		groupCiphertext := make([]byte, len(ciphertext))
		for reverse := int(fragments) - 1; reverse >= 0; reverse-- {
			fragmentIndex := firstFragment + uint32(reverse)
			cipherStart, cipherEnd := externalV2BulkPacketGroupedFragmentCiphertextRange(fragmentIndex, len(ciphertext))
			packet, err := encodeExternalV2BulkPacketGroupedFragment(
				nil,
				runID,
				fragmentIndex,
				fragmentCount,
				ciphertext[cipherStart:cipherEnd],
			)
			if err != nil {
				t.Fatal(err)
			}
			header, fragment, ok := parseExternalV2BulkPacketGroupedFragment(packet)
			if !ok || header.index != fragmentIndex || header.total != fragmentCount {
				t.Fatalf("fragment %d did not parse: header=%+v ok=%v", fragmentIndex, header, ok)
			}
			copy(groupCiphertext[cipherStart:cipherEnd], fragment)
		}
		opened, ok := openExternalV2BulkPacketGroup(
			auth.grouped,
			assembled[start:start:start+int64(plaintextBytes)],
			runID,
			groupID,
			groupCount,
			plaintextBytes,
			groupCiphertext,
		)
		if !ok || len(opened) != plaintextBytes {
			t.Fatalf("group %d did not authenticate", groupID)
		}
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatal("grouped record output differs from input")
	}
}

func TestExternalV2BulkPacketGroupedWireRequiresNegotiatedAuth(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	src := &BlockSource{
		Payload:     bytes.NewReader(make([]byte, externalV2BulkPacketGroupedMinimumFileBytes)),
		PayloadSize: externalV2BulkPacketGroupedMinimumFileBytes,
	}
	if !newExternalV2BulkPacketSender(context.Background(), src, externalV2BulkPacketPath{}, auth, nil).grouped {
		t.Fatal("negotiated grouped auth did not select grouped wire")
	}
	auth.grouped = nil
	if newExternalV2BulkPacketSender(context.Background(), src, externalV2BulkPacketPath{}, auth, nil).grouped {
		t.Fatal("missing grouped auth selected incompatible grouped wire")
	}
}

func TestExternalV2BulkPacketGroupedRecordRejectsTampering(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketGroupedPlaintextBytes)
	ciphertext, err := sealExternalV2BulkPacketGroup(auth.grouped, nil, 9, 1, 3, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)/2] ^= 0xff
	if _, ok := openExternalV2BulkPacketGroup(auth.grouped, make([]byte, 0, len(plaintext)), 9, 1, 3, len(plaintext), ciphertext); ok {
		t.Fatal("tampered grouped record authenticated")
	}
}

func TestExternalV2BulkPacketGroupedFragmentRejectsMalformedLength(t *testing.T) {
	packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 7, 2, 8, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	packet = append(packet, 0)
	if _, _, ok := parseExternalV2BulkPacketGroupedFragment(packet); ok {
		t.Fatal("fragment with trailing bytes parsed")
	}
}

func TestExternalV2BulkPacketGroupedBatchedSenderRoundTrip(t *testing.T) {
	const laneCount = 4
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes*2+731)
	for index := range payload {
		payload[index] = byte((index*41 + 5) % 251)
	}
	senders, receivers := listenExternalV2BulkPacketTestConns(t, laneCount)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(context.Background(), &BlockSource{
		Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)),
	}, externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receivers)}, auth, nil)
	sender.grouped = true
	sender.groupCount, sender.totalPackets = externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	sender.pacer = rate.NewLimiter(rate.Inf, externalV2BulkPacketPaceBurstBytes)
	captures := make([]*captureExternalV2BulkPacketBatchConn, laneCount)
	sender.batchConns = make([]externalV2BulkPacketBatchConn, laneCount)
	for lane := range laneCount {
		captures[lane] = &captureExternalV2BulkPacketBatchConn{}
		sender.batchConns[lane] = captures[lane]
	}

	if err := sender.sendInitialPacketsBatched(); err != nil {
		t.Fatal(err)
	}
	packets := make(map[uint32][]byte, sender.totalPackets)
	for lane, capture := range captures {
		for _, packet := range capture.packets {
			header, _, ok := parseExternalV2BulkPacketGroupedFragment(packet)
			if !ok {
				t.Fatalf("lane %d emitted a non-grouped packet", lane)
			}
			if externalV2BulkPacketPrimaryLane(header.index, laneCount) != lane {
				t.Fatalf("fragment %d used lane %d", header.index, lane)
			}
			packets[header.index] = packet
		}
	}
	if len(packets) != int(sender.totalPackets) {
		t.Fatalf("captured %d fragments, want %d", len(packets), sender.totalPackets)
	}
	assembled := make([]byte, len(payload))
	for groupID := uint32(0); groupID < sender.groupCount; groupID++ {
		plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, int64(len(payload)))
		first, count := externalV2BulkPacketGroupedFragmentRange(groupID, int64(len(payload)), auth.grouped.Overhead())
		ciphertext := make([]byte, plainBytes+auth.grouped.Overhead())
		for index := first; index < first+count; index++ {
			_, fragment, ok := parseExternalV2BulkPacketGroupedFragment(packets[index])
			if !ok {
				t.Fatalf("fragment %d did not parse", index)
			}
			start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
			copy(ciphertext[start:end], fragment)
		}
		if _, ok := openExternalV2BulkPacketGroup(
			auth.grouped, assembled[plainStart:plainStart:plainStart+int64(plainBytes)],
			sender.runID, groupID, sender.groupCount, plainBytes, ciphertext,
		); !ok {
			t.Fatalf("group %d did not authenticate", groupID)
		}
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatal("grouped sender payload differs")
	}
	if got := sender.primaryPayloadBytes.Load(); got != int64(len(payload)) {
		t.Fatalf("primary payload bytes = %d, want %d", got, len(payload))
	}

	for _, capture := range captures {
		capture.mu.Lock()
		capture.packets = nil
		capture.maxBatch = 0
		capture.mu.Unlock()
	}
	wantRepair := []uint32{0, 1, 46}
	sent, err := sender.repairMissing(wantRepair, make(map[uint32]time.Time), make(map[uint32]uint64))
	if err != nil {
		t.Fatal(err)
	}
	if !sent {
		t.Fatal("grouped repair sent no packets")
	}
	repaired := make(map[uint32][]byte, len(wantRepair))
	for _, capture := range captures {
		for _, packet := range capture.packets {
			header, _, ok := parseExternalV2BulkPacketGroupedFragment(packet)
			if !ok {
				t.Fatal("grouped repair did not parse")
			}
			repaired[header.index] = packet
		}
	}
	for _, index := range wantRepair {
		if !bytes.Equal(repaired[index], packets[index]) {
			t.Fatalf("repair fragment %d differs from primary", index)
		}
	}
}

func TestExternalV2BulkPacketGroupAssemblerAuthenticatesOutOfOrderFragments(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes+731)
	for index := range payload {
		payload[index] = byte((index*43 + 17) % 251)
	}
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	arrivals := newExternalV2BulkPacketArrivalTracker(fragmentCount)
	direct := make([]byte, len(payload))
	assembler := newExternalV2BulkPacketGroupAssembler(int64(len(payload)), auth.grouped, arrivals, direct)
	runID := uint64(73)
	for groupID := uint32(0); groupID < groupCount; groupID++ {
		plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, int64(len(payload)))
		ciphertext, err := sealExternalV2BulkPacketGroup(auth.grouped, nil, runID, groupID, groupCount, payload[plainStart:plainStart+int64(plainBytes)])
		if err != nil {
			t.Fatal(err)
		}
		first, count := externalV2BulkPacketGroupedFragmentRange(groupID, int64(len(payload)), auth.grouped.Overhead())
		completed := false
		for reverse := int(count) - 1; reverse >= 0; reverse-- {
			index := first + uint32(reverse)
			start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
			packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, runID, index, fragmentCount, ciphertext[start:end])
			if err != nil {
				t.Fatal(err)
			}
			result, ok, err := assembler.add(packet)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				completed = true
				if !result.grouped || result.fragmentStart != first || result.fragmentCount != count || int(result.header.length) != plainBytes {
					t.Fatalf("group result = %+v", result)
				}
			}
		}
		if !completed {
			t.Fatalf("group %d never completed", groupID)
		}
	}
	if !bytes.Equal(direct, payload) || arrivals.payloadBytes() != int64(len(payload)) {
		t.Fatalf("group assembler payload mismatch or credit=%d", arrivals.payloadBytes())
	}
	for index := uint32(0); index < fragmentCount; index++ {
		if !arrivals.contains(index) {
			t.Fatalf("fragment %d was not marked present", index)
		}
	}
}

func TestExternalV2BulkPacketGroupAssemblerDefersAuthenticationAfterInlineAssembly(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x4d}, externalV2BulkPacketGroupedPlaintextBytes)
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	ciphertext, err := sealExternalV2BulkPacketGroup(auth.grouped, nil, 75, 0, groupCount, payload)
	if err != nil {
		t.Fatal(err)
	}
	arrivals := newExternalV2BulkPacketArrivalTracker(fragmentCount)
	direct := make([]byte, len(payload))
	assembler := newExternalV2BulkPacketGroupAssembler(int64(len(payload)), auth.grouped, arrivals, direct)
	var completed *externalV2BulkPacketCiphertextGroup
	for index := uint32(0); index < fragmentCount; index++ {
		start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
		packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 75, index, fragmentCount, ciphertext[start:end])
		if err != nil {
			t.Fatal(err)
		}
		var accepted bool
		completed, accepted, err = assembler.addEncrypted(packet)
		if err != nil {
			t.Fatal(err)
		}
		if !accepted {
			t.Fatalf("valid grouped fragment %d was not accepted", index)
		}
	}
	if completed == nil {
		t.Fatal("complete ciphertext group was not emitted")
	}
	if arrivals.payloadBytes() != 0 || bytes.Equal(direct, payload) || !arrivals.lastActivity().IsZero() {
		t.Fatal("inline assembly authenticated or committed payload")
	}
	result, err := assembler.openGroup(completed)
	if err != nil {
		t.Fatal(err)
	}
	if !result.grouped || !bytes.Equal(direct, payload) || arrivals.payloadBytes() != int64(len(payload)) {
		t.Fatal("deferred group authentication did not commit the payload")
	}
	if arrivals.lastActivity().IsZero() {
		t.Fatal("successful group authentication did not record receive-pipeline progress")
	}
}

func TestExternalV2BulkPacketGroupedReceivePipelineStaysMemoryBounded(t *testing.T) {
	activeGroups := (externalV2BulkPacketDirectReceiveWindow + externalV2BulkPacketGroupedPlaintextBytes - 1) /
		externalV2BulkPacketGroupedPlaintextBytes
	completedBytes := externalV2BulkPacketGroupedDecryptQueue *
		(externalV2BulkPacketGroupedPlaintextBytes + 16)
	if completedBytes < externalV2BulkPacketDirectReceiveWindow {
		t.Fatalf("grouped decrypt queue = %d bytes, want one direct receive window %d", completedBytes, externalV2BulkPacketDirectReceiveWindow)
	}
	residentBytes := (activeGroups + externalV2BulkPacketGroupedDecryptQueue) *
		(externalV2BulkPacketGroupedPlaintextBytes + 16)
	if residentBytes > 65<<20 {
		t.Fatalf("grouped receive pipeline = %d bytes, want at most 65 MiB", residentBytes)
	}
}

func TestExternalV2BulkPacketGroupAssemblerBypassesLegacyClaimsAndRejectsLateDuplicate(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x53}, externalV2BulkPacketGroupedPlaintextBytes)
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	ciphertext, err := sealExternalV2BulkPacketGroup(auth.grouped, nil, 77, 0, groupCount, payload)
	if err != nil {
		t.Fatal(err)
	}
	arrivals := newExternalV2BulkPacketArrivalTracker(fragmentCount)
	assembler := newExternalV2BulkPacketGroupAssembler(int64(len(payload)), auth.grouped, arrivals, make([]byte, len(payload)))
	var firstPacket []byte
	for index := uint32(0); index < fragmentCount; index++ {
		start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
		packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 77, index, fragmentCount, ciphertext[start:end])
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			firstPacket = bytes.Clone(packet)
		}
		if _, _, err := assembler.add(packet); err != nil {
			t.Fatal(err)
		}
	}
	for index := uint32(0); index < fragmentCount; index++ {
		if got := arrivals.claims[index].Load(); got != 0 {
			t.Fatalf("grouped fragment %d used legacy claim state %d", index, got)
		}
	}
	if _, complete, err := assembler.add(firstPacket); err != nil || complete {
		t.Fatalf("late duplicate complete=%t err=%v", complete, err)
	}
	if got := assembler.activeGroups.Load(); got != 0 {
		t.Fatalf("late duplicate resurrected %d active groups", got)
	}
}

func TestExternalV2BulkPacketGroupAssemblerReusesCiphertextBuffers(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x39}, externalV2BulkPacketGroupedPlaintextBytes*2)
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	assembler := newExternalV2BulkPacketGroupAssembler(
		int64(len(payload)), auth.grouped, newExternalV2BulkPacketArrivalTracker(fragmentCount), make([]byte, len(payload)),
	)
	allocations := 0
	assembler.groupPool.New = func() any {
		allocations++
		return &externalV2BulkPacketCiphertextGroup{
			ciphertext: make([]byte, externalV2BulkPacketGroupedPlaintextBytes+auth.grouped.Overhead()),
		}
	}
	for groupID := uint32(0); groupID < groupCount; groupID++ {
		plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, int64(len(payload)))
		ciphertext, err := sealExternalV2BulkPacketGroup(
			auth.grouped, nil, 79, groupID, groupCount, payload[plainStart:plainStart+int64(plainBytes)],
		)
		if err != nil {
			t.Fatal(err)
		}
		first, count := externalV2BulkPacketGroupedFragmentRange(groupID, int64(len(payload)), auth.grouped.Overhead())
		for index := first; index < first+count; index++ {
			start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
			packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 79, index, fragmentCount, ciphertext[start:end])
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := assembler.add(packet); err != nil {
				t.Fatal(err)
			}
		}
	}
	if allocations != 1 {
		t.Fatalf("group ciphertext allocations = %d, want one pooled buffer", allocations)
	}
}

func TestExternalV2BulkPacketGroupAssemblerBoundsIncompleteGroups(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payloadSize := int64(externalV2BulkPacketGroupedPlaintextBytes * 4)
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(payloadSize, auth.grouped.Overhead())
	arrivals := newExternalV2BulkPacketArrivalTracker(fragmentCount)
	assembler := newExternalV2BulkPacketGroupAssembler(payloadSize, auth.grouped, arrivals, make([]byte, payloadSize))
	assembler.maxActiveGroups = 2
	for groupID := uint32(0); groupID < 3; groupID++ {
		_, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, payloadSize)
		ciphertext, err := sealExternalV2BulkPacketGroup(
			auth.grouped, nil, 83, groupID, groupCount, make([]byte, plainBytes),
		)
		if err != nil {
			t.Fatal(err)
		}
		first, _ := externalV2BulkPacketGroupedFragmentRange(groupID, payloadSize, auth.grouped.Overhead())
		start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(first, len(ciphertext))
		packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 83, first, fragmentCount, ciphertext[start:end])
		if err != nil {
			t.Fatal(err)
		}
		if _, complete, err := assembler.add(packet); err != nil || complete {
			t.Fatalf("group %d add complete=%t err=%v", groupID, complete, err)
		}
		if groupID < 2 && !arrivals.contains(first) {
			t.Fatalf("admitted group %d fragment was not retained", groupID)
		}
		if groupID == 2 && arrivals.contains(first) {
			t.Fatal("fragment beyond incomplete-group bound was retained")
		}
	}
	if got := assembler.activeGroups.Load(); got != 2 {
		t.Fatalf("active groups = %d, want 2", got)
	}
}

func TestExternalV2BulkPacketGroupAssemblerPinsAuthenticatedProbeRunID(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payloadSize := int64(externalV2BulkPacketGroupedPlaintextBytes)
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(payloadSize, auth.grouped.Overhead())
	arrivals := newExternalV2BulkPacketArrivalTracker(fragmentCount)
	assembler := newExternalV2BulkPacketGroupAssembler(payloadSize, auth.grouped, arrivals, make([]byte, payloadSize))
	assembler.setExpectedRunID(91)
	ciphertext, err := sealExternalV2BulkPacketGroup(
		auth.grouped, nil, 92, 0, groupCount, make([]byte, payloadSize),
	)
	if err != nil {
		t.Fatal(err)
	}
	start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(0, len(ciphertext))
	packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 92, 0, fragmentCount, ciphertext[start:end])
	if err != nil {
		t.Fatal(err)
	}
	if _, complete, err := assembler.add(packet); err != nil || complete {
		t.Fatalf("spoofed run add complete=%t err=%v", complete, err)
	}
	if arrivals.contains(0) || assembler.activeGroups.Load() != 0 || assembler.runID.Load() != 91 {
		t.Fatalf("spoofed run mutated assembler: arrived=%t active=%d run=%d", arrivals.contains(0), assembler.activeGroups.Load(), assembler.runID.Load())
	}
}

func TestExternalV2BulkPacketGroupAssemblerRejectsTamperedGroup(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x61}, externalV2BulkPacketGroupedPlaintextBytes)
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	ciphertext, err := sealExternalV2BulkPacketGroup(auth.grouped, nil, 81, 0, groupCount, payload)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[17] ^= 0xff
	assembler := newExternalV2BulkPacketGroupAssembler(
		int64(len(payload)), auth.grouped, newExternalV2BulkPacketArrivalTracker(fragmentCount), make([]byte, len(payload)),
	)
	var finalErr error
	for index := uint32(0); index < fragmentCount; index++ {
		start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
		packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, 81, index, fragmentCount, ciphertext[start:end])
		if err != nil {
			t.Fatal(err)
		}
		_, _, finalErr = assembler.add(packet)
	}
	if finalErr == nil {
		t.Fatal("tampered grouped record was not rejected")
	}
}

func TestExternalV2BulkPacketGroupedBatchedReaderAuthenticatesIntoDirectBuffer(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, externalV2BulkPacketGroupedPlaintextBytes+731)
	for index := range payload {
		payload[index] = byte((index*47 + 3) % 251)
	}
	groupCount, fragmentCount := externalV2BulkPacketGroupedLayout(int64(len(payload)), auth.grouped.Overhead())
	packets := make([][]byte, 0, fragmentCount)
	const runID = uint64(87)
	for groupID := uint32(0); groupID < groupCount; groupID++ {
		plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(groupID, int64(len(payload)))
		ciphertext, err := sealExternalV2BulkPacketGroup(
			auth.grouped, nil, runID, groupID, groupCount, payload[plainStart:plainStart+int64(plainBytes)],
		)
		if err != nil {
			t.Fatal(err)
		}
		first, count := externalV2BulkPacketGroupedFragmentRange(groupID, int64(len(payload)), auth.grouped.Overhead())
		for reverse := int(count) - 1; reverse >= 0; reverse-- {
			index := first + uint32(reverse)
			start, end := externalV2BulkPacketGroupedFragmentCiphertextRange(index, len(ciphertext))
			packet, err := encodeExternalV2BulkPacketGroupedFragment(nil, runID, index, fragmentCount, ciphertext[start:end])
			if err != nil {
				t.Fatal(err)
			}
			packets = append(packets, packet)
		}
	}

	direct := make([]byte, len(payload))
	arrivals := newExternalV2BulkPacketArrivalTracker(fragmentCount)
	assembler := newExternalV2BulkPacketGroupAssembler(int64(len(payload)), auth.grouped, arrivals, direct)
	batchConn := &scriptedReceiveExternalV2BulkPacketBatchConn{packets: packets, delivered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	dataCh := make(chan externalV2BulkPacketReceiveBatch, 1)
	errCh := make(chan error, 1)
	done := startExternalV2BulkPacketBatchedDataReaders(
		ctx, []externalV2BulkPacketBatchConn{batchConn}, auth, dataCh, errCh, arrivals, direct, assembler,
	)
	receivedGroups := 0
	for receivedGroups < int(groupCount) {
		select {
		case batch := <-dataCh:
			receivedGroups += len(batch.results)
			batch.release()
		case err := <-errCh:
			t.Fatalf("grouped reader failed: %v", err)
		case <-time.After(time.Second):
			t.Fatalf("timed out after %d/%d grouped results", receivedGroups, groupCount)
		}
	}
	if !bytes.Equal(direct, payload) || arrivals.payloadBytes() != int64(len(payload)) {
		t.Fatalf("grouped reader output mismatch or credit=%d", arrivals.payloadBytes())
	}
	if arrivals.lastActivity().IsZero() {
		t.Fatal("grouped socket reader did not record accepted packet activity")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("grouped readers did not stop after cancellation")
	}
}

func TestExternalV2BulkPacketGroupedReceiverCommitsWithoutLegacyAssembler(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	const payloadSize = externalV2BulkPacketGroupedMinimumFileBytes
	sink := &groupedCaptureSink{}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(200, 0), nil, transfertrace.RoleReceive)
	receiver := newExternalV2BulkPacketReceiver(sink, externalV2BlockReceiveConfig{
		PayloadSize: payloadSize,
		HeaderBytes: 17,
	}, externalV2BulkPacketPath{}, auth, metrics)
	receiver.stopHello = func() {}
	if !receiver.grouped || receiver.groupAssembler == nil {
		t.Fatal("large authenticated receive did not select grouped mode")
	}
	if receiver.assembler != nil {
		t.Fatal("grouped receive retained the legacy packet assembler")
	}

	plainStart, plainBytes := externalV2BulkPacketGroupedPlaintextRange(0, payloadSize)
	firstFragment, fragmentCount := externalV2BulkPacketGroupedFragmentRange(0, payloadSize, auth.grouped.Overhead())
	data := bytes.Repeat([]byte{0x6d}, plainBytes)
	err = receiver.handleDataBatch(externalV2BulkPacketReceiveBatch{results: []externalV2BulkPacketReceiveResult{{
		header: externalV2BulkPacketHeader{
			kind: externalV2BulkPacketGroupedData, runID: 91, index: 0,
			total: receiver.groupCount, length: uint16(plainBytes),
		},
		data: data, grouped: true, fragmentStart: firstFragment, fragmentCount: fragmentCount,
	}}}, time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}
	received, stats, err := receiver.result(nil)
	if err != nil {
		t.Fatal(err)
	}
	if received != int64(17+plainBytes) || stats.BytesReceived != int64(plainBytes) {
		t.Fatalf("received=%d stats=%d, want header plus %d payload bytes", received, stats.BytesReceived, plainBytes)
	}
	if sink.offset != plainStart || !bytes.Equal(sink.data, data) {
		t.Fatal("grouped receiver did not write the authenticated group once at its file offset")
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.filePayloadEngine != transfertrace.FilePayloadEngineBulk || metrics.filePayloadBytesCommitted != int64(plainBytes) || metrics.filePayloadBytesBulk != int64(plainBytes) {
		t.Fatalf("grouped file payload engine=%q committed=%d bulk=%d", metrics.filePayloadEngine, metrics.filePayloadBytesCommitted, metrics.filePayloadBytesBulk)
	}
}

type groupedCaptureSink struct {
	mu     sync.Mutex
	offset int64
	data   []byte
}

func (s *groupedCaptureSink) WriteAt(payload []byte, offset int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offset = offset
	s.data = append(s.data[:0], payload...)
	return len(payload), nil
}

func (*groupedCaptureSink) Close() error { return nil }
