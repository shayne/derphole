package probe

import (
	"encoding/binary"
	"testing"
)

func TestMarshalBlastStatsPayloadRoundTripsReceiverProgress(t *testing.T) {
	want := blastReceiverStats{
		ReceivedPayloadBytes:  12345,
		ReceivedPackets:       67,
		MaxSeqPlusOne:         89,
		AckFloor:              55,
		CommittedPayloadBytes: 54321,
	}

	payload := marshalBlastStatsPayload(want)
	got, ok := unmarshalBlastStatsPayload(payload)
	if !ok {
		t.Fatal("unmarshalBlastStatsPayload() ok = false")
	}

	if got != want {
		t.Fatalf("unmarshalBlastStatsPayload() = %+v, want %+v", got, want)
	}
}

func TestUnmarshalBlastStatsPayloadBackfillsCommittedBytesForLegacyPayload(t *testing.T) {
	payload := make([]byte, blastStatsPayloadLenV1)
	binary.BigEndian.PutUint64(payload[0:8], 12345)
	binary.BigEndian.PutUint64(payload[8:16], 67)
	binary.BigEndian.PutUint64(payload[16:24], 89)
	binary.BigEndian.PutUint64(payload[24:32], 55)

	got, ok := unmarshalBlastStatsPayload(payload)
	if !ok {
		t.Fatal("unmarshalBlastStatsPayload() ok = false")
	}
	if got.CommittedPayloadBytes != got.ReceivedPayloadBytes {
		t.Fatalf("CommittedPayloadBytes = %d, want legacy fallback %d", got.CommittedPayloadBytes, got.ReceivedPayloadBytes)
	}
}
