package probe

import (
	"testing"
)

func TestMarshalBlastStatsPayloadRoundTripsReceiverProgress(t *testing.T) {
	want := blastReceiverStats{
		ReceivedPayloadBytes: 12345,
		ReceivedPackets:      67,
		MaxSeqPlusOne:        89,
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
