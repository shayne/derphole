package probe

import "encoding/binary"

const (
	blastStatsPayloadLen   = 40
	blastStatsPayloadLenV1 = 32
	blastStatsPayloadLenV0 = 24
)

type blastReceiverStats struct {
	ReceivedPayloadBytes  uint64
	ReceivedPackets       uint64
	MaxSeqPlusOne         uint64
	AckFloor              uint64
	CommittedPayloadBytes uint64
}

func marshalBlastStatsPayload(stats blastReceiverStats) []byte {
	payload := make([]byte, blastStatsPayloadLen)
	binary.BigEndian.PutUint64(payload[0:8], stats.ReceivedPayloadBytes)
	binary.BigEndian.PutUint64(payload[8:16], stats.ReceivedPackets)
	binary.BigEndian.PutUint64(payload[16:24], stats.MaxSeqPlusOne)
	binary.BigEndian.PutUint64(payload[24:32], stats.AckFloor)
	binary.BigEndian.PutUint64(payload[32:40], stats.CommittedPayloadBytes)
	return payload
}

func unmarshalBlastStatsPayload(payload []byte) (blastReceiverStats, bool) {
	if len(payload) < blastStatsPayloadLenV0 {
		return blastReceiverStats{}, false
	}
	stats := blastReceiverStats{
		ReceivedPayloadBytes: binary.BigEndian.Uint64(payload[0:8]),
		ReceivedPackets:      binary.BigEndian.Uint64(payload[8:16]),
		MaxSeqPlusOne:        binary.BigEndian.Uint64(payload[16:24]),
	}
	if len(payload) >= blastStatsPayloadLenV1 {
		stats.AckFloor = binary.BigEndian.Uint64(payload[24:32])
	}
	if len(payload) >= blastStatsPayloadLen {
		stats.CommittedPayloadBytes = binary.BigEndian.Uint64(payload[32:40])
	} else {
		stats.CommittedPayloadBytes = stats.ReceivedPayloadBytes
	}
	return stats, true
}
