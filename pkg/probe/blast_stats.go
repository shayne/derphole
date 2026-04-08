package probe

import "encoding/binary"

const blastStatsPayloadLen = 24

type blastReceiverStats struct {
	ReceivedPayloadBytes uint64
	ReceivedPackets      uint64
	MaxSeqPlusOne        uint64
}

func marshalBlastStatsPayload(stats blastReceiverStats) []byte {
	payload := make([]byte, blastStatsPayloadLen)
	binary.BigEndian.PutUint64(payload[0:8], stats.ReceivedPayloadBytes)
	binary.BigEndian.PutUint64(payload[8:16], stats.ReceivedPackets)
	binary.BigEndian.PutUint64(payload[16:24], stats.MaxSeqPlusOne)
	return payload
}

func unmarshalBlastStatsPayload(payload []byte) (blastReceiverStats, bool) {
	if len(payload) < blastStatsPayloadLen {
		return blastReceiverStats{}, false
	}
	return blastReceiverStats{
		ReceivedPayloadBytes: binary.BigEndian.Uint64(payload[0:8]),
		ReceivedPackets:      binary.BigEndian.Uint64(payload[8:16]),
		MaxSeqPlusOne:        binary.BigEndian.Uint64(payload[16:24]),
	}, true
}
