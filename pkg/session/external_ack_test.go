package session

import (
	"encoding/json"
	"testing"
)

func testPeerAckPayload(t *testing.T, bytesReceived int64) []byte {
	t.Helper()

	payload, err := json.Marshal(envelope{Type: envelopeAck, Ack: newPeerAck(bytesReceived)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
