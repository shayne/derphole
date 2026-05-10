// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
