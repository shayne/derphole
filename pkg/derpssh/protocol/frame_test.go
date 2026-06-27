// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msg := Message{
		Type: MessageHello,
		Hello: &Hello{
			ProtocolVersion: ProtocolVersion,
			ParticipantID:   "guest-1",
			DisplayName:     "Alex",
			Role:            RolePending,
		},
	}
	if err := WriteFrame(&buf, msg); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if got.Type != MessageHello || got.Hello == nil || got.Hello.DisplayName != "Alex" {
		t.Fatalf("ReadFrame() = %#v, want hello Alex", got)
	}
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("ReadFrame() error = nil, want oversized frame error")
	}
}
