// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package session

import (
	"bytes"
	"testing"
)

func TestExternalV2BulkPacketFlattenMessage(t *testing.T) {
	if _, err := externalV2BulkPacketFlattenMessage(nil); err == nil {
		t.Fatal("empty batch message did not fail")
	}
	single := []byte("single")
	got, err := externalV2BulkPacketFlattenMessage([][]byte{single})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || &got[0] != &single[0] {
		t.Fatal("single-buffer batch message was copied")
	}
	got, err = externalV2BulkPacketFlattenMessage([][]byte{[]byte("split-"), []byte("message")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("split-message")) {
		t.Fatalf("flattened message = %q", got)
	}
}
