// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package model

import "testing"

func TestReplayBufferKeepsBoundedTail(t *testing.T) {
	buf := NewReplayBuffer(5)
	buf.Append([]byte("abc"))
	buf.Append([]byte("def"))
	got := string(buf.Bytes())
	if got != "bcdef" {
		t.Fatalf("Bytes() = %q, want bcdef", got)
	}
	if buf.NextSeq() != 3 {
		t.Fatalf("NextSeq() = %d, want 3", buf.NextSeq())
	}
}
