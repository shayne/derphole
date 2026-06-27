// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package model

type ReplayBuffer struct {
	limit   int
	nextSeq uint64
	buf     []byte
}

func NewReplayBuffer(limit int) *ReplayBuffer {
	return &ReplayBuffer{limit: limit}
}

func (b *ReplayBuffer) Append(data []byte) {
	if len(data) == 0 {
		return
	}
	b.nextSeq++
	b.buf = append(b.buf, data...)
	if b.limit <= 0 {
		b.buf = nil
		return
	}
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
}

func (b *ReplayBuffer) Bytes() []byte {
	return append([]byte(nil), b.buf...)
}

func (b *ReplayBuffer) NextSeq() uint64 {
	return b.nextSeq + 1
}
