// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package model

type ChatMessage struct {
	ParticipantID string
	DisplayName   string
	Text          string
	Seq           uint64
}

type ChatHistory struct {
	limit    int
	nextSeq  uint64
	messages []ChatMessage
}

func NewChatHistory(limit int) *ChatHistory {
	return &ChatHistory{limit: limit}
}

func (h *ChatHistory) Append(msg ChatMessage) {
	h.nextSeq++
	msg.Seq = h.nextSeq
	if h.limit <= 0 {
		h.messages = nil
		return
	}
	h.messages = append(h.messages, msg)
	if len(h.messages) > h.limit {
		h.messages = h.messages[len(h.messages)-h.limit:]
	}
}

func (h *ChatHistory) Messages() []ChatMessage {
	return append([]ChatMessage(nil), h.messages...)
}
