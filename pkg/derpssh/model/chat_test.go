// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package model

import "testing"

func TestChatHistoryKeepsBoundedMessages(t *testing.T) {
	h := NewChatHistory(2)
	h.Append(ChatMessage{ParticipantID: "a", DisplayName: "A", Text: "one"})
	h.Append(ChatMessage{ParticipantID: "b", DisplayName: "B", Text: "two"})
	h.Append(ChatMessage{ParticipantID: "c", DisplayName: "C", Text: "three"})
	got := h.Messages()
	if len(got) != 2 || got[0].Text != "two" || got[1].Seq != 3 {
		t.Fatalf("Messages() = %#v, want last two with seq 2 and 3", got)
	}
}
