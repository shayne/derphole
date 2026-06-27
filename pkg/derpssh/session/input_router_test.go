// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"strings"
	"testing"
)

func TestInputRouterTreatsColonCommandsAsRawTerminalInput(t *testing.T) {
	sink := &recordingInputSink{}
	err := pumpRoutedInput(context.Background(), strings.NewReader(":chat hello there\n:write\n:kick done\nwhoami\n"), sink.sink())
	if err != nil {
		t.Fatalf("pumpRoutedInput() error = %v", err)
	}
	if got := strings.Join(sink.chat, "|"); got != "" {
		t.Fatalf("chat = %q, want empty", got)
	}
	if got := string(sink.data); got != ":chat hello there\n:write\n:kick done\nwhoami\n" {
		t.Fatalf("terminal data = %q, want raw colon text", got)
	}
}

type recordingInputSink struct {
	data []byte
	chat []string
}

func (s *recordingInputSink) sink() routedInputSink {
	return routedInputSink{
		sendData: func(_ context.Context, data []byte) error {
			s.data = append(s.data, data...)
			return nil
		},
		sendChat: func(_ context.Context, text string) error {
			s.chat = append(s.chat, text)
			return nil
		},
	}
}
