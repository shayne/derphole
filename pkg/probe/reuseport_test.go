// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"strings"
	"testing"
)

func TestListenPacketReusePortCanBindTwice(t *testing.T) {
	first, err := ListenPacketReusePort(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "unsupported") {
			t.Skip(err)
		}
		t.Fatalf("ListenPacketReusePort() first bind error = %v", err)
	}
	defer first.Close()

	second, err := ListenPacketReusePort(context.Background(), "udp4", first.LocalAddr().String())
	if err != nil {
		t.Fatalf("ListenPacketReusePort() second bind error = %v", err)
	}
	defer second.Close()
}
