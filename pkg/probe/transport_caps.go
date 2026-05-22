// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import "fmt"

type TransportCaps struct {
	Kind             string `json:"kind"`
	RequestedKind    string `json:"requested_kind,omitempty"`
	BatchSize        int    `json:"batch_size,omitempty"`
	RequestedSockBuf int    `json:"requested_sock_buf,omitempty"`
	ReadBufferBytes  int    `json:"read_buffer_bytes,omitempty"`
	WriteBufferBytes int    `json:"write_buffer_bytes,omitempty"`
	TXOffload        bool   `json:"tx_offload,omitempty"`
	RXOffload        bool   `json:"rx_offload,omitempty"`
	RXQOverflow      bool   `json:"rxq_overflow,omitempty"`
	Connected        bool   `json:"connected,omitempty"`
}

func (c TransportCaps) Summary() string {
	if c.Kind == "" {
		return "none"
	}
	return fmt.Sprintf(
		"%s(req=%s batch=%d read_buf=%d write_buf=%d tx_offload=%t rx_offload=%t rxq_overflow=%t connected=%t)",
		c.Kind,
		c.RequestedKind,
		c.BatchSize,
		c.ReadBufferBytes,
		c.WriteBufferBytes,
		c.TXOffload,
		c.RXOffload,
		c.RXQOverflow,
		c.Connected,
	)
}
