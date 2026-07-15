// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dataplane

import (
	"context"
	"io"
	"time"
)

type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}

type Client interface {
	Open(context.Context) (Stream, error)
	Stats() Stats
	CloseWithError(uint64, string) error
}

type Server interface {
	Accept(context.Context) (Stream, error)
	Stats() Stats
	CloseWithError(uint64, string) error
}

type Stats struct {
	BytesSent            int64
	BytesReceived        int64
	TelemetryPresent     bool
	Connections          uint32
	Streams              uint32
	PacketsSent          uint64
	PacketsReceived      uint64
	PacketsLost          uint64
	WireBytesSent        uint64
	RecoveryWireBytes    uint64
	SmoothedRTT          time.Duration
	HandshakeDuration    time.Duration
	FirstByteDuration    time.Duration
	StreamBytesSent      uint64
	StreamBytesReceived  uint64
	Version              string
	RawSocketBackend     string
	NativeSendBackend    string
	NativeReceiveBackend string
	NativeGSO            string
	NativeReceiveBatch   string
	HandshakeMS          int64
	FirstByteMS          int64
	OpenedAt             time.Time
	HandshakeAt          time.Time
	FirstByteAt          time.Time
	ClosedAt             time.Time
	CloseReason          string
}
