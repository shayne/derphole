package wg

import (
	"context"
)

type MemoryTransport struct {
	in  chan []byte
	out chan []byte
}

func NewMemoryTransportPair() (*MemoryTransport, *MemoryTransport) {
	aIn := make(chan []byte, 16)
	bIn := make(chan []byte, 16)
	return &MemoryTransport{in: aIn, out: bIn}, &MemoryTransport{in: bIn, out: aIn}
}

func (m *MemoryTransport) Send(payload []byte) error {
	m.out <- append([]byte(nil), payload...)
	return nil
}

func (m *MemoryTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-m.in:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
