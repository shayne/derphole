//lint:file-ignore U1000 Retired public QUIC handoff runtime pending deletion after the WG cutover settles.
package session

import (
	"context"
	"errors"
	"io"
	"sync"
)

var errExternalHandoffRuntimeClosed = errors.New("external handoff runtime closed")

type externalHandoffCarrierRuntime struct {
	run func(io.ReadWriteCloser) error

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	errMu    sync.Mutex
	firstErr error
}

func newExternalHandoffCarrierRuntime(run func(io.ReadWriteCloser) error) *externalHandoffCarrierRuntime {
	return &externalHandoffCarrierRuntime{run: run}
}

func (r *externalHandoffCarrierRuntime) Add(carrier io.ReadWriteCloser) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		if carrier != nil {
			_ = carrier.Close()
		}
		return errExternalHandoffRuntimeClosed
	}
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.wg.Done()
		if err := r.run(carrier); err != nil {
			r.errMu.Lock()
			if r.firstErr == nil {
				r.firstErr = err
			}
			r.errMu.Unlock()
		}
	}()
	return nil
}

func (r *externalHandoffCarrierRuntime) Close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
}

func (r *externalHandoffCarrierRuntime) Wait() error {
	r.wg.Wait()
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.firstErr
}

func (r *externalHandoffCarrierRuntime) CloseAndWait() error {
	r.Close()
	return r.Wait()
}

func newExternalHandoffSendRuntime(ctx context.Context, spool *externalHandoffSpool) *externalHandoffCarrierRuntime {
	return newExternalHandoffCarrierRuntime(func(carrier io.ReadWriteCloser) error {
		return sendExternalHandoffCarrier(ctx, carrier, spool, nil)
	})
}

func newExternalHandoffReceiveRuntime(ctx context.Context, rx *externalHandoffReceiver) *externalHandoffCarrierRuntime {
	return newExternalHandoffCarrierRuntime(func(carrier io.ReadWriteCloser) error {
		return receiveExternalHandoffCarrier(ctx, carrier, rx, externalCopyBufferSize)
	})
}
