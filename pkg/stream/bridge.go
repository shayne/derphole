package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

func Bridge(ctx context.Context, a, b net.Conn) error {
	if err := ctx.Err(); err != nil {
		_ = a.Close()
		_ = b.Close()
		return err
	}

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	errCh := make(chan error, 2)
	copyConn := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		closeBoth()
		errCh <- err
	}

	go copyConn(a, b)
	go copyConn(b, a)

	var retErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil && !isExpectedCloseError(err) && retErr == nil {
				retErr = err
			}
		case <-ctx.Done():
			closeBoth()
			retErr = ctx.Err()
		}
	}

	closeBoth()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return retErr
}

func isExpectedCloseError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}
