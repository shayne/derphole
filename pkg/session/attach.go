package session

import (
	"context"
	"io"
)

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

type nopReadCloser struct {
	io.Reader
}

func (nopReadCloser) Close() error { return nil }

func openSendSource(ctx context.Context, cfg SendConfig) (io.ReadCloser, error) {
	if cfg.StdioIn != nil {
		if src, ok := cfg.StdioIn.(io.ReadCloser); ok {
			return src, nil
		}
		return nopReadCloser{Reader: cfg.StdioIn}, nil
	}
	return nopReadCloser{Reader: io.LimitReader(nilReader{}, 0)}, nil
}

func openListenSink(ctx context.Context, cfg ListenConfig) (io.WriteCloser, error) {
	if cfg.StdioOut != nil {
		return nopWriteCloser{Writer: cfg.StdioOut}, nil
	}
	return nopWriteCloser{Writer: io.Discard}, nil
}

type nilReader struct{}

func (nilReader) Read(_ []byte) (int, error) { return 0, io.EOF }
