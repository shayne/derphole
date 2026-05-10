// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"os"
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

func sendConfigWithInferredExpectedBytes(cfg SendConfig) SendConfig {
	if cfg.StdioExpectedBytes > 0 {
		return cfg
	}
	expectedBytes, ok := regularFileRemainingBytes(cfg.StdioIn)
	if ok {
		cfg.StdioExpectedBytes = expectedBytes
	}
	return cfg
}

func regularFileRemainingBytes(r io.Reader) (int64, bool) {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return 0, false
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, false
	}
	remaining := info.Size() - pos
	if remaining < 0 {
		remaining = 0
	}
	return remaining, true
}

func openListenSink(ctx context.Context, cfg ListenConfig) (io.WriteCloser, error) {
	if cfg.StdioOut != nil {
		if dst, ok := cfg.StdioOut.(io.WriteCloser); ok {
			return dst, nil
		}
		return nopWriteCloser{Writer: cfg.StdioOut}, nil
	}
	return nopWriteCloser{Writer: io.Discard}, nil
}

type nilReader struct{}

func (nilReader) Read(_ []byte) (int, error) { return 0, io.EOF }
