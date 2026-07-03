// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/shayne/derphole/pkg/session"
)

func pipeBlockSource(stdin io.Reader) *session.BlockSource {
	file, ok := stdin.(*os.File)
	if !ok || file == nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil || offset < 0 || offset > info.Size() {
		return nil
	}
	return &session.BlockSource{
		Payload:     io.NewSectionReader(file, offset, info.Size()-offset),
		PayloadSize: info.Size() - offset,
	}
}

func pipeBlockReceiver(stdout io.Writer) session.BlockReceiver {
	file, ok := stdout.(*os.File)
	if !ok || file == nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil || offset < 0 {
		return nil
	}
	return func(_ context.Context, req session.BlockReceiveRequest) (session.BlockReceiveSink, error) {
		if len(req.Header) != 0 {
			return nil, errors.New("raw pipe block transfer included a structured header")
		}
		return pipeBlockFileSink{file: file, baseOffset: offset, payloadSize: req.PayloadSize}, nil
	}
}

type pipeBlockFileSink struct {
	file        *os.File
	baseOffset  int64
	payloadSize int64
}

func (s pipeBlockFileSink) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative pipe block offset")
	}
	return s.file.WriteAt(p, s.baseOffset+off)
}

func (s pipeBlockFileSink) Close() error {
	if s.payloadSize < 0 {
		return nil
	}
	return s.file.Truncate(s.baseOffset + s.payloadSize)
}
