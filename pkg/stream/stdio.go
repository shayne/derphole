// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream

import "io"

type StdioAttachment struct {
	r io.Reader
	w io.Writer
}

func NewStdioAttachment(r io.Reader, w io.Writer) *StdioAttachment {
	return &StdioAttachment{r: r, w: w}
}

func (a *StdioAttachment) Read(p []byte) (int, error) {
	return a.r.Read(p)
}

func (a *StdioAttachment) Write(p []byte) (int, error) {
	return a.w.Write(p)
}

func (a *StdioAttachment) WriteTo(w io.Writer) (int64, error) {
	if writerTo, ok := a.r.(io.WriterTo); ok {
		return writerTo.WriteTo(w)
	}
	return io.Copy(w, a.r)
}

func (a *StdioAttachment) ReadFrom(r io.Reader) (int64, error) {
	if readerFrom, ok := a.w.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(a.w, r)
}
