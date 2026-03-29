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
