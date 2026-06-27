// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxFrameBytes = 1 << 20

var ErrFrameTooLarge = errors.New("derpssh frame too large")

func WriteFrame(w io.Writer, msg Message) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(raw) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func ReadFrame(r io.Reader) (Message, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxFrameBytes {
		return Message{}, ErrFrameTooLarge
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}
