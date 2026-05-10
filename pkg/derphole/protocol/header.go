// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const magic = "DERPHOLE1"
const maxHeaderSize = 1 << 20

type Kind string

const (
	KindText         Kind = "text"
	KindFile         Kind = "file"
	KindDirectoryTar Kind = "directory_tar"
	KindSSHInvite    Kind = "ssh_invite"
	KindSSHAccept    Kind = "ssh_accept"
)

type Header struct {
	Version  uint8  `json:"version"`
	Kind     Kind   `json:"kind"`
	Name     string `json:"name,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Verify   string `json:"verify,omitempty"`
	Metadata []byte `json:"metadata,omitempty"`
}

func HeaderWireSize(h Header) (int64, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return 0, err
	}
	if len(raw) > maxHeaderSize {
		return 0, fmt.Errorf("header too large: %d bytes", len(raw))
	}
	return int64(len(magic) + 4 + len(raw)), nil
}

func WriteHeader(w io.Writer, h Header) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(raw) > maxHeaderSize {
		return fmt.Errorf("header too large: %d bytes", len(raw))
	}
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(raw))); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func ReadHeader(r *bufio.Reader) (Header, error) {
	var h Header

	magicBuf := make([]byte, len(magic))
	if _, err := io.ReadFull(r, magicBuf); err != nil {
		return h, err
	}
	if string(magicBuf) != magic {
		return h, errors.New("invalid derphole header magic")
	}

	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return h, err
	}
	if n > maxHeaderSize {
		return h, fmt.Errorf("header too large: %d bytes", n)
	}

	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return h, err
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, err
	}
	return h, nil
}
