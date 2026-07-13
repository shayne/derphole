// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package session

import "errors"

func externalV2BulkPacketFlattenMessage(buffers [][]byte) ([]byte, error) {
	if len(buffers) == 0 {
		return nil, errors.New("bulk packet batch message has no buffers")
	}
	if len(buffers) == 1 {
		return buffers[0], nil
	}
	total := 0
	for _, buffer := range buffers {
		total += len(buffer)
	}
	payload := make([]byte, 0, total)
	for _, buffer := range buffers {
		payload = append(payload, buffer...)
	}
	return payload, nil
}
