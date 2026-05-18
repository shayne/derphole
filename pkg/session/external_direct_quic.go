// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
)

var errExternalDirectQUICNotImplemented = errors.New("direct QUIC transport is not implemented")

func sendExternalViaDirectQUIC(ctx context.Context, cfg SendConfig) error {
	return errExternalDirectQUICNotImplemented
}

func listenExternalViaDirectQUIC(ctx context.Context, cfg ListenConfig) (string, error) {
	return "", errExternalDirectQUICNotImplemented
}
