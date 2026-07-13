// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package session

func externalV2DirectTCPRetransmits(*externalV2DirectTCPPath) (int64, bool) {
	return 0, false
}
