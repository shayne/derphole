// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wg

import (
	"crypto/sha256"
	"net/netip"
)

func DeriveAddresses(sessionID [16]byte) (netip.Prefix, netip.Addr, netip.Addr) {
	sum := sha256.Sum256(sessionID[:])

	var prefixBytes [16]byte
	prefixBytes[0] = 0xfd
	copy(prefixBytes[1:8], sum[:7])

	var listenerBytes [16]byte
	copy(listenerBytes[:8], prefixBytes[:8])
	listenerBytes[15] = 1

	var senderBytes [16]byte
	copy(senderBytes[:8], prefixBytes[:8])
	senderBytes[15] = 2

	prefix := netip.PrefixFrom(netip.AddrFrom16(prefixBytes), 64)
	return prefix, netip.AddrFrom16(listenerBytes), netip.AddrFrom16(senderBytes)
}
