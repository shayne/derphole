// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"net/netip"
)

func externalNativeTCPTokenBootstrapAddr() (netip.AddrPort, bool) {
	if len(externalNativeTCPBindOverrideAddrs()) == 0 {
		return netip.AddrPort{}, false
	}
	for _, addr := range externalNativeTCPEnvAddrs(externalNativeTCPAdvertiseAddrEnv) {
		tcpAddr, _, ok := externalNativeTCPAddr(addr)
		if !ok || tcpAddr.Port == 0 {
			continue
		}
		ip, ok := netip.AddrFromSlice(tcpAddr.IP)
		if !ok {
			continue
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(tcpAddr.Port)), true
	}
	return netip.AddrPort{}, false
}
