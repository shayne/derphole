// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package candidate

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

const MaxCount = 32
const MaxLength = 128

var ErrInvalid = errors.New("invalid candidate")

type policy struct {
	allowLoopback bool
}

type Option func(*policy)

func AllowLoopback() Option {
	return func(p *policy) {
		p.allowLoopback = true
	}
}

func ValidateClaimStrings(values []string, opts ...Option) error {
	if len(values) > MaxCount {
		return ErrInvalid
	}
	p := newPolicy(opts...)
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ap, ok := parsePeerAddrPort(value, p)
		if !ok {
			return ErrInvalid
		}
		canonical := ap.String()
		if _, exists := seen[canonical]; exists {
			return ErrInvalid
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func ParsePeerAddrs(values []string, opts ...Option) []net.Addr {
	p := newPolicy(opts...)
	return parseAddrs(values, func(value string) (netip.AddrPort, bool) {
		return parsePeerAddrPort(value, p)
	})
}

func ParseLocalAddrs(values []string) []net.Addr {
	return parseAddrs(values, parseLocalAddrPort)
}

func StringifyLocalAddrs(addrs []net.Addr) []string {
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		ap, ok := addrPortFromNetAddr(addr)
		if !ok || !validLocalAdvertiseAddrPort(ap) {
			continue
		}
		canonical := ap.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
		if len(out) == MaxCount {
			break
		}
	}
	return out
}

func parseAddrs(values []string, parse func(string) (netip.AddrPort, bool)) []net.Addr {
	out := make([]net.Addr, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ap, ok := parse(value)
		if !ok {
			continue
		}
		canonical := ap.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, net.UDPAddrFromAddrPort(ap))
		if len(out) == MaxCount {
			break
		}
	}
	return out
}

func parsePeerAddrPort(value string, p policy) (netip.AddrPort, bool) {
	return parseAddrPort(value, func(ap netip.AddrPort) bool {
		return validPeerAddrPort(ap, p)
	})
}

func parseLocalAddrPort(value string) (netip.AddrPort, bool) {
	return parseAddrPort(value, validLocalAddrPort)
}

func parseAddrPort(value string, valid func(netip.AddrPort) bool) (netip.AddrPort, bool) {
	if len(value) == 0 || len(value) > MaxLength {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil || ap.String() != value || !valid(ap) {
		return netip.AddrPort{}, false
	}
	return ap, true
}

func validPeerAddrPort(ap netip.AddrPort, p policy) bool {
	addr := ap.Addr()
	if addr.IsLoopback() && !p.allowLoopback {
		return false
	}
	return ap.Port() != 0 &&
		addr.IsValid() &&
		addr.Zone() == "" &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast()
}

func validLocalAddrPort(ap netip.AddrPort) bool {
	addr := ap.Addr()
	return ap.Port() != 0 &&
		addr.IsValid() &&
		addr.Zone() == "" &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast()
}

func validLocalAdvertiseAddrPort(ap netip.AddrPort) bool {
	return validLocalAddrPort(ap) && !ap.Addr().IsLoopback()
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return addrPortFromIPPort(a.IP, a.Port, a.Zone)
	case *net.TCPAddr:
		return addrPortFromIPPort(a.IP, a.Port, a.Zone)
	default:
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return netip.AddrPort{}, false
		}
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ip, uint16(parsedPort)), true
	}
}

func addrPortFromIPPort(ip net.IP, port int, zone string) (netip.AddrPort, bool) {
	if ip == nil || port <= 0 || port > 65535 {
		return netip.AddrPort{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	addr = addr.Unmap()
	if zone != "" {
		addr = addr.WithZone(zone)
	}
	return netip.AddrPortFrom(addr, uint16(port)), true
}

func newPolicy(opts ...Option) policy {
	var p policy
	for _, opt := range opts {
		if opt != nil {
			opt(&p)
		}
	}
	return p
}
