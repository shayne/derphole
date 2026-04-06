//lint:file-ignore U1000 Retired public QUIC bootstrap helpers pending deletion after the WG cutover settles.
package session

import (
	"context"
	"net"
	"net/netip"

	"github.com/shayne/derpcat/pkg/quicpath"
	"github.com/shayne/derpcat/pkg/token"
)

type externalNativeTCPBootstrapResult struct {
	conns []net.Conn
	err   error
}

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

func externalNativeTCPBootstrapNetAddr(tok token.Token) (net.Addr, bool) {
	addr, ok := tok.NativeTCPBootstrapAddr()
	if !ok {
		return nil, false
	}
	return &net.TCPAddr{
		IP:   append(net.IP(nil), addr.Addr().AsSlice()...),
		Port: int(addr.Port()),
		Zone: addr.Addr().Zone(),
	}, true
}

func startExternalNativeTCPBootstrapListener(ctx context.Context, tok token.Token, identity quicpath.SessionIdentity) (net.Listener, <-chan externalNativeTCPBootstrapResult, bool) {
	if _, ok := tok.NativeTCPBootstrapAddr(); !ok {
		return nil, nil, false
	}
	ln, ok := listenExternalNativeTCPOnAddrs(
		externalNativeTCPBindOverrideAddrs(),
		quicpath.DefaultTLSConfig(identity.Certificate, quicpath.ServerName),
	)
	if !ok {
		return nil, nil, false
	}
	resultCh := make(chan externalNativeTCPBootstrapResult, 1)
	go func() {
		conns, err := acceptExternalNativeTCPBootstrapConns(
			ctx,
			ln,
			externalNativeTCPAuth{
				Enabled:      true,
				SessionID:    tok.SessionID,
				BearerSecret: tok.BearerSecret,
				LocalPublic:  tok.QUICPublic,
			},
			externalNativeTCPConnCap(),
		)
		resultCh <- externalNativeTCPBootstrapResult{conns: conns, err: err}
	}()
	return ln, resultCh, true
}

func dialExternalNativeTCPBootstrap(ctx context.Context, tok token.Token, clientIdentity quicpath.SessionIdentity, connCount int) ([]net.Conn, error) {
	addr, ok := externalNativeTCPBootstrapNetAddr(tok)
	if !ok {
		return nil, nil
	}
	return dialExternalNativeTCPBootstrapConns(
		ctx,
		addr,
		quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic),
		externalNativeTCPAuth{
			Enabled:      true,
			SessionID:    tok.SessionID,
			BearerSecret: tok.BearerSecret,
			PeerPublic:   tok.QUICPublic,
		},
		connCount,
	)
}
