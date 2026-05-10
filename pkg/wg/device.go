// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	"github.com/shayne/derphole/pkg/derpbind"
	localnetstack "github.com/shayne/derphole/pkg/wg/netstack"
	"github.com/tailscale/wireguard-go/device"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/types/key"
)

const defaultMTU = 1280

type Config struct {
	PrivateKey     [32]byte
	PeerPublicKey  [32]byte
	LocalAddr      netip.Addr
	PeerAddr       netip.Addr
	PacketConn     net.PacketConn
	Transport      string
	DERPClient     *derpbind.Client
	PeerDERP       key.NodePublic
	PathSelector   PathSelector
	DirectEndpoint string
	MTU            int
}

type Node struct {
	localAddr netip.Addr
	peerAddr  netip.Addr
	device    *device.Device
	bind      *Bind
	net       *localnetstack.Net
}

func GenerateKeypair() (private [32]byte, public [32]byte, err error) {
	if _, err = rand.Read(private[:]); err != nil {
		return private, public, err
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return private, public, err
	}
	copy(public[:], pub)
	return private, public, nil
}

func NewNode(cfg Config) (*Node, error) {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	tunDev, tnet, err := localnetstack.CreateNetTUN([]netip.Addr{cfg.LocalAddr}, nil, mtu)
	if err != nil {
		return nil, err
	}

	bind := NewBind(BindConfig{
		PacketConn:     cfg.PacketConn,
		Transport:      cfg.Transport,
		DERPClient:     cfg.DERPClient,
		PeerDERP:       cfg.PeerDERP,
		PathSelector:   cfg.PathSelector,
		DirectEndpoint: cfg.DirectEndpoint,
	})

	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, "derphole: "))
	if err := dev.IpcSet(uapiConfig(cfg)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	return &Node{
		localAddr: cfg.LocalAddr,
		peerAddr:  cfg.PeerAddr,
		device:    dev,
		bind:      bind,
		net:       tnet,
	}, nil
}

func (n *Node) Close() error {
	if n == nil {
		return nil
	}
	n.device.Close()
	return nil
}

func (n *Node) ListenTCP(port uint16) (net.Listener, error) {
	return n.net.ListenTCP(&net.TCPAddr{
		IP:   net.IP(n.localAddr.AsSlice()),
		Port: int(port),
	})
}

func (n *Node) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return n.net.DialContextTCPAddrPort(ctx, addr)
}

func (n *Node) SetDirectEndpoint(addr string) error {
	return n.bind.SetDirectEndpoint(addr)
}

func (n *Node) DirectEndpoint() string {
	return n.bind.DirectEndpoint()
}

func (n *Node) DirectConfirmed() bool {
	return n.bind.DirectConfirmed()
}

func uapiConfig(cfg Config) string {
	return fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=%s\nendpoint=%s\n",
		hex.EncodeToString(cfg.PrivateKey[:]),
		hex.EncodeToString(cfg.PeerPublicKey[:]),
		allowedIP(cfg.PeerAddr),
		initialEndpoint(cfg.DirectEndpoint),
	)
}

func allowedIP(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String() + "/32"
	}
	return addr.String() + "/128"
}

func initialEndpoint(direct string) string {
	if direct != "" {
		return direct
	}
	return "derp"
}
