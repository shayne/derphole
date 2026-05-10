// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	wgtransport "github.com/shayne/derphole/pkg/wg"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
)

const defaultWireGuardKernelMTU = 1280

type wireGuardOSNode struct {
	iface  string
	device *device.Device
	tun    tun.Device
}

func SendWireGuardOS(ctx context.Context, conn net.PacketConn, src io.Reader, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardOSNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer func() { _ = node.Close() }()

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	if len(cfg.PeerCandidates) > 0 {
		go PunchAddrs(punchCtx, conn, cfg.PeerCandidates, nil, defaultPunchInterval)
	}

	stats := TransferStats{
		StartedAt: time.Now(),
		Transport: PreviewTransportCaps(conn, cfg.Transport),
	}
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(resolved.localAddr.String())},
	}
	if wireGuardStreamCount(cfg) > 1 {
		return sendWireGuardParallel(ctx, &stats, func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(resolved.peerAddr.String(), strconv.Itoa(int(resolved.port))))
		}, cfg)
	}
	return sendWireGuardSingle(ctx, &stats, src, func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(resolved.peerAddr.String(), strconv.Itoa(int(resolved.port))))
	})
}

func ReceiveWireGuardOSToWriter(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardOSNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer func() { _ = node.Close() }()

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	if len(cfg.PeerCandidates) > 0 {
		go PunchAddrs(punchCtx, conn, cfg.PeerCandidates, nil, defaultPunchInterval)
	}

	stats := TransferStats{
		StartedAt: time.Now(),
		Transport: PreviewTransportCaps(conn, cfg.Transport),
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{
		IP:   net.ParseIP(resolved.localAddr.String()),
		Port: int(resolved.port),
	})
	if err != nil {
		return TransferStats{}, err
	}
	defer func() { _ = ln.Close() }()
	if wireGuardStreamCount(cfg) > 1 {
		return receiveWireGuardParallel(ctx, &stats, ln, dst, cfg)
	}
	return receiveWireGuardSingle(ctx, &stats, dst, cfg, func(ctx context.Context) (net.Conn, error) {
		return acceptConn(ctx, ln)
	})
}

func newWireGuardOSNode(conn net.PacketConn, cfg WireGuardConfig) (*wireGuardOSNode, resolvedWireGuardConfig, error) {
	resolved, err := resolveWireGuardConfig(conn, cfg)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	tunDev, iface, err := newWireGuardOSTUN()
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	dev, err := startWireGuardOSDevice(conn, tunDev, cfg, resolved)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	if err := configureWireGuardOSInterface(iface, resolved.localAddr, resolved.peerAddr); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return nil, resolvedWireGuardConfig{}, err
	}
	return &wireGuardOSNode{iface: iface, device: dev, tun: tunDev}, resolved, nil
}

func newWireGuardOSTUN() (tun.Device, string, error) {
	tunDev, err := tun.CreateTUN(platformWGInterfaceHint(), defaultWireGuardKernelMTU)
	if err != nil {
		return nil, "", err
	}
	iface, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, "", err
	}
	return tunDev, iface, nil
}

func startWireGuardOSDevice(conn net.PacketConn, tunDev tun.Device, cfg WireGuardConfig, resolved resolvedWireGuardConfig) (*device.Device, error) {
	directEndpoint := strings.TrimSpace(cfg.DirectEndpoint)
	bind := wgtransport.NewBind(wgtransport.BindConfig{
		PacketConn:     conn,
		Transport:      cfg.Transport,
		DirectEndpoint: directEndpoint,
	})
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, "derphole-probe: "))
	if err := configureWireGuardDevice(dev, tunDev, wireGuardUAPI(resolved, directEndpoint)); err != nil {
		return nil, err
	}
	return dev, nil
}

func configureWireGuardDevice(dev *device.Device, tunDev tun.Device, uapi string) error {
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return err
	}
	return nil
}

func (n *wireGuardOSNode) Close() error {
	if n == nil {
		return nil
	}
	if n.iface != "" {
		_ = teardownWireGuardOSInterface(n.iface)
	}
	if n.device != nil {
		n.device.Close()
	}
	if n.tun != nil {
		return n.tun.Close()
	}
	return nil
}

func resolveWireGuardConfig(conn net.PacketConn, cfg WireGuardConfig) (resolvedWireGuardConfig, error) {
	if conn == nil {
		return resolvedWireGuardConfig{}, fmt.Errorf("nil packet conn")
	}
	if strings.TrimSpace(cfg.Transport) == "" {
		cfg.Transport = probeTransportBatched
	}
	if cfg.Transport != probeTransportBatched {
		return resolvedWireGuardConfig{}, fmt.Errorf("wireguard probe mode requires %q transport", probeTransportBatched)
	}
	privateKey, err := parseHex32(cfg.PrivateKeyHex)
	if err != nil {
		return resolvedWireGuardConfig{}, fmt.Errorf("parse wg private key: %w", err)
	}
	peerPublic, err := parseHex32(cfg.PeerPublicHex)
	if err != nil {
		return resolvedWireGuardConfig{}, fmt.Errorf("parse wg peer public key: %w", err)
	}
	localAddr, err := netip.ParseAddr(strings.TrimSpace(cfg.LocalAddr))
	if err != nil {
		return resolvedWireGuardConfig{}, fmt.Errorf("parse wg local addr: %w", err)
	}
	peerAddr, err := netip.ParseAddr(strings.TrimSpace(cfg.PeerAddr))
	if err != nil {
		return resolvedWireGuardConfig{}, fmt.Errorf("parse wg peer addr: %w", err)
	}
	port := cfg.Port
	if port == 0 {
		port = defaultWireGuardProbePort
	}
	return resolvedWireGuardConfig{
		privateKey: privateKey,
		peerPublic: peerPublic,
		localAddr:  localAddr,
		peerAddr:   peerAddr,
		port:       port,
	}, nil
}

func wireGuardUAPI(cfg resolvedWireGuardConfig, directEndpoint string) string {
	return fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=%s\nendpoint=%s\n",
		encodeHex32(cfg.privateKey),
		encodeHex32(cfg.peerPublic),
		wireGuardAllowedIP(cfg.peerAddr),
		wireGuardInitialEndpoint(directEndpoint),
	)
}

func encodeHex32(v [32]byte) string {
	return fmt.Sprintf("%x", v[:])
}

func wireGuardAllowedIP(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String() + "/32"
	}
	return addr.String() + "/128"
}

func wireGuardInitialEndpoint(direct string) string {
	if direct != "" {
		return direct
	}
	return "derp"
}

func platformWGInterfaceHint() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return fmt.Sprintf("dcpwg%d", os.Getpid()%10000)
}

func configureWireGuardOSInterface(iface string, localAddr, peerAddr netip.Addr) error {
	switch runtime.GOOS {
	case "darwin":
		return runInterfaceCommand("ifconfig", iface, "inet", localAddr.String(), peerAddr.String(), "up")
	case "linux":
		if err := runInterfaceCommand("ip", "addr", "add", localAddr.String(), "peer", peerAddr.String(), "dev", iface); err != nil {
			return err
		}
		return runInterfaceCommand("ip", "link", "set", "dev", iface, "up", "mtu", strconv.Itoa(defaultWireGuardKernelMTU))
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

func teardownWireGuardOSInterface(iface string) error {
	switch runtime.GOOS {
	case "darwin":
		return runInterfaceCommand("ifconfig", iface, "down")
	case "linux":
		return runInterfaceCommand("ip", "link", "del", "dev", iface)
	default:
		return nil
	}
}

func runInterfaceCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}
