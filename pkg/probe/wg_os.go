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

	wgtransport "github.com/shayne/derpcat/pkg/wg"
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
	defer node.Close()

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
	tcpConn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(resolved.peerAddr.String(), strconv.Itoa(int(resolved.port))))
	if err != nil {
		return TransferStats{}, err
	}
	defer tcpConn.Close()

	var closeWrite func() error
	if closer, ok := tcpConn.(interface{ CloseWrite() error }); ok {
		closeWrite = closer.CloseWrite
	}

	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := tcpConn.Write(buf[:n])
			if written > 0 {
				if stats.FirstByteAt.IsZero() {
					stats.FirstByteAt = time.Now()
				}
				stats.BytesSent += int64(written)
			}
			if writeErr != nil {
				return TransferStats{}, writeErr
			}
			if written != n {
				return TransferStats{}, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			if closeWrite != nil {
				if err := closeWrite(); err != nil {
					return TransferStats{}, err
				}
			}
			if err := waitForWireGuardAck(ctx, tcpConn); err != nil {
				return TransferStats{}, err
			}
			stats.CompletedAt = time.Now()
			return stats, nil
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func ReceiveWireGuardOSToWriter(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg WireGuardConfig) (TransferStats, error) {
	node, resolved, err := newWireGuardOSNode(conn, cfg)
	if err != nil {
		return TransferStats{}, err
	}
	defer node.Close()

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
	defer ln.Close()
	if wireGuardStreamCount(cfg) > 1 {
		return receiveWireGuardParallel(ctx, &stats, ln, dst, cfg)
	}

	tcpConn, err := acceptConn(ctx, ln)
	if err != nil {
		return TransferStats{}, err
	}
	defer tcpConn.Close()

	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return TransferStats{}, err
		}
		n, readErr := tcpConn.Read(buf)
		if n > 0 {
			if stats.FirstByteAt.IsZero() {
				stats.FirstByteAt = time.Now()
			}
			written, writeErr := dst.Write(buf[:n])
			if written > 0 {
				stats.BytesReceived += int64(written)
			}
			if writeErr != nil {
				return TransferStats{}, writeErr
			}
			if written != n {
				return TransferStats{}, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			if _, err := tcpConn.Write(wireGuardDrainAck); err != nil {
				return TransferStats{}, err
			}
			stats.CompletedAt = time.Now()
			return stats, nil
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func newWireGuardOSNode(conn net.PacketConn, cfg WireGuardConfig) (*wireGuardOSNode, resolvedWireGuardConfig, error) {
	resolved, err := resolveWireGuardConfig(conn, cfg)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	ifaceHint := platformWGInterfaceHint()
	tunDev, err := tun.CreateTUN(ifaceHint, defaultWireGuardKernelMTU)
	if err != nil {
		return nil, resolvedWireGuardConfig{}, err
	}
	iface, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, resolvedWireGuardConfig{}, err
	}

	bind := wgtransport.NewBind(wgtransport.BindConfig{
		PacketConn:     conn,
		Transport:      cfg.Transport,
		DirectEndpoint: strings.TrimSpace(cfg.DirectEndpoint),
	})
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, "derpcat-probe: "))
	if err := dev.IpcSet(wireGuardUAPI(resolved, strings.TrimSpace(cfg.DirectEndpoint))); err != nil {
		dev.Close()
		tunDev.Close()
		return nil, resolvedWireGuardConfig{}, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		tunDev.Close()
		return nil, resolvedWireGuardConfig{}, err
	}
	if err := configureWireGuardOSInterface(iface, resolved.localAddr, resolved.peerAddr); err != nil {
		dev.Close()
		tunDev.Close()
		return nil, resolvedWireGuardConfig{}, err
	}
	return &wireGuardOSNode{iface: iface, device: dev, tun: tunDev}, resolved, nil
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
		return resolvedWireGuardConfig{}, fmt.Errorf("wireguard os probe mode requires %q transport", probeTransportBatched)
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
