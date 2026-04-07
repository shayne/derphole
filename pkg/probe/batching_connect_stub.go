//go:build !linux && !darwin

package probe

import (
	"errors"
	"net"
)

func platformConnectUDP(conn *net.UDPConn, peer *net.UDPAddr) error {
	return errors.New("connected udp unsupported on this platform")
}
