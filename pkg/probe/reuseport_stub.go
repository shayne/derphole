//go:build !linux && !darwin

package probe

import (
	"errors"
	"syscall"
)

func reusePortControl(network, address string, c syscall.RawConn) error {
	return errors.New("SO_REUSEPORT unsupported on this platform")
}
