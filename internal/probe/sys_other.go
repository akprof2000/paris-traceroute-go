//go:build !windows

package probe

import (
	"errors"
	"net"
	"syscall"
)

const tcpSupported = true

func isPermission(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func disableConnReset(*net.UDPConn) error { return nil }
