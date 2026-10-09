//go:build windows

package probe

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// Windows refuses to send TCP segments through raw sockets.
const tcpSupported = false

func isPermission(err error) bool {
	return errors.Is(err, syscall.WSAEACCES) || errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, syscall.EACCES)
}

// disableConnReset stops Windows from reporting ICMP port unreachable
// messages as WSAECONNRESET errors on the UDP socket.
func disableConnReset(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	const sioUDPConnReset = syscall.IOC_IN | syscall.IOC_VENDOR | 12
	var ioErr error
	err = rc.Control(func(fd uintptr) {
		flag := uint32(0)
		var ret uint32
		ioErr = syscall.WSAIoctl(syscall.Handle(fd), sioUDPConnReset,
			(*byte)(unsafe.Pointer(&flag)), uint32(unsafe.Sizeof(flag)), nil, 0, &ret, nil, 0)
	})
	if err != nil {
		return err
	}
	return ioErr
}
