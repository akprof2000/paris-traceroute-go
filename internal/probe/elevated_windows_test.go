package probe

import "golang.org/x/sys/windows"

// Unelevated Windows processes can open raw sockets but do not receive
// ICMP errors on them.
func canReceiveICMPErrors() bool { return windows.GetCurrentProcessToken().IsElevated() }
