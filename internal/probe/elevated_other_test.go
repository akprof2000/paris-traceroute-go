//go:build !windows

package probe

func canReceiveICMPErrors() bool { return true }
