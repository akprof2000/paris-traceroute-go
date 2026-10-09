//go:build !windows

package main

func privilegeWarning() string { return "" }

func noReplyHint() string {
	return "No router answered: check that a firewall does not drop inbound ICMP time-exceeded messages."
}
