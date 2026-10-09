//go:build windows

package main

import "golang.org/x/sys/windows"

func privilegeWarning() string {
	if windows.GetCurrentProcessToken().IsElevated() {
		return ""
	}
	return "not running elevated: raw sockets may not receive ICMP errors, run from an Administrator prompt"
}

func noReplyHint() string {
	return `No router answered. On Windows, run from an elevated prompt and make sure the
firewall lets inbound ICMP errors through, for example (elevated PowerShell):
  New-NetFirewallRule -DisplayName "paris-traceroute ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 11,3 -Action Allow
  New-NetFirewallRule -DisplayName "paris-traceroute ICMPv6" -Direction Inbound -Protocol ICMPv6 -IcmpType 3,1 -Action Allow`
}
