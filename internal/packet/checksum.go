// Package packet builds Paris-traceroute probes and parses the replies.
//
// The central idea of Paris traceroute is that every field a load balancer
// may hash on (the "flow identifier") stays constant for all probes of one
// flow, while the probe is still uniquely tagged so that replies can be
// matched. Fields used for tagging are chosen per protocol:
//
//   - UDP:  the UDP checksum (forced through a 2-byte payload);
//   - ICMP: the echo sequence number, compensated in the identifier so the
//     ICMP checksum stays constant;
//   - TCP:  the upper 16 bits of the sequence number.
package packet

import "net"

// sum adds b as a sequence of big-endian 16-bit words to acc.
func sum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

// fold reduces a 32-bit accumulator to a 16-bit one's complement sum.
func fold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}

// Checksum returns the Internet checksum (RFC 1071) of b.
func Checksum(b []byte) uint16 {
	return ^fold(sum(b, 0))
}

// onesAdd and onesSub implement one's complement 16-bit arithmetic.
func onesAdd(a, b uint16) uint16 { return fold(uint32(a) + uint32(b)) }
func onesSub(a, b uint16) uint16 { return onesAdd(a, ^b) }

// pseudoHeaderSum returns the (unfolded) sum of the IPv4 or IPv6
// pseudo-header used by UDP, TCP and ICMPv6 checksums.
func pseudoHeaderSum(src, dst net.IP, proto uint8, length int) uint32 {
	var acc uint32
	if s4, d4 := src.To4(), dst.To4(); s4 != nil && d4 != nil {
		acc = sum(s4, acc)
		acc = sum(d4, acc)
		acc += uint32(proto)
		acc += uint32(length)
		return acc
	}
	acc = sum(src.To16(), acc)
	acc = sum(dst.To16(), acc)
	acc += uint32(length) >> 16
	acc += uint32(length) & 0xffff
	acc += uint32(proto)
	return acc
}

// transportChecksum computes the checksum of a transport segment whose
// checksum field is assumed to be zero.
func transportChecksum(src, dst net.IP, proto uint8, seg []byte) uint16 {
	return ^fold(sum(seg, pseudoHeaderSum(src, dst, proto, len(seg))))
}
