package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Proto is the transport protocol used for probes.
type Proto int

const (
	UDP Proto = iota
	ICMP
	TCP
)

func (p Proto) String() string {
	switch p {
	case UDP:
		return "udp"
	case ICMP:
		return "icmp"
	case TCP:
		return "tcp"
	}
	return fmt.Sprintf("proto(%d)", int(p))
}

// ParseProto converts a protocol name into a Proto.
func ParseProto(s string) (Proto, error) {
	switch strings.ToLower(s) {
	case "udp":
		return UDP, nil
	case "icmp":
		return ICMP, nil
	case "tcp":
		return TCP, nil
	}
	return 0, fmt.Errorf("unknown protocol %q (want udp, icmp or tcp)", s)
}

// IANA protocol numbers.
const (
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58
)

// Tags are carried in 16-bit fields; 0 and 0xffff are reserved because the
// UDP checksum cannot represent them unambiguously.
const (
	MinTag = 1
	MaxTag = 0xfffe
)

// UDPPayloadLen is the constant length of UDP probe payloads.
const UDPPayloadLen = 2

// UDPPayload returns the 2-byte payload that makes the checksum of a UDP
// datagram (src:sport -> dst:dport) equal to tag. The kernel computes the
// checksum itself, so probes can be sent through ordinary UDP sockets.
func UDPPayload(src, dst net.IP, sport, dport, tag uint16) []byte {
	length := 8 + UDPPayloadLen
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:], sport)
	binary.BigEndian.PutUint16(hdr[2:], dport)
	binary.BigEndian.PutUint16(hdr[4:], uint16(length))
	s0 := fold(sum(hdr, pseudoHeaderSum(src, dst, ipProtoUDP, length)))
	// checksum = ^(s0 + p)  =>  p = ^tag - s0
	p := onesSub(^tag, s0)
	return []byte{byte(p >> 8), byte(p)}
}

// BuildUDP returns a complete UDP datagram (header and payload) tagged with
// tag. It is used for raw sending and for tests.
func BuildUDP(src, dst net.IP, sport, dport, tag uint16) []byte {
	b := make([]byte, 8+UDPPayloadLen)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], UDPPayload(src, dst, sport, dport, tag))
	binary.BigEndian.PutUint16(b[6:], transportChecksum(src, dst, ipProtoUDP, b))
	return b
}

// UDPTag recovers the probe tag from the checksum of a quoted UDP header.
// If a NAT rewrote the source address (quotedSrc != localSrc), it also
// adjusted the checksum incrementally; the adjustment is undone here.
func UDPTag(checksum uint16, quotedSrc, localSrc net.IP) uint16 {
	if quotedSrc == nil || localSrc == nil || quotedSrc.Equal(localSrc) {
		return checksum
	}
	q, l := addrSum(quotedSrc), addrSum(localSrc)
	return ^onesAdd(onesSub(^checksum, q), l)
}

func addrSum(ip net.IP) uint16 {
	if v4 := ip.To4(); v4 != nil {
		return fold(sum(v4, 0))
	}
	return fold(sum(ip.To16(), 0))
}

// icmpFlowBase is added to the flow identifier to obtain the constant
// one's complement sum id+seq of ICMP echo probes.
const icmpFlowBase = 0x5000

// ICMPEchoPayload is the constant payload of ICMP echo probes.
var ICMPEchoPayload = []byte("paris-traceroute")

// ICMPEchoID returns the echo identifier used for a probe of the given flow
// tagged with seq. id + seq is constant for a flow, hence the ICMP checksum
// (which load balancers may hash on) is constant too.
func ICMPEchoID(flow, seq uint16) uint16 {
	return onesSub(icmpFlowBase+flow, seq)
}

// ICMPEchoFlow returns the flow identifier encoded by an id/seq pair.
func ICMPEchoFlow(id, seq uint16) uint16 {
	return onesAdd(id, seq) - icmpFlowBase
}

// BuildICMPEcho returns an ICMP (or ICMPv6 when dst is IPv6) echo request
// of the given flow tagged with tag (the sequence number). For ICMPv6 the
// checksum includes the pseudo-header; operating systems usually recompute
// it, but the result is the same.
func BuildICMPEcho(src, dst net.IP, flow, tag uint16) []byte {
	b := make([]byte, 8+len(ICMPEchoPayload))
	v6 := dst.To4() == nil
	if v6 {
		b[0] = 128
	} else {
		b[0] = 8
	}
	binary.BigEndian.PutUint16(b[4:], ICMPEchoID(flow, tag))
	binary.BigEndian.PutUint16(b[6:], tag)
	copy(b[8:], ICMPEchoPayload)
	var cs uint16
	if v6 {
		cs = transportChecksum(src, dst, ipProtoICMPv6, b)
	} else {
		cs = Checksum(b)
	}
	binary.BigEndian.PutUint16(b[2:], cs)
	return b
}

// TCPSeq returns the sequence number carrying tag.
func TCPSeq(tag uint16) uint32 { return uint32(tag)<<16 | 0x5054 }

// TCPTagFromSeq extracts the tag from a probe sequence number.
func TCPTagFromSeq(seq uint32) uint16 { return uint16(seq >> 16) }

// BuildTCPSyn returns a TCP SYN segment tagged with tag. The TCP checksum
// covers the pseudo-header, so src must be the real source address.
func BuildTCPSyn(src, dst net.IP, sport, dport, tag uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint32(b[4:], TCPSeq(tag))
	b[12] = 5 << 4 // data offset
	b[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(b[14:], 5840)
	binary.BigEndian.PutUint16(b[16:], transportChecksum(src, dst, ipProtoTCP, b))
	return b
}
