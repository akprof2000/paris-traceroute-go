package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	src4 = net.ParseIP("192.168.1.10").To4()
	dst4 = net.ParseIP("93.184.216.34").To4()
	nat4 = net.ParseIP("203.0.113.7").To4()
	src6 = net.ParseIP("2001:db8::10")
	dst6 = net.ParseIP("2001:db8:ffff::1")
)

func TestUDPChecksumIsTag(t *testing.T) {
	for _, ips := range [][2]net.IP{{src4, dst4}, {src6, dst6}} {
		for _, tag := range []uint16{MinTag, 2, 0x1234, 0x8000, 0xfff0, MaxTag} {
			b := BuildUDP(ips[0], ips[1], 40000, 33457, tag)
			if got := binary.BigEndian.Uint16(b[6:]); got != tag {
				t.Errorf("%v: checksum %#x, want tag %#x", ips[1], got, tag)
			}
			// The datagram must verify: the checksum over pseudo-header and
			// segment (checksum included) is zero.
			if v := ^fold(sum(b, pseudoHeaderSum(ips[0], ips[1], ipProtoUDP, len(b)))); v != 0 {
				t.Errorf("%v tag %#x: datagram does not verify (%#x)", ips[1], tag, v)
			}
			// Flow identifier (ports, length) is unchanged by the tag.
			if binary.BigEndian.Uint16(b[0:]) != 40000 || binary.BigEndian.Uint16(b[2:]) != 33457 || len(b) != 10 {
				t.Errorf("flow fields changed")
			}
		}
	}
}

func TestUDPTagThroughNAT(t *testing.T) {
	const tag = 0x4242
	b := BuildUDP(src4, dst4, 40000, 33457, tag)
	// The NAT rewrites the source address and recomputes the checksum.
	b[6], b[7] = 0, 0
	natted := transportChecksum(nat4, dst4, ipProtoUDP, b)
	if natted == tag {
		t.Fatal("test is meaningless: NAT did not change the checksum")
	}
	if got := UDPTag(natted, nat4, src4); got != tag {
		t.Fatalf("UDPTag = %#x, want %#x", got, tag)
	}
}

func TestICMPEchoChecksumConstantPerFlow(t *testing.T) {
	for _, dst := range []net.IP{dst4, dst6} {
		for flow := uint16(0); flow < 50; flow += 7 {
			want := binary.BigEndian.Uint16(BuildICMPEcho(src4, dst, flow, MinTag)[2:])
			if dst.To4() == nil {
				want = binary.BigEndian.Uint16(BuildICMPEcho(src6, dst, flow, MinTag)[2:])
			}
			for _, tag := range []uint16{2, 100, 0x7fff, 0xabcd, MaxTag} {
				s := src4
				if dst.To4() == nil {
					s = src6
				}
				b := BuildICMPEcho(s, dst, flow, tag)
				if got := binary.BigEndian.Uint16(b[2:]); got != want {
					t.Errorf("flow %d tag %d: checksum %#x, want %#x", flow, tag, got, want)
				}
				id, seq := binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:])
				if seq != tag || ICMPEchoFlow(id, seq) != flow {
					t.Errorf("flow %d tag %d: id/seq decode to flow %d seq %d", flow, tag, ICMPEchoFlow(id, seq), seq)
				}
				if dst.To4() != nil && Checksum(b) != 0 {
					t.Errorf("ICMP echo does not verify")
				}
			}
		}
	}
	a := binary.BigEndian.Uint16(BuildICMPEcho(src4, dst4, 1, 5)[2:])
	b := binary.BigEndian.Uint16(BuildICMPEcho(src4, dst4, 2, 5)[2:])
	if a == b {
		t.Error("different flows must have different checksums")
	}
}

func ipv4Header(src, dst net.IP, proto, ttl int, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8] = byte(ttl)
	h[9] = byte(proto)
	copy(h[12:], src.To4())
	copy(h[16:], dst.To4())
	binary.BigEndian.PutUint16(h[10:], Checksum(h))
	return append(h, payload...)
}

func ipv6Header(src, dst net.IP, next int, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)))
	h[6] = byte(next)
	h[7] = 1
	copy(h[8:], src.To16())
	copy(h[24:], dst.To16())
	return append(h, payload...)
}

func marshal(t *testing.T, m *icmp.Message) []byte {
	t.Helper()
	b, err := m.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseTimeExceededUDPv4(t *testing.T) {
	probe := BuildUDP(src4, dst4, 40001, 33457, 0x777)
	quoted := ipv4Header(src4, dst4, ipProtoUDP, 1, probe)
	router := net.ParseIP("10.0.0.1")
	b := marshal(t, &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{
		Data: quoted,
		Extensions: []icmp.Extension{&icmp.MPLSLabelStack{Class: 1, Type: 1,
			Labels: []icmp.MPLSLabel{{Label: 16004, TC: 0, S: true, TTL: 1}}}},
	}})
	r, err := ParseICMP(false, router, b, src4)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != TimeExceeded || r.Proto != UDP || r.Tag != 0x777 || r.SrcPort != 40001 ||
		r.DstPort != 33457 || !r.QuotedDst.Equal(dst4) || r.QuotedTTL != 1 {
		t.Fatalf("unexpected response %+v", r)
	}
	if len(r.MPLS) != 1 || r.MPLS[0].Label != 16004 {
		t.Fatalf("MPLS labels %+v", r.MPLS)
	}
}

func TestParsePortUnreachableUDPv6(t *testing.T) {
	probe := BuildUDP(src6, dst6, 40001, 33457, 0x1001)
	quoted := ipv6Header(src6, dst6, ipProtoUDP, probe)
	b := marshal(t, &icmp.Message{Type: ipv6.ICMPTypeDestinationUnreachable, Code: 4,
		Body: &icmp.DstUnreach{Data: quoted}})
	r, err := ParseICMP(true, dst6, b, src6)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != DestUnreachable || r.Code != 4 || r.Tag != 0x1001 || !r.QuotedDst.Equal(dst6) {
		t.Fatalf("unexpected response %+v", r)
	}
}

func TestParseICMPEcho(t *testing.T) {
	probe := BuildICMPEcho(src4, dst4, 3, 0x2222)
	quoted := ipv4Header(src4, dst4, ipProtoICMP, 1, probe)
	b := marshal(t, &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: quoted}})
	r, err := ParseICMP(false, net.ParseIP("10.0.0.1"), b, src4)
	if err != nil {
		t.Fatal(err)
	}
	if r.Proto != ICMP || r.Tag != 0x2222 || ICMPEchoFlow(r.ID, r.Tag) != 3 {
		t.Fatalf("unexpected response %+v", r)
	}

	reply := marshal(t, &icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{
		ID: int(ICMPEchoID(3, 0x2223)), Seq: 0x2223, Data: ICMPEchoPayload}})
	r, err = ParseICMP(false, dst4, reply, src4)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != EchoReply || r.Tag != 0x2223 || ICMPEchoFlow(r.ID, r.Tag) != 3 {
		t.Fatalf("unexpected echo reply %+v", r)
	}
	// Echo requests (e.g. our own probes looped back) are not replies.
	req := marshal(t, &icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 1}})
	if _, err := ParseICMP(false, dst4, req, src4); err == nil {
		t.Fatal("echo request accepted as a reply")
	}
}

func TestParseTCP(t *testing.T) {
	syn := BuildTCPSyn(src4, dst4, 41000, 80, 0x3333)
	if Checksum(append(pseudo(src4, dst4, ipProtoTCP, len(syn)), syn...)) != 0 {
		t.Fatal("TCP SYN does not verify")
	}
	// Quoted in a time exceeded message.
	b := marshal(t, &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded,
		Body: &icmp.TimeExceeded{Data: ipv4Header(src4, dst4, ipProtoTCP, 1, syn)}})
	r, err := ParseICMP(false, net.ParseIP("10.0.0.1"), b, src4)
	if err != nil || r.Proto != TCP || r.Tag != 0x3333 || r.SrcPort != 41000 {
		t.Fatalf("quoted TCP: %+v %v", r, err)
	}
	// SYN/ACK from the destination.
	sa := make([]byte, 20)
	binary.BigEndian.PutUint16(sa[0:], 80)
	binary.BigEndian.PutUint16(sa[2:], 41000)
	binary.BigEndian.PutUint32(sa[8:], TCPSeq(0x3333)+1)
	sa[12] = 5 << 4
	sa[13] = 0x12
	r, err = ParseTCP(dst4, sa)
	if err != nil || r.Tag != 0x3333 || r.SrcPort != 41000 || r.DstPort != 80 || r.Kind != TCPReply {
		t.Fatalf("SYN/ACK: %+v %v", r, err)
	}
}

// pseudo returns the IPv4 pseudo-header as bytes.
func pseudo(src, dst net.IP, proto, length int) []byte {
	b := make([]byte, 12)
	copy(b, src.To4())
	copy(b[4:], dst.To4())
	b[9] = byte(proto)
	binary.BigEndian.PutUint16(b[10:], uint16(length))
	return b
}

func TestUDPTagNATChecksumNotRestored(t *testing.T) {
	// Some NATs (e.g. the one in front of WSL) translate the quoted
	// addresses back but leave the quoted checksum as it was on the wire.
	const tag = 0x02fa
	b := BuildUDP(src4, dst4, 52030, 33457, tag)
	wire := append([]byte(nil), b...)
	wire[6], wire[7] = 0, 0
	binary.BigEndian.PutUint16(b[6:], transportChecksum(nat4, dst4, ipProtoUDP, wire))
	icmpMsg := marshal(t, &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded,
		Body: &icmp.TimeExceeded{Data: ipv4Header(src4, dst4, ipProtoUDP, 1, b)}})
	r, err := ParseICMP(false, net.ParseIP("10.0.0.2"), icmpMsg, src4)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tag == tag || r.AltTag != tag {
		t.Fatalf("Tag=%#x AltTag=%#x, want AltTag %#x", r.Tag, r.AltTag, tag)
	}
}
