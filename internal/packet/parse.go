package packet

import (
	"encoding/binary"
	"errors"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Kind classifies a reply to a probe.
type Kind int

const (
	TimeExceeded    Kind = iota // ICMP time exceeded from an intermediate hop
	DestUnreachable             // ICMP destination unreachable
	EchoReply                   // ICMP echo reply from the destination
	TCPReply                    // TCP SYN/ACK or RST from the destination
)

func (k Kind) String() string {
	switch k {
	case TimeExceeded:
		return "time-exceeded"
	case DestUnreachable:
		return "unreachable"
	case EchoReply:
		return "echo-reply"
	case TCPReply:
		return "tcp-reply"
	}
	return "unknown"
}

// MPLSLabel is an MPLS label stack entry reported in ICMP extensions (RFC 4950).
type MPLSLabel struct {
	Label int  `json:"label"`
	TC    int  `json:"tc"`
	S     bool `json:"s"`
	TTL   int  `json:"ttl"`
}

// Response is a parsed reply that refers to one of our probes.
type Response struct {
	From  net.IP
	Kind  Kind
	Type  int // ICMP type (0 for TCP replies)
	Code  int // ICMP code
	Proto Proto
	Tag   uint16
	// AltTag, when not zero, is a second candidate tag. It is recomputed
	// from the quoted UDP header and payload, for NATs that translate the
	// quoted addresses back but leave the quoted checksum as it was on the
	// wire.
	AltTag uint16
	// Flow is set for ICMP echo probes (derived from id/seq); for UDP and
	// TCP the flow is identified by the source port.
	SrcPort, DstPort uint16
	ID               uint16 // ICMP echo identifier
	// QuotedDst is the destination of the quoted probe (ICMP errors only).
	QuotedDst net.IP
	// QuotedTTL is the TTL of the probe as it arrived at the replying
	// router (IPv4 ICMP errors only, -1 otherwise).
	QuotedTTL int
	TCPFlags  uint8
	MPLS      []MPLSLabel
}

// ErrNotOurs is returned for packets that are not replies to probes.
var ErrNotOurs = errors.New("packet is not a reply to a probe")

// ParseICMP parses an ICMP (v4 or v6) message received from "from".
// localSrc is the probe source address, used to undo NAT checksum updates.
func ParseICMP(v6 bool, from net.IP, b []byte, localSrc net.IP) (*Response, error) {
	proto := ipProtoICMP
	if v6 {
		proto = ipProtoICMPv6
	}
	m, err := icmp.ParseMessage(proto, b)
	if err != nil {
		return nil, err
	}
	r := &Response{From: from, Code: m.Code, QuotedTTL: -1}
	var quoted []byte
	var exts []icmp.Extension
	switch body := m.Body.(type) {
	case *icmp.Echo:
		if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
			return nil, ErrNotOurs
		}
		r.Kind, r.Proto = EchoReply, ICMP
		r.ID, r.Tag = uint16(body.ID), uint16(body.Seq)
		r.Type = icmpType(m.Type)
		return r, nil
	case *icmp.TimeExceeded:
		r.Kind = TimeExceeded
		quoted, exts = body.Data, body.Extensions
	case *icmp.DstUnreach:
		r.Kind = DestUnreachable
		quoted, exts = body.Data, body.Extensions
	default:
		return nil, ErrNotOurs
	}
	r.Type = icmpType(m.Type)
	for _, e := range exts {
		if st, ok := e.(*icmp.MPLSLabelStack); ok {
			for _, l := range st.Labels {
				r.MPLS = append(r.MPLS, MPLSLabel{Label: l.Label, TC: l.TC, S: l.S, TTL: l.TTL})
			}
		}
	}
	if err := parseQuoted(r, quoted, localSrc); err != nil {
		return nil, err
	}
	return r, nil
}

func icmpType(t icmp.Type) int {
	switch t := t.(type) {
	case ipv4.ICMPType:
		return int(t)
	case ipv6.ICMPType:
		return int(t)
	}
	return -1
}

// parseQuoted decodes the IP header and the first 8 bytes of the transport
// header quoted in an ICMP error.
func parseQuoted(r *Response, b []byte, localSrc net.IP) error {
	if len(b) < 1 {
		return ErrNotOurs
	}
	var proto int
	var src net.IP
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 {
			return ErrNotOurs
		}
		r.QuotedTTL = int(b[8])
		proto = int(b[9])
		src = net.IP(append([]byte(nil), b[12:16]...))
		r.QuotedDst = net.IP(append([]byte(nil), b[16:20]...))
		b = b[ihl:]
	case 6:
		if len(b) < 40+8 {
			return ErrNotOurs
		}
		proto = int(b[6])
		src = net.IP(append([]byte(nil), b[8:24]...))
		r.QuotedDst = net.IP(append([]byte(nil), b[24:40]...))
		b = b[40:]
	default:
		return ErrNotOurs
	}
	switch proto {
	case ipProtoUDP:
		r.Proto = UDP
		r.SrcPort = binary.BigEndian.Uint16(b[0:])
		r.DstPort = binary.BigEndian.Uint16(b[2:])
		r.Tag = UDPTag(binary.BigEndian.Uint16(b[6:]), src, localSrc)
		if localSrc != nil && len(b) >= 8+UDPPayloadLen && binary.BigEndian.Uint16(b[4:]) == 8+UDPPayloadLen {
			seg := append([]byte(nil), b[:8+UDPPayloadLen]...)
			seg[6], seg[7] = 0, 0
			if alt := transportChecksum(localSrc, r.QuotedDst, ipProtoUDP, seg); alt != r.Tag {
				r.AltTag = alt
			}
		}
	case ipProtoICMP, ipProtoICMPv6:
		if b[0] != 8 && b[0] != 128 { // only echo requests are probes
			return ErrNotOurs
		}
		r.Proto = ICMP
		r.ID = binary.BigEndian.Uint16(b[4:])
		r.Tag = binary.BigEndian.Uint16(b[6:])
	case ipProtoTCP:
		r.Proto = TCP
		r.SrcPort = binary.BigEndian.Uint16(b[0:])
		r.DstPort = binary.BigEndian.Uint16(b[2:])
		r.Tag = TCPTagFromSeq(binary.BigEndian.Uint32(b[4:]))
	default:
		return ErrNotOurs
	}
	return nil
}

// ParseTCP parses a TCP segment (without IP header) received from the
// destination in reply to a SYN probe.
func ParseTCP(from net.IP, b []byte) (*Response, error) {
	if len(b) < 20 {
		return nil, ErrNotOurs
	}
	flags := b[13]
	const ack, rst, syn = 0x10, 0x04, 0x02
	if flags&ack == 0 || flags&(rst|syn) == 0 {
		return nil, ErrNotOurs
	}
	ackNum := binary.BigEndian.Uint32(b[8:])
	return &Response{
		From:      from,
		Kind:      TCPReply,
		Proto:     TCP,
		SrcPort:   binary.BigEndian.Uint16(b[2:]), // our port is their destination
		DstPort:   binary.BigEndian.Uint16(b[0:]),
		Tag:       TCPTagFromSeq(ackNum - 1),
		QuotedTTL: -1,
		TCPFlags:  flags,
	}, nil
}
