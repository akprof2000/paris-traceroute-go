// Package probe sends Paris-traceroute probes over the network and matches
// the replies to them.
package probe

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/akprof2000/paris-traceroute-go/internal/packet"
)

// Reply is the answer to one probe.
type Reply struct {
	Addr      net.IP
	RTT       time.Duration
	Kind      packet.Kind
	Type      int
	Code      int
	QuotedTTL int
	MPLS      []packet.MPLSLabel
}

// Prober sends single probes. Implementations must be safe for concurrent use.
type Prober interface {
	// Probe sends a probe with the given TTL on the given flow and waits
	// for the reply. A nil reply and nil error mean that nothing came back
	// before the timeout (a "star").
	Probe(ctx context.Context, ttl int, flow uint16) (*Reply, error)
	Close() error
}

// MaxFlow is the largest flow identifier a prober accepts.
const MaxFlow = 0x7fff

// Config configures a network prober.
type Config struct {
	Proto   packet.Proto
	Dst     net.IP
	Src     net.IP // source address; detected automatically when nil
	DstPort uint16 // destination port (UDP/TCP)
	SrcPort uint16 // base source port (UDP/TCP); flow f uses SrcPort+f. 0 = automatic
	Timeout time.Duration
}

type received struct {
	resp *packet.Response
	at   time.Time
}

type pendingProbe struct {
	flow  uint16
	sport uint16
	order uint64 // registration order
	ch    chan received
}

type udpSock struct {
	conn  *net.UDPConn
	sport uint16
	v4    *ipv4.Conn
	v6    *ipv6.Conn
}

type netProber struct {
	cfg Config
	v6  bool
	src net.IP

	icmpConn *icmp.PacketConn
	tcpConn  *net.IPConn
	tcpPC4   *ipv4.PacketConn
	tcpPC6   *ipv6.PacketConn

	sendMu sync.Mutex // serialises TTL changes and writes

	mu      sync.Mutex
	pending map[uint16]*pendingProbe
	nextTag uint16
	order   uint64
	udp     map[uint16]*udpSock

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// ErrPermission hints that raw sockets need elevated privileges.
var ErrPermission = errors.New("raw sockets require root/CAP_NET_RAW on Linux or an elevated (Administrator) prompt on Windows")

// New opens the sockets needed to probe cfg.Dst with cfg.Proto.
func New(cfg Config) (Prober, error) {
	if cfg.Dst == nil {
		return nil, errors.New("no destination")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	p := &netProber{
		cfg:     cfg,
		v6:      cfg.Dst.To4() == nil,
		pending: make(map[uint16]*pendingProbe),
		nextTag: uint16(rand.IntN(packet.MaxTag-packet.MinTag)) + packet.MinTag,
		udp:     make(map[uint16]*udpSock),
	}
	if p.v6 {
		p.cfg.Dst = cfg.Dst.To16()
	} else {
		p.cfg.Dst = cfg.Dst.To4()
	}
	src := cfg.Src
	if src == nil {
		var err error
		if src, err = sourceFor(p.cfg.Dst); err != nil {
			return nil, fmt.Errorf("cannot find a source address for %s: %w", cfg.Dst, err)
		}
	}
	if p.v6 {
		p.src = src.To16()
	} else if p.src = src.To4(); p.src == nil {
		return nil, fmt.Errorf("source %s and destination %s are of different families", src, cfg.Dst)
	}

	icmpNet := "ip4:icmp"
	if p.v6 {
		icmpNet = "ip6:ipv6-icmp"
	}
	c, err := icmp.ListenPacket(icmpNet, p.src.String())
	if err != nil {
		return nil, wrapPerm(fmt.Errorf("listen %s: %w", icmpNet, err))
	}
	p.icmpConn = c
	if p.v6 {
		// Only the message types we care about.
		var f ipv6.ICMPFilter
		f.SetAll(true)
		for _, t := range []ipv6.ICMPType{ipv6.ICMPTypeTimeExceeded, ipv6.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeEchoReply} {
			f.Accept(t)
		}
		_ = c.IPv6PacketConn().SetICMPFilter(&f) // best effort, unsupported on some platforms
	}

	if cfg.Proto == packet.TCP {
		if !tcpSupported {
			c.Close()
			return nil, errors.New("TCP probes need raw TCP sockets, which this operating system does not allow (use -P udp or -P icmp)")
		}
		tcpNet := "ip4:tcp"
		if p.v6 {
			tcpNet = "ip6:tcp"
		}
		tc, err := net.ListenIP(tcpNet, &net.IPAddr{IP: p.src})
		if err != nil {
			c.Close()
			return nil, wrapPerm(fmt.Errorf("listen %s: %w", tcpNet, err))
		}
		p.tcpConn = tc
		if p.v6 {
			p.tcpPC6 = ipv6.NewPacketConn(tc)
		} else {
			p.tcpPC4 = ipv4.NewPacketConn(tc)
		}
		if p.cfg.SrcPort == 0 {
			p.cfg.SrcPort = uint16(33000 + rand.IntN(20000))
		}
		p.wg.Add(1)
		go p.readTCP()
	}
	if cfg.Proto == packet.UDP && p.cfg.DstPort == 0 {
		p.cfg.DstPort = 33457
	}
	if cfg.Proto == packet.TCP && p.cfg.DstPort == 0 {
		p.cfg.DstPort = 80
	}
	p.wg.Add(1)
	go p.readICMP()
	return p, nil
}

// Source returns the source address used by a prober created with New.
func Source(p Prober) net.IP {
	if np, ok := p.(*netProber); ok {
		return np.src
	}
	return nil
}

func wrapPerm(err error) error {
	if isPermission(err) {
		return fmt.Errorf("%w: %v", ErrPermission, err)
	}
	return err
}

// sourceFor finds the local address the kernel would use to reach dst.
func sourceFor(dst net.IP) (net.IP, error) {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dst, Port: 33434})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP, nil
}

func (p *netProber) Close() error {
	p.closeOnce.Do(func() {
		p.icmpConn.Close()
		if p.tcpConn != nil {
			p.tcpConn.Close()
		}
		p.mu.Lock()
		for _, s := range p.udp {
			s.conn.Close()
		}
		p.mu.Unlock()
	})
	p.wg.Wait()
	return nil
}

func (p *netProber) Probe(ctx context.Context, ttl int, flow uint16) (*Reply, error) {
	if flow > MaxFlow {
		return nil, fmt.Errorf("flow %d out of range", flow)
	}
	pp := &pendingProbe{flow: flow, ch: make(chan received, 1)}
	var us *udpSock
	switch p.cfg.Proto {
	case packet.UDP:
		var err error
		if us, err = p.udpSocket(flow); err != nil {
			return nil, err
		}
		pp.sport = us.sport
	case packet.TCP:
		pp.sport = p.cfg.SrcPort + flow
	}
	tag, err := p.register(pp)
	if err != nil {
		return nil, err
	}
	defer p.unregister(tag)

	sent, err := p.send(ttl, flow, tag, pp.sport, us)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(p.cfg.Timeout)
	defer timer.Stop()
	select {
	case r := <-pp.ch:
		return &Reply{
			Addr:      r.resp.From,
			RTT:       r.at.Sub(sent),
			Kind:      r.resp.Kind,
			Type:      r.resp.Type,
			Code:      r.resp.Code,
			QuotedTTL: r.resp.QuotedTTL,
			MPLS:      r.resp.MPLS,
		}, nil
	case <-timer.C:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *netProber) register(pp *pendingProbe) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for range packet.MaxTag {
		tag := p.nextTag
		p.nextTag++
		if p.nextTag > packet.MaxTag {
			p.nextTag = packet.MinTag
		}
		if _, busy := p.pending[tag]; !busy {
			p.order++
			pp.order = p.order
			p.pending[tag] = pp
			return tag, nil
		}
	}
	return 0, errors.New("too many probes in flight")
}

func (p *netProber) unregister(tag uint16) {
	p.mu.Lock()
	delete(p.pending, tag)
	p.mu.Unlock()
}

func (p *netProber) udpSocket(flow uint16) (*udpSock, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.udp[flow]; ok {
		return s, nil
	}
	port := 0
	if p.cfg.SrcPort != 0 {
		port = int(p.cfg.SrcPort) + int(flow)
		if port > 0xffff {
			return nil, fmt.Errorf("source port %d+%d out of range", p.cfg.SrcPort, flow)
		}
	}
	network := "udp4"
	if p.v6 {
		network = "udp6"
	}
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: p.src, Port: port})
	if err != nil {
		return nil, fmt.Errorf("udp socket for flow %d: %w", flow, err)
	}
	_ = disableConnReset(c)
	s := &udpSock{conn: c, sport: uint16(c.LocalAddr().(*net.UDPAddr).Port)}
	if p.v6 {
		s.v6 = ipv6.NewConn(c)
	} else {
		s.v4 = ipv4.NewConn(c)
	}
	p.udp[flow] = s
	return s, nil
}

// send transmits one probe and returns the time it left.
func (p *netProber) send(ttl int, flow, tag, sport uint16, us *udpSock) (time.Time, error) {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	dst := p.cfg.Dst
	var err error
	switch p.cfg.Proto {
	case packet.UDP:
		if p.v6 {
			err = us.v6.SetHopLimit(ttl)
		} else {
			err = us.v4.SetTTL(ttl)
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("set ttl: %w", err)
		}
		payload := packet.UDPPayload(p.src, dst, sport, p.cfg.DstPort, tag)
		now := time.Now()
		_, err = us.conn.WriteToUDP(payload, &net.UDPAddr{IP: dst, Port: int(p.cfg.DstPort)})
		return now, err
	case packet.ICMP:
		if p.v6 {
			err = p.icmpConn.IPv6PacketConn().SetHopLimit(ttl)
		} else {
			err = p.icmpConn.IPv4PacketConn().SetTTL(ttl)
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("set ttl: %w", err)
		}
		b := packet.BuildICMPEcho(p.src, dst, flow, tag)
		now := time.Now()
		_, err = p.icmpConn.WriteTo(b, &net.IPAddr{IP: dst})
		return now, err
	case packet.TCP:
		if p.v6 {
			err = p.tcpPC6.SetHopLimit(ttl)
		} else {
			err = p.tcpPC4.SetTTL(ttl)
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("set ttl: %w", err)
		}
		b := packet.BuildTCPSyn(p.src, dst, sport, p.cfg.DstPort, tag)
		now := time.Now()
		_, err = p.tcpConn.WriteTo(b, &net.IPAddr{IP: dst})
		return now, err
	}
	return time.Time{}, fmt.Errorf("unsupported protocol %v", p.cfg.Proto)
}

func (p *netProber) readICMP() {
	defer p.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, addr, err := p.icmpConn.ReadFrom(buf)
		at := time.Now()
		if err != nil {
			if isClosed(err) {
				return
			}
			continue
		}
		from := addrIP(addr)
		r, err := packet.ParseICMP(p.v6, from, buf[:n], p.src)
		if err != nil {
			continue
		}
		p.dispatch(r, at)
	}
}

func (p *netProber) readTCP() {
	defer p.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, addr, err := p.tcpConn.ReadFrom(buf)
		at := time.Now()
		if err != nil {
			if isClosed(err) {
				return
			}
			continue
		}
		from := addrIP(addr)
		if !from.Equal(p.cfg.Dst) {
			continue
		}
		r, err := packet.ParseTCP(from, buf[:n])
		if err != nil {
			continue
		}
		p.dispatch(r, at)
	}
}

// dispatch hands a response to the probe waiting for it, if any.
func (p *netProber) dispatch(r *packet.Response, at time.Time) {
	if r.Proto != p.cfg.Proto {
		return
	}
	switch r.Kind {
	case packet.EchoReply, packet.TCPReply:
		if !r.From.Equal(p.cfg.Dst) {
			return
		}
	default:
		if !r.QuotedDst.Equal(p.cfg.Dst) {
			return
		}
	}
	if (r.Proto == packet.UDP || r.Proto == packet.TCP) && r.DstPort != p.cfg.DstPort {
		return
	}
	p.mu.Lock()
	pp := p.pending[r.Tag]
	if pp == nil && r.AltTag != 0 {
		if pp = p.pending[r.AltTag]; pp != nil {
			r.Tag = r.AltTag
		}
	}
	if pp == nil && r.Proto == packet.UDP && !p.recentTag(r.Tag) && (r.AltTag == 0 || !p.recentTag(r.AltTag)) {
		pp = p.oldestUDP(r.SrcPort)
	}
	p.mu.Unlock()
	if pp == nil {
		return
	}
	if r.Proto == packet.ICMP && r.ID != packet.ICMPEchoID(pp.flow, r.Tag) {
		return
	}
	if r.Kind == packet.TCPReply && r.SrcPort != pp.sport {
		return
	}
	select {
	case pp.ch <- received{resp: r, at: at}:
	default: // duplicate reply
	}
}

// oldestUDP returns the oldest unanswered probe sent from sport. It is the
// fallback for NATs that translate the quoted header back but leave a
// checksum that no longer carries the tag; only the 8 first bytes of the
// UDP header are quoted then. Probes sharing a source port share the flow,
// and Paris sends them for one TTL at a time, so at worst RTTs of probes
// of the same hop are swapped. Called with p.mu held.
func (p *netProber) oldestUDP(sport uint16) *pendingProbe {
	var best *pendingProbe
	for _, pp := range p.pending {
		if pp.sport == sport && len(pp.ch) == 0 && (best == nil || pp.order < best.order) {
			best = pp
		}
	}
	return best
}

// recentTag reports whether tag was handed out recently: a reply carrying
// it belongs to a probe that has already timed out, not to a NAT-mangled
// one. Called with p.mu held.
func (p *netProber) recentTag(tag uint16) bool {
	const size = packet.MaxTag - packet.MinTag + 1
	d := (int(p.nextTag) - int(tag) + size) % size
	return d >= 1 && d <= 1024
}

func addrIP(a net.Addr) net.IP {
	switch a := a.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	return nil
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
