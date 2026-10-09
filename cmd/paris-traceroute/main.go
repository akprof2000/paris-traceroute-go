// Command paris-traceroute traces the route to a host while controlling
// the flow identifier of probes, so that load-balanced paths are reported
// faithfully (Paris traceroute), or enumerates all load-balanced paths (MDA).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/akprof2000/paris-traceroute-go/internal/packet"
	"github.com/akprof2000/paris-traceroute-go/internal/probe"
	"github.com/akprof2000/paris-traceroute-go/internal/tracer"
)

func run(o options, host string) error {
	proto, err := packet.ParseProto(o.proto)
	if err != nil {
		return err
	}
	algo := strings.ToLower(o.algo)
	switch algo {
	case "paris", "paris-traceroute":
		algo = "paris"
	case "mda":
	default:
		return fmt.Errorf("unknown algorithm %q (want paris or mda)", o.algo)
	}
	if o.flow < 0 || o.flow > probe.MaxFlow {
		return fmt.Errorf("flow must be within 0..%d", probe.MaxFlow)
	}
	dst, err := resolve(host, o.ipv4, o.ipv6)
	if err != nil {
		return err
	}
	var src net.IP
	switch {
	case o.srcAddr != "":
		if src = net.ParseIP(o.srcAddr); src == nil {
			return fmt.Errorf("bad source address %q", o.srcAddr)
		}
	case o.iface != "":
		if src, err = interfaceAddr(o.iface, dst.To4() == nil); err != nil {
			return err
		}
	}
	if w := privilegeWarning(); w != "" {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	p, err := probe.New(probe.Config{
		Proto:   proto,
		Dst:     dst,
		Src:     src,
		DstPort: uint16(o.dstPort),
		SrcPort: uint16(o.srcPort),
		Timeout: time.Duration(o.wait * float64(time.Second)),
	})
	if err != nil {
		return err
	}
	defer p.Close()
	tp := probe.Throttle(p, time.Duration(o.delay*float64(time.Second)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(o.timeout*float64(time.Second)))
		defer cancel()
	}
	names := newResolver(!o.numeric)

	var routers bool
	if algo == "paris" {
		routers, err = runParis(ctx, tp, o, host, dst, proto, names)
	} else {
		routers, err = runMDA(ctx, tp, o, host, dst, proto, names)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintln(os.Stderr, "paris-traceroute: measurement timeout reached")
		return nil
	}
	if err == nil && !routers && o.firstTTL == 1 {
		if h := noReplyHint(); h != "" {
			fmt.Fprintln(os.Stderr, h)
		}
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// interfaceAddr returns the first address of the requested family of the
// named interface, preferring global addresses to link-local ones.
func interfaceAddr(name string, v6 bool) (net.IP, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	var linkLocal net.IP
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || (ipn.IP.To4() == nil) != v6 {
			continue
		}
		if ipn.IP.IsLinkLocalUnicast() {
			linkLocal = ipn.IP
			continue
		}
		return ipn.IP, nil
	}
	if linkLocal != nil {
		return linkLocal, nil
	}
	return nil, fmt.Errorf("interface %s has no suitable address", name)
}
func resolve(host string, only4, only6 bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if only4 && ip.To4() == nil || only6 && ip.To4() != nil {
			return nil, fmt.Errorf("%s does not match the requested address family", host)
		}
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, want4 := range []bool{true, false} {
		for _, ip := range ips {
			is4 := ip.To4() != nil
			if (only4 && !is4) || (only6 && is4) || (!only4 && !only6 && is4 != want4) {
				continue
			}
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no suitable address for %s", host)
}

// resolver caches reverse DNS lookups.
type resolver struct {
	enabled bool
	mu      sync.Mutex
	cache   map[string]string
}

func newResolver(enabled bool) *resolver {
	return &resolver{enabled: enabled, cache: map[string]string{}}
}

func (r *resolver) name(addr string) string {
	if !r.enabled || addr == tracer.Star {
		return ""
	}
	r.mu.Lock()
	n, ok := r.cache[addr]
	r.mu.Unlock()
	if ok {
		return n
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(ctx, addr); err == nil && len(names) > 0 {
		n = strings.TrimSuffix(names[0], ".")
	}
	r.mu.Lock()
	r.cache[addr] = n
	r.mu.Unlock()
	return n
}

func (r *resolver) label(addr string) string {
	if n := r.name(addr); n != "" {
		return fmt.Sprintf("%s (%s)", n, addr)
	}
	return addr
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// annotation returns the traceroute-style suffix for unreachable replies.
func annotation(r *probe.Reply, v6 bool) string {
	if r.Kind != packet.DestUnreachable {
		return ""
	}
	if v6 {
		switch r.Code {
		case 0:
			return " !N"
		case 1:
			return " !X"
		case 3:
			return " !H"
		case 4:
			return ""
		}
	} else {
		switch r.Code {
		case 0:
			return " !N"
		case 1:
			return " !H"
		case 2:
			return " !P"
		case 3:
			return ""
		case 4:
			return " !F"
		case 9, 10, 13:
			return " !X"
		}
	}
	return fmt.Sprintf(" !<%d>", r.Code)
}

func mplsString(labels []packet.MPLSLabel) string {
	var b strings.Builder
	for _, l := range labels {
		s := 0
		if l.S {
			s = 1
		}
		fmt.Fprintf(&b, " [MPLS Label %d TC=%d S=%d TTL=%d]", l.Label, l.TC, s, l.TTL)
	}
	return b.String()
}

func header(algo, host string, dst net.IP, p probe.Prober, proto packet.Proto, o options) string {
	return fmt.Sprintf("%s to %s (%s) from %s, %d hops max, %s probes", algo, host, dst,
		probe.Source(p), o.maxTTL, proto)
}

// JSON output types.
type jsonReply struct {
	Addr  string             `json:"addr"`
	Name  string             `json:"name,omitempty"`
	RTTms float64            `json:"rtt_ms"`
	Kind  string             `json:"kind"`
	Type  int                `json:"icmp_type"`
	Code  int                `json:"icmp_code"`
	MPLS  []packet.MPLSLabel `json:"mpls,omitempty"`
}

func toJSONReply(r *probe.Reply, names *resolver) *jsonReply {
	if r == nil {
		return nil
	}
	a := r.Addr.String()
	return &jsonReply{Addr: a, Name: names.name(a), RTTms: ms(r.RTT), Kind: r.Kind.String(),
		Type: r.Type, Code: r.Code, MPLS: r.MPLS}
}

func runParis(ctx context.Context, p probe.Prober, o options, host string, dst net.IP, proto packet.Proto, names *resolver) (bool, error) {
	v6 := dst.To4() == nil
	po := tracer.ParisOptions{
		FirstTTL:        o.firstTTL,
		MaxTTL:          o.maxTTL,
		Queries:         o.queries,
		MaxUndiscovered: o.maxUndisc,
		Flow:            uint16(o.flow),
	}
	var onHop func(tracer.Hop)
	if !o.jsonOut {
		fmt.Println(header("paris-traceroute", host, dst, p, proto, o) + fmt.Sprintf(", flow %d", o.flow))
		onHop = func(h tracer.Hop) {
			var b strings.Builder
			fmt.Fprintf(&b, "%2d ", h.TTL)
			last := ""
			for _, r := range h.Replies {
				if r == nil {
					b.WriteString(" *")
					continue
				}
				if a := r.Addr.String(); a != last {
					fmt.Fprintf(&b, " %s", names.label(a))
					last = a
				}
				fmt.Fprintf(&b, "  %.3f ms%s%s", ms(r.RTT), annotation(r, v6), mplsString(r.MPLS))
			}
			fmt.Println(b.String())
		}
	}
	hops, reached, err := tracer.Paris(ctx, p, dst, po, onHop)
	heard := false // did any router, or a destination one hop away, answer?
	for i, h := range hops {
		for _, r := range h.Replies {
			heard = heard || r != nil && (r.Kind == packet.TimeExceeded || i == 0)
		}
	}
	if o.jsonOut {
		type jsonHop struct {
			TTL     int          `json:"ttl"`
			Replies []*jsonReply `json:"replies"`
		}
		out := struct {
			Algorithm string    `json:"algorithm"`
			Host      string    `json:"host"`
			Dst       string    `json:"dst"`
			Src       string    `json:"src"`
			Protocol  string    `json:"protocol"`
			Flow      int       `json:"flow"`
			Reached   bool      `json:"reached"`
			Hops      []jsonHop `json:"hops"`
		}{"paris", host, dst.String(), probe.Source(p).String(), proto.String(), o.flow, reached, []jsonHop{}}
		for _, h := range hops {
			jh := jsonHop{TTL: h.TTL}
			for _, r := range h.Replies {
				jh.Replies = append(jh.Replies, toJSONReply(r, names))
			}
			out.Hops = append(out.Hops, jh)
		}
		if jerr := printJSON(out); jerr != nil {
			return heard, jerr
		}
	}
	return heard, err
}

func runMDA(ctx context.Context, p probe.Prober, o options, host string, dst net.IP, proto packet.Proto, names *resolver) (bool, error) {
	v6 := dst.To4() == nil
	mo := tracer.MDAOptions{
		FirstTTL:        o.firstTTL,
		MaxTTL:          o.maxTTL,
		MaxUndiscovered: o.maxUndisc,
		Confidence:      o.confidence / 100,
		Parallel:        o.parallel,
		Retries:         o.retries,
		MaxBranch:       o.maxBranch,
		MaxChildren:     o.maxChild,
	}
	if o.srcPort != 0 {
		mo.MaxFlows = min(0x10000-o.srcPort, probe.MaxFlow+1)
	}
	var onHop func(tracer.MDAHop)
	if !o.jsonOut {
		fmt.Println(header("mda", host, dst, p, proto, o) + fmt.Sprintf(", confidence %g%%", o.confidence))
		onHop = func(h tracer.MDAHop) {
			for i, ifc := range h.Interfaces {
				prefix := "   "
				if i == 0 {
					prefix = fmt.Sprintf("%2d ", h.TTL)
				}
				fmt.Println(prefix + " " + interfaceLine(ifc, names, v6))
			}
		}
	}
	res, err := tracer.MDA(ctx, p, dst, mo, onHop)
	if res == nil {
		return false, err
	}
	heard := false
	for i, h := range res.Hops {
		for _, ifc := range h.Interfaces {
			for _, r := range ifc.Replies {
				heard = heard || r.Kind == packet.TimeExceeded || i == 0
			}
		}
	}
	if o.jsonOut {
		type jsonIface struct {
			Addr     string       `json:"addr"`
			Name     string       `json:"name,omitempty"`
			Terminal bool         `json:"terminal"`
			Replies  []*jsonReply `json:"replies"`
		}
		type jsonHop struct {
			TTL        int         `json:"ttl"`
			Interfaces []jsonIface `json:"interfaces"`
		}
		out := struct {
			Algorithm  string        `json:"algorithm"`
			Host       string        `json:"host"`
			Dst        string        `json:"dst"`
			Src        string        `json:"src"`
			Protocol   string        `json:"protocol"`
			Confidence float64       `json:"confidence"`
			Reached    bool          `json:"reached"`
			Probes     int           `json:"probes"`
			Hops       []jsonHop     `json:"hops"`
			Links      []tracer.Link `json:"links"`
		}{"mda", host, dst.String(), probe.Source(p).String(), proto.String(), o.confidence,
			res.Reached, res.Probes, []jsonHop{}, res.Links}
		for _, h := range res.Hops {
			jh := jsonHop{TTL: h.TTL}
			for _, ifc := range h.Interfaces {
				ji := jsonIface{Addr: ifc.Addr, Name: names.name(ifc.Addr), Terminal: ifc.Terminal, Replies: []*jsonReply{}}
				for _, r := range ifc.Replies {
					ji.Replies = append(ji.Replies, toJSONReply(r, names))
				}
				jh.Interfaces = append(jh.Interfaces, ji)
			}
			out.Hops = append(out.Hops, jh)
		}
		if jerr := printJSON(out); jerr != nil {
			return heard, jerr
		}
		return heard, err
	}

	fmt.Println("\nLinks:")
	for _, h := range res.Hops {
		for _, ifc := range h.Interfaces {
			succ := res.Successors(h.TTL, ifc.Addr)
			if len(succ) == 0 {
				continue
			}
			fmt.Printf("%2d  %s -> %s\n", h.TTL, ifc.Addr, strings.Join(succ, ", "))
		}
	}
	fmt.Printf("\n%d probes sent, destination %s\n", res.Probes, map[bool]string{true: "reached", false: "not reached"}[res.Reached])
	return heard, err
}

func interfaceLine(ifc *tracer.Interface, names *resolver, v6 bool) string {
	if ifc.Addr == tracer.Star {
		return "*"
	}
	var minRTT, maxRTT, total time.Duration
	for i, r := range ifc.Replies {
		if i == 0 || r.RTT < minRTT {
			minRTT = r.RTT
		}
		if r.RTT > maxRTT {
			maxRTT = r.RTT
		}
		total += r.RTT
	}
	s := names.label(ifc.Addr)
	if n := len(ifc.Replies); n > 0 {
		r := ifc.Replies[0]
		s += fmt.Sprintf("  %.3f/%.3f/%.3f ms%s%s", ms(minRTT), ms(total/time.Duration(n)), ms(maxRTT),
			annotation(r, v6), mplsString(r.MPLS))
	}
	return s
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
