package tracer

import (
	"context"
	"errors"
	"net"
	"slices"
	"sort"
	"sync"

	"github.com/akprof2000/paris-traceroute-go/internal/probe"
)

// Star is the address used for interfaces that did not answer.
const Star = "*"

// MDAOptions configures the Multipath Detection Algorithm.
type MDAOptions struct {
	FirstTTL        int
	MaxTTL          int
	MaxUndiscovered int     // stop after this many consecutive silent hops
	Confidence      float64 // e.g. 0.95
	MaxBranch       int     // number of hypothesis tests sharing 1-Confidence
	Parallel        int     // probes in flight
	Retries         int     // extra attempts for unanswered probes
	MaxFlows        int     // flow identifiers available
}

func (o *MDAOptions) defaults() {
	if o.FirstTTL < 1 {
		o.FirstTTL = 1
	}
	if o.MaxTTL < o.FirstTTL {
		o.MaxTTL = 30
	}
	if o.MaxUndiscovered < 1 {
		o.MaxUndiscovered = 3
	}
	if o.Confidence <= 0 || o.Confidence >= 1 {
		o.Confidence = 0.95
	}
	if o.MaxBranch < 1 {
		o.MaxBranch = DefaultMaxBranch
	}
	if o.Parallel < 1 {
		o.Parallel = 16
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	if o.MaxFlows < 1 || o.MaxFlows > probe.MaxFlow+1 {
		o.MaxFlows = probe.MaxFlow + 1
	}
}

// Interface is a node of the multipath graph: one address seen at one TTL.
type Interface struct {
	TTL      int
	Addr     string // Star for unanswered probes
	Replies  []*probe.Reply
	Terminal bool // the destination, or a node that reported it unreachable
}

// Link connects an interface at TTL to an interface at TTL+1.
type Link struct {
	TTL  int    `json:"ttl"`
	From string `json:"from"`
	To   string `json:"to"`
}

// MDAHop lists the interfaces found at one TTL in discovery order.
type MDAHop struct {
	TTL        int
	Interfaces []*Interface
}

// MDAResult is the multipath graph discovered by MDA.
type MDAResult struct {
	Hops    []MDAHop
	Links   []Link
	Reached bool
	Probes  int
}

// Successors returns the addresses linked from addr at ttl.
func (r *MDAResult) Successors(ttl int, addr string) []string {
	var out []string
	for _, l := range r.Links {
		if l.TTL == ttl && l.From == addr {
			out = append(out, l.To)
		}
	}
	return out
}

type mdaState struct {
	ctx context.Context
	p   probe.Prober
	dst net.IP
	o   MDAOptions
	nk  []int

	mu       sync.Mutex
	nextFlow int
	at       map[int]map[uint16]string // ttl -> flow -> interface address
	ifaces   map[int]map[string]*Interface
	order    map[int][]string
	probes   int
}

var errFlowsExhausted = errors.New("flow identifiers exhausted")

// MDA discovers all load-balanced paths towards dst, hop by hop, with the
// Multipath Detection Algorithm of Augustin et al. onHop, if not nil, is
// called when a hop is complete.
func MDA(ctx context.Context, p probe.Prober, dst net.IP, o MDAOptions, onHop func(MDAHop)) (*MDAResult, error) {
	o.defaults()
	m := &mdaState{
		ctx:    ctx,
		p:      p,
		dst:    dst,
		o:      o,
		nk:     StoppingPoints(o.Confidence, o.MaxBranch, 128),
		at:     make(map[int]map[uint16]string),
		ifaces: make(map[int]map[string]*Interface),
		order:  make(map[int][]string),
	}
	res := &MDAResult{}
	prev := []string{""} // the source: every flow goes through it
	silent := 0
	exhausted := false
	for ttl := o.FirstTTL; ttl <= o.MaxTTL && !exhausted; ttl++ {
		done := map[string]bool{}
		queue := append([]string(nil), prev...)
		for i := 0; i < len(queue); i++ {
			v := queue[i]
			done[v] = true
			err := m.expand(ttl, v)
			if errors.Is(err, errFlowsExhausted) {
				exhausted = true
				break
			}
			if err != nil {
				return m.result(res), err
			}
			// Node control at ttl-1 may have revealed new interfaces there.
			for _, a := range m.order[ttl-1] {
				if a != Star && !done[a] && !contains(queue, a) && !m.ifaces[ttl-1][a].Terminal {
					queue = append(queue, a)
				}
			}
		}

		hop := MDAHop{TTL: ttl}
		var next []string
		answered := false
		for _, a := range m.order[ttl] {
			ifc := m.ifaces[ttl][a]
			hop.Interfaces = append(hop.Interfaces, ifc)
			if a != Star {
				answered = true
			}
			if ifc.Terminal {
				if a == dst.String() {
					res.Reached = true
				}
			} else {
				next = append(next, a)
			}
		}
		if onHop != nil {
			onHop(hop)
		}
		if answered {
			// Unanswered probes say nothing about the topology; carry on
			// from the interfaces that did answer.
			next = slices.DeleteFunc(next, func(a string) bool { return a == Star })
		}
		if len(next) == 0 {
			break
		}
		if answered {
			silent = 0
		} else if silent++; silent >= o.MaxUndiscovered {
			break
		}
		prev = next
	}
	return m.result(res), nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (m *mdaState) stop(k int) int {
	if k < 1 {
		k = 1
	}
	if k >= len(m.nk) {
		k = len(m.nk) - 1
	}
	return m.nk[k]
}

// flowsThrough returns the flows known to reach v at ttl, and those of
// them already probed at ttl+1.
func (m *mdaState) flowsThrough(ttl int, v string) (all, probedNext []uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for f, a := range m.at[ttl] {
		if a == v {
			all = append(all, f)
			if _, ok := m.at[ttl+1][f]; ok {
				probedNext = append(probedNext, f)
			}
		}
	}
	return
}

// expand discovers the successors at ttl of interface v at ttl-1 (v == ""
// is the source).
func (m *mdaState) expand(ttl int, v string) error {
	controlled := 0 // flows generated by node control for v
	for {
		var through, probed []uint16
		if v == "" {
			// Every flow leaves the source.
			m.mu.Lock()
			for f := range m.at[ttl] {
				probed = append(probed, f)
			}
			m.mu.Unlock()
		} else {
			through, probed = m.flowsThrough(ttl-1, v)
		}
		succ := map[string]bool{}
		m.mu.Lock()
		for _, f := range probed {
			if a := m.at[ttl][f]; a != Star {
				succ[a] = true
			}
		}
		m.mu.Unlock()
		need := m.stop(len(succ))
		if len(probed) >= need {
			return nil
		}
		missing := need - len(probed)

		var candidates []uint16
		for _, f := range through {
			if !contains16(probed, f) {
				candidates = append(candidates, f)
			}
		}
		if len(candidates) < missing {
			more, err := m.moreFlows(ttl-1, v, missing-len(candidates), &controlled, need)
			if err != nil {
				return err
			}
			if len(more) == 0 && len(candidates) == 0 {
				return nil // cannot steer more flows through v
			}
			candidates = append(candidates, more...)
		}
		if len(candidates) > missing {
			candidates = candidates[:missing]
		}
		if err := m.probeMany(ttl, candidates); err != nil {
			return err
		}
	}
}

func contains16(s []uint16, v uint16) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// moreFlows returns up to n new flows going through v at ttl.
func (m *mdaState) moreFlows(ttl int, v string, n int, controlled *int, need int) ([]uint16, error) {
	m.mu.Lock()
	single := len(m.order[ttl]) == 1 && m.order[ttl][0] == v
	m.mu.Unlock()
	if v == "" || single {
		// All flows go through v (the source, or the only interface at
		// ttl): no need to check.
		flows, err := m.newFlows(n)
		if err != nil {
			return nil, err
		}
		if v != "" {
			m.mu.Lock()
			for _, f := range flows {
				m.at[ttl][f] = v
			}
			m.mu.Unlock()
		}
		return flows, nil
	}

	// Node control: probe new flows at ttl until enough of them hit v.
	limit := 4*need + 16
	var out []uint16
	for len(out) < n && *controlled < limit {
		m.mu.Lock()
		width := len(m.order[ttl])
		m.mu.Unlock()
		batch := min((n-len(out))*max(width, 1), limit-*controlled)
		flows, err := m.newFlows(batch)
		if err != nil {
			return out, err
		}
		*controlled += batch
		known := m.known(ttl)
		if err := m.probeMany(ttl, flows); err != nil {
			return out, err
		}
		var fresh []uint16
		m.mu.Lock()
		for _, f := range flows {
			a := m.at[ttl][f]
			if a == v {
				out = append(out, f)
			}
			if !known[a] {
				fresh = append(fresh, f)
				known[a] = true
			}
		}
		m.mu.Unlock()
		// A new interface at ttl: find its predecessor too.
		if ttl-1 >= m.o.FirstTTL && len(fresh) > 0 {
			if err := m.probeMany(ttl-1, fresh); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func (m *mdaState) known(ttl int) map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := map[string]bool{}
	for _, a := range m.order[ttl] {
		k[a] = true
	}
	return k
}

func (m *mdaState) newFlows(n int) ([]uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nextFlow+n > m.o.MaxFlows {
		n = m.o.MaxFlows - m.nextFlow
	}
	if n <= 0 {
		return nil, errFlowsExhausted
	}
	out := make([]uint16, n)
	for i := range out {
		out[i] = uint16(m.nextFlow)
		m.nextFlow++
	}
	return out, nil
}

// probeMany probes every flow at ttl, Parallel at a time, and records the
// interfaces reached.
func (m *mdaState) probeMany(ttl int, flows []uint16) error {
	sem := make(chan struct{}, m.o.Parallel)
	errc := make(chan error, len(flows))
	var wg sync.WaitGroup
	for _, f := range flows {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			// Routers rate-limit ICMP errors: retry before concluding
			// that nothing answers on this flow.
			var r *probe.Reply
			var err error
			for try := 0; try <= m.o.Retries && r == nil; try++ {
				m.mu.Lock()
				m.probes++
				m.mu.Unlock()
				if r, err = m.p.Probe(m.ctx, ttl, f); err != nil {
					errc <- err
					return
				}
			}
			m.record(ttl, f, r)
		}()
	}
	wg.Wait()
	close(errc)
	return <-errc
}

func (m *mdaState) record(ttl int, f uint16, r *probe.Reply) {
	addr := Star
	if r != nil {
		addr = r.Addr.String()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at[ttl] == nil {
		m.at[ttl] = make(map[uint16]string)
		m.ifaces[ttl] = make(map[string]*Interface)
	}
	m.at[ttl][f] = addr
	ifc := m.ifaces[ttl][addr]
	if ifc == nil {
		ifc = &Interface{TTL: ttl, Addr: addr}
		m.ifaces[ttl][addr] = ifc
		m.order[ttl] = append(m.order[ttl], addr)
	}
	if r != nil {
		ifc.Replies = append(ifc.Replies, r)
		ifc.Terminal = ifc.Terminal || IsTerminal(r, m.dst)
	}
}

func (m *mdaState) result(res *MDAResult) *MDAResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	res.Probes = m.probes
	res.Hops = res.Hops[:0]
	seen := map[Link]bool{}
	for ttl := m.o.FirstTTL; ttl <= m.o.MaxTTL; ttl++ {
		if len(m.order[ttl]) == 0 {
			break
		}
		hop := MDAHop{TTL: ttl}
		for _, a := range m.order[ttl] {
			hop.Interfaces = append(hop.Interfaces, m.ifaces[ttl][a])
		}
		res.Hops = append(res.Hops, hop)
		for _, a := range m.order[ttl] {
			for f, b := range m.at[ttl+1] {
				if m.at[ttl][f] != a {
					continue
				}
				l := Link{TTL: ttl, From: a, To: b}
				if a == Star && b == Star {
					continue // says nothing about the topology
				}
				if !seen[l] {
					seen[l] = true
					res.Links = append(res.Links, l)
				}
			}
		}
	}
	sort.SliceStable(res.Links, func(i, j int) bool {
		a, b := res.Links[i], res.Links[j]
		if a.TTL != b.TTL {
			return a.TTL < b.TTL
		}
		return m.rank(a.TTL, a.From)*1e6+m.rank(a.TTL+1, a.To) < m.rank(b.TTL, b.From)*1e6+m.rank(b.TTL+1, b.To)
	})
	return res
}

// rank returns the discovery index of addr at ttl.
func (m *mdaState) rank(ttl int, addr string) int {
	for i, a := range m.order[ttl] {
		if a == addr {
			return i
		}
	}
	return len(m.order[ttl])
}
