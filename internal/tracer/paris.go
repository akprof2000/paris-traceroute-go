// Package tracer implements the Paris traceroute and MDA (Multipath
// Detection Algorithm) route tracing algorithms on top of a probe.Prober.
package tracer

import (
	"context"
	"net"
	"sync"

	"github.com/akprof2000/paris-traceroute-go/internal/packet"
	"github.com/akprof2000/paris-traceroute-go/internal/probe"
)

// Hop holds the replies received for one TTL. A nil entry is a probe that
// got no reply.
type Hop struct {
	TTL     int
	Replies []*probe.Reply
}

// ParisOptions configures the classic Paris traceroute algorithm.
type ParisOptions struct {
	FirstTTL        int
	MaxTTL          int
	Queries         int // probes per hop
	MaxUndiscovered int // stop after this many consecutive silent hops
	Flow            uint16
}

func (o *ParisOptions) defaults() {
	if o.FirstTTL < 1 {
		o.FirstTTL = 1
	}
	if o.MaxTTL < o.FirstTTL {
		o.MaxTTL = 30
	}
	if o.Queries < 1 {
		o.Queries = 3
	}
	if o.MaxUndiscovered < 1 {
		o.MaxUndiscovered = 3
	}
}

// IsTerminal reports whether a reply ends the trace: the destination
// answered, or a router reported the destination unreachable.
func IsTerminal(r *probe.Reply, dst net.IP) bool {
	return r != nil && (r.Kind != packet.TimeExceeded || r.Addr.Equal(dst))
}

// Paris traces the route to dst keeping the flow identifier constant, so
// that every probe follows the same path through per-flow load balancers.
// onHop, if not nil, is called as soon as each hop is complete. It returns
// the hops and whether the destination was reached.
func Paris(ctx context.Context, p probe.Prober, dst net.IP, o ParisOptions, onHop func(Hop)) ([]Hop, bool, error) {
	o.defaults()
	var hops []Hop
	silent := 0
	for ttl := o.FirstTTL; ttl <= o.MaxTTL; ttl++ {
		hop := Hop{TTL: ttl, Replies: make([]*probe.Reply, o.Queries)}
		errs := make([]error, o.Queries)
		var wg sync.WaitGroup
		for i := range o.Queries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hop.Replies[i], errs[i] = p.Probe(ctx, ttl, o.Flow)
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return hops, false, err
			}
		}
		hops = append(hops, hop)
		if onHop != nil {
			onHop(hop)
		}
		answered, done, reached := false, false, false
		for _, r := range hop.Replies {
			if r != nil {
				answered = true
				done = done || IsTerminal(r, dst)
				reached = reached || r.Addr.Equal(dst)
			}
		}
		if done {
			return hops, reached, nil
		}
		if answered {
			silent = 0
		} else if silent++; silent >= o.MaxUndiscovered {
			break
		}
	}
	return hops, false, nil
}
