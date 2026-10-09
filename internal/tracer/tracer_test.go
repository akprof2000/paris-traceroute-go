package tracer

import (
	"context"
	"hash/fnv"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/akprof2000/paris-traceroute-go/internal/packet"
	"github.com/akprof2000/paris-traceroute-go/internal/probe"
)

// simNet is a simulated network of per-flow load balancers. next maps a
// router to its successors; the successor taken by a flow is chosen by
// hashing the flow and the router, like a per-flow load balancer would.
type simNet struct {
	src    string
	dst    string
	next   map[string][]string
	silent map[string]bool // routers that never answer

	mu     sync.Mutex
	probes int
}

func (s *simNet) Probe(_ context.Context, ttl int, flow uint16) (*probe.Reply, error) {
	s.mu.Lock()
	s.probes++
	s.mu.Unlock()
	node := s.src
	for range ttl {
		succ := s.next[node]
		if len(succ) == 0 {
			break // the destination answers every TTL beyond its distance
		}
		h := fnv.New32a()
		h.Write([]byte{byte(flow >> 8), byte(flow)})
		h.Write([]byte(node))
		node = succ[h.Sum32()%uint32(len(succ))]
	}
	if s.silent[node] {
		return nil, nil
	}
	r := &probe.Reply{Addr: net.ParseIP(node), RTT: time.Millisecond, Kind: packet.TimeExceeded}
	if node == s.dst {
		r.Kind = packet.DestUnreachable
		r.Code = 3
	}
	return r, nil
}

func (s *simNet) Close() error { return nil }

func TestStoppingPoints(t *testing.T) {
	nk := StoppingPoints(0.95, DefaultMaxBranch, 5)
	want := []int{9, 9, 17, 24, 32, 40}
	for k := range want {
		if nk[k] != want[k] {
			t.Fatalf("n_k = %v, want %v", nk, want)
		}
	}
}

func TestParisFixedFlowFollowsOnePath(t *testing.T) {
	n := &simNet{
		src: "0.0.0.0", dst: "10.0.9.9",
		next: map[string][]string{
			"0.0.0.0":  {"10.0.0.1"},
			"10.0.0.1": {"10.0.1.1", "10.0.1.2", "10.0.1.3"},
			"10.0.1.1": {"10.0.2.1"},
			"10.0.1.2": {"10.0.2.2"},
			"10.0.1.3": {"10.0.2.1"},
			"10.0.2.1": {"10.0.9.9"},
			"10.0.2.2": {"10.0.9.9"},
		},
	}
	hops, reached, err := Paris(context.Background(), n, net.ParseIP(n.dst), ParisOptions{Queries: 3, Flow: 7}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reached || len(hops) != 4 {
		t.Fatalf("reached=%v hops=%d", reached, len(hops))
	}
	for _, h := range hops {
		for _, r := range h.Replies[1:] {
			if !r.Addr.Equal(h.Replies[0].Addr) {
				t.Fatalf("ttl %d: one flow went through %v and %v", h.TTL, h.Replies[0].Addr, r.Addr)
			}
		}
	}
	// Consecutive hops must be adjacent: no false links.
	prev := n.src
	for _, h := range hops {
		cur := h.Replies[0].Addr.String()
		ok := false
		for _, s := range n.next[prev] {
			ok = ok || s == cur
		}
		if !ok {
			t.Fatalf("false link %s -> %s", prev, cur)
		}
		prev = cur
	}
}

func TestParisStopsAfterSilentHops(t *testing.T) {
	n := &simNet{
		src: "0.0.0.0", dst: "10.0.9.9",
		next: map[string][]string{
			"0.0.0.0": {"10.0.0.1"}, "10.0.0.1": {"10.0.0.2"}, "10.0.0.2": {"10.0.0.3"},
			"10.0.0.3": {"10.0.0.4"}, "10.0.0.4": {"10.0.0.5"}, "10.0.0.5": {"10.0.9.9"},
		},
		silent: map[string]bool{"10.0.0.2": true, "10.0.0.3": true, "10.0.0.4": true, "10.0.0.5": true},
	}
	hops, reached, err := Paris(context.Background(), n, net.ParseIP(n.dst), ParisOptions{MaxUndiscovered: 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reached || len(hops) != 4 {
		t.Fatalf("reached=%v hops=%d, want 4 hops", reached, len(hops))
	}
}

func linkSet(ls []Link) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.From+">"+l.To)
	}
	sort.Strings(out)
	return out
}

func TestMDADiscoversAllPaths(t *testing.T) {
	// Hop 2 has 4 load-balanced interfaces, which reconverge at hop 3 on
	// two routers; one of them balances again at hop 4.
	n := &simNet{
		src: "0.0.0.0", dst: "10.0.9.9",
		next: map[string][]string{
			"0.0.0.0":  {"10.0.0.1"},
			"10.0.0.1": {"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"},
			"10.0.1.1": {"10.0.2.1"},
			"10.0.1.2": {"10.0.2.1"},
			"10.0.1.3": {"10.0.2.2"},
			"10.0.1.4": {"10.0.2.2"},
			"10.0.2.1": {"10.0.3.1"},
			"10.0.2.2": {"10.0.3.2", "10.0.3.3"},
			"10.0.3.1": {"10.0.9.9"},
			"10.0.3.2": {"10.0.9.9"},
			"10.0.3.3": {"10.0.9.9"},
		},
	}
	res, err := MDA(context.Background(), n, net.ParseIP(n.dst), MDAOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached {
		t.Fatal("destination not reached")
	}
	var want []string
	for from, succ := range n.next {
		if from == n.src {
			continue
		}
		for _, to := range succ {
			want = append(want, from+">"+to)
		}
	}
	sort.Strings(want)
	got := linkSet(res.Links)
	if len(got) != len(want) {
		t.Fatalf("links:\n got %v\nwant %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("links:\n got %v\nwant %v", got, want)
		}
	}
	widths := []int{1, 4, 2, 3, 1}
	for i, h := range res.Hops {
		if len(h.Interfaces) != widths[i] {
			t.Errorf("ttl %d: %d interfaces, want %d", h.TTL, len(h.Interfaces), widths[i])
		}
	}
	if res.Probes != n.probes {
		t.Errorf("probe count %d, simulator saw %d", res.Probes, n.probes)
	}
}

func TestMDASinglePathIsCheap(t *testing.T) {
	n := &simNet{
		src: "0.0.0.0", dst: "10.0.9.9",
		next: map[string][]string{
			"0.0.0.0": {"10.0.0.1"}, "10.0.0.1": {"10.0.0.2"}, "10.0.0.2": {"10.0.9.9"},
		},
	}
	res, err := MDA(context.Background(), n, net.ParseIP(n.dst), MDAOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached || len(res.Hops) != 3 {
		t.Fatalf("reached=%v hops=%d", res.Reached, len(res.Hops))
	}
	// n_1 probes per hop are enough to rule out load balancing.
	if res.Probes != 3*9 {
		t.Errorf("%d probes, want %d", res.Probes, 3*9)
	}
}

func TestMDAWithSilentRouter(t *testing.T) {
	n := &simNet{
		src: "0.0.0.0", dst: "10.0.9.9",
		next: map[string][]string{
			"0.0.0.0":  {"10.0.0.1"},
			"10.0.0.1": {"10.0.1.1", "10.0.1.2"},
			"10.0.1.1": {"10.0.2.1"},
			"10.0.1.2": {"10.0.2.1"},
			"10.0.2.1": {"10.0.9.9"},
		},
		silent: map[string]bool{"10.0.1.2": true},
	}
	res, err := MDA(context.Background(), n, net.ParseIP(n.dst), MDAOptions{Retries: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached {
		t.Fatal("destination not reached")
	}
	if res.Probes != n.probes {
		t.Errorf("probe count %d, simulator saw %d", res.Probes, n.probes)
	}
	got := map[string]bool{}
	for _, l := range linkSet(res.Links) {
		got[l] = true
	}
	for _, l := range []string{"10.0.0.1>10.0.1.1", "10.0.0.1>*", "10.0.1.1>10.0.2.1", "10.0.2.1>10.0.9.9"} {
		if !got[l] {
			t.Errorf("missing link %s in %v", l, linkSet(res.Links))
		}
	}
}
