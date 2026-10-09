package tracer

import "math"

// MDA stopping rule.
//
// When k next-hop interfaces of a node have been found, the MDA keeps
// sending probes (each on a new flow) until n_k probes have been sent, n_k
// being chosen so that, if the node actually had k+1 equally loaded next
// hops, the probability of stopping before seeing all of them is bounded.
//
// The computation follows libparistraceroute (bound.c, after Veitch et al.,
// "Failure control in multipath route tracing", INFOCOM 2009): the global
// failure probability 1-confidence is spread over at most maxBranch
// branching points, giving a per-node failure bound
// 1 - confidence^(1/maxBranch), and the stopping points are computed on the
// Markov chain of discovered interfaces, accounting for the probability of
// having already stopped at an earlier stopping point. With the defaults of
// the original tool (95%, 5 branching points) this gives
// n_1..n_5 = 8, 15, 21, 28, 36; with a single branching point (5% per
// node) it reproduces the classical table 6, 11, 16, 21, 27, 33.

// Defaults of the original paris-traceroute (-B 95,5,128).
const (
	DefaultMaxBranch   = 5
	DefaultMaxChildren = 128
)

// StoppingPoints returns n_k for k = 0..maxChildren-1: the number of probes
// after which a node with k known successors is considered fully explored.
// n_0 equals n_1.
func StoppingPoints(confidence float64, maxBranch, maxChildren int) []int {
	if confidence <= 0 || confidence >= 1 {
		confidence = 0.95
	}
	if maxBranch < 1 {
		maxBranch = DefaultMaxBranch
	}
	if maxChildren < 2 {
		maxChildren = DefaultMaxChildren
	}
	table := hypothesisTable(1-confidence, maxBranch, maxChildren)
	nk := make([]int, maxChildren)
	for k := 1; k < maxChildren; k++ {
		nk[k] = table[k+1] // hypothesis: k+1 interfaces
	}
	nk[0] = nk[1]
	return nk
}

// hypothesisTable is a port of bound_build: table[h] is the number of probes
// needed to reject the hypothesis that h interfaces exist when only h-1
// have been seen.
func hypothesisTable(failure float64, maxBranch, maxN int) []int {
	alpha := 1 - math.Pow(1-failure, 1/float64(maxBranch))
	nk := make([]int, maxN+1)
	pk := make([]float64, maxN+1)
	first := make([]float64, maxN)
	second := make([]float64, maxN)

	stop := func(jstart, h int, cur float64) bool {
		if jstart != h-1 {
			return false
		}
		sum := 0.0
		for i := 0; i <= jstart; i++ {
			sum += pk[i]
		}
		return sum+cur <= alpha
	}

	j := 0
	for h := 2; h <= maxN; h++ {
		for x := range first {
			first[x] = 0
		}
		second[0], second[1] = 0, 1
		cur := 1.0
		jstart := 2
		i := 1
		for ; !stop(jstart, h, cur); i++ {
			for j = jstart; j < h; j++ {
				cur = first[j]*float64(j)/float64(h) + second[j-1]*float64(h-j+1)/float64(h)
				if i+j-1 == nk[j+1] {
					jstart = j + 1
					second[j], first[j] = 0, 0
					pk[j+1] = cur
				} else {
					second[j] = cur
				}
			}
			if i == 1 {
				jstart = 1
			}
			first, second = second, first
		}
		nk[h] = i + j - 1 - 2
	}
	return nk
}
