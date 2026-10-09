package tracer

// MDA stopping rule.
//
// When k next-hop interfaces of a node have been found, the MDA keeps
// sending probes (each on a new flow) until n_k probes have been sent, n_k
// being the smallest number of probes such that, if the node actually had
// k+1 equally loaded next hops, the probability of not having seen all of
// them is at most alpha.
//
// Following Veitch et al. ("Failure control in multipath route tracing",
// INFOCOM 2009) the global failure probability 1-confidence is shared among
// a fixed number of hypothesis tests; with 12 tests and 95% confidence
// this yields n_1..n_5 = 9, 17, 24, 32, 40 (n_1 = 9 and n_2 = 17 as in the
// original MDA papers).

// DefaultMaxBranch is the number of hypothesis tests the failure
// probability is shared among.
const DefaultMaxBranch = 12

// unseenProb returns the probability that n probes spread uniformly over K
// interfaces do not reach all of them.
func unseenProb(K, n int) float64 {
	// p[j] = probability that exactly j distinct interfaces have been seen.
	p := make([]float64, K+1)
	p[0] = 1
	for range n {
		for j := K; j >= 1; j-- {
			p[j] = p[j]*float64(j)/float64(K) + p[j-1]*float64(K-j+1)/float64(K)
		}
		p[0] = 0
	}
	return 1 - p[K]
}

// StoppingPoints returns n_k for k = 0..maxK (n_0 is unused and equals n_1).
func StoppingPoints(confidence float64, maxBranch, maxK int) []int {
	if confidence <= 0 || confidence >= 1 {
		confidence = 0.95
	}
	if maxBranch < 1 {
		maxBranch = DefaultMaxBranch
	}
	alpha := (1 - confidence) / float64(maxBranch)
	nk := make([]int, maxK+1)
	n := 1
	for k := 1; k <= maxK; k++ {
		for unseenProb(k+1, n) > alpha {
			n++
		}
		nk[k] = n
	}
	nk[0] = nk[1]
	return nk
}
