package probe

import (
	"context"
	"sync"
	"time"
)

// Throttle returns a Prober that starts probes at least interval apart.
func Throttle(p Prober, interval time.Duration) Prober {
	if interval <= 0 {
		return p
	}
	return &throttled{Prober: p, interval: interval}
}

type throttled struct {
	Prober
	interval time.Duration

	mu   sync.Mutex
	next time.Time
}

func (t *throttled) Probe(ctx context.Context, ttl int, flow uint16) (*Reply, error) {
	t.mu.Lock()
	now := time.Now()
	slot := t.next
	if slot.Before(now) {
		slot = now
	}
	t.next = slot.Add(t.interval)
	t.mu.Unlock()

	if wait := time.Until(slot); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return t.Prober.Probe(ctx, ttl, flow)
}
