package probe

import (
	"context"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu    sync.Mutex
	times []time.Time
}

func (r *recorder) Probe(context.Context, int, uint16) (*Reply, error) {
	r.mu.Lock()
	r.times = append(r.times, time.Now())
	r.mu.Unlock()
	return nil, nil
}

func (r *recorder) Close() error { return nil }

func TestThrottleSpacesProbes(t *testing.T) {
	rec := &recorder{}
	p := Throttle(rec, 20*time.Millisecond)
	start := time.Now()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Probe(context.Background(), 1, 0)
		}()
	}
	wg.Wait()
	if d := time.Since(start); d < 75*time.Millisecond {
		t.Fatalf("5 probes 20ms apart took only %v", d)
	}
}

func TestThrottleCancel(t *testing.T) {
	p := Throttle(&recorder{}, time.Hour)
	p.Probe(context.Background(), 1, 0) // takes the first slot
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.Probe(ctx, 1, 0); err == nil {
		t.Fatal("expected a context error")
	}
}
