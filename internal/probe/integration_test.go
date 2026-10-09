package probe

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/akprof2000/paris-traceroute-go/internal/packet"
)

// These tests send real probes to the loopback interface. They need raw
// sockets and are skipped without the privileges for them (run them as
// root on Linux, or from an elevated prompt on Windows).

func newLoopback(t *testing.T, proto packet.Proto, dst string) Prober {
	t.Helper()
	if proto == packet.TCP && !tcpSupported {
		t.Skip("TCP probes are not supported on " + runtime.GOOS)
	}
	if !canReceiveICMPErrors() {
		t.Skip("not elevated: ICMP errors are not delivered to raw sockets")
	}
	if proto == packet.UDP && runtime.GOOS == "windows" {
		// Windows answers UDP to a closed loopback port without an ICMP
		// port unreachable message, so there is nothing to receive.
		t.Skip("no ICMP port unreachable on the Windows loopback")
	}
	ip := net.ParseIP(dst)
	p, err := New(Config{Proto: proto, Dst: ip, Timeout: time.Second})
	if errors.Is(err, ErrPermission) {
		t.Skip("raw sockets need privileges: ", err)
	}
	if err != nil {
		if ip.To4() == nil {
			t.Skip("no IPv6 loopback: ", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestLoopbackReplies(t *testing.T) {
	cases := []struct {
		proto packet.Proto
		kind  packet.Kind
	}{
		{packet.UDP, packet.DestUnreachable},
		{packet.ICMP, packet.EchoReply},
		{packet.TCP, packet.TCPReply},
	}
	for _, dst := range []string{"127.0.0.1", "::1"} {
		for _, c := range cases {
			t.Run(c.proto.String()+"/"+dst, func(t *testing.T) {
				p := newLoopback(t, c.proto, dst)
				r, err := p.Probe(context.Background(), 1, 0)
				if err != nil {
					t.Fatal(err)
				}
				if r == nil {
					t.Fatal("no reply from the loopback")
				}
				if !r.Addr.Equal(net.ParseIP(dst)) || r.Kind != c.kind {
					t.Fatalf("reply %+v, want %v from %s", r, c.kind, dst)
				}
				// Zero is possible: the Windows clock is coarser than a loopback RTT.
				if r.RTT < 0 || r.RTT > time.Second {
					t.Fatalf("implausible RTT %v", r.RTT)
				}
			})
		}
	}
}

// Many probes in flight on many flows must each get their own reply.
func TestLoopbackConcurrentFlows(t *testing.T) {
	for _, proto := range []packet.Proto{packet.UDP, packet.ICMP, packet.TCP} {
		t.Run(proto.String(), func(t *testing.T) {
			p := newLoopback(t, proto, "127.0.0.1")
			const n = 64
			var wg sync.WaitGroup
			var mu sync.Mutex
			answered := 0
			for f := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					r, err := p.Probe(context.Background(), 8, uint16(f))
					if err != nil {
						t.Error(err)
						return
					}
					if r != nil {
						mu.Lock()
						answered++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			// Kernels rate-limit ICMP errors (UDP port unreachable), so
			// require most, not all, of them.
			if answered < n/2 {
				t.Fatalf("%d of %d probes answered", answered, n)
			}
		})
	}
}

func TestPermissionErrorIsReported(t *testing.T) {
	_, err := New(Config{Proto: packet.ICMP, Dst: net.ParseIP("127.0.0.1")})
	if err == nil {
		t.Skip("running with raw socket privileges")
	}
	if runtime.GOOS == "linux" && !errors.Is(err, ErrPermission) {
		t.Fatalf("error %v does not wrap ErrPermission", err)
	}
}
