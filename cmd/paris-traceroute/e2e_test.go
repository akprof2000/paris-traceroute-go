package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// End-to-end tests run the real binary. PT_BIN selects a prebuilt binary;
// otherwise it is built with the go tool. Tests that need raw sockets are
// skipped without privileges. PT_E2E_HOST adds traces to a real host.

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func binary(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("PT_BIN"); b != "" {
		return b
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("set PT_BIN or install go")
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pt-e2e")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "paris-traceroute")
		if runtime.GOOS == "windows" {
			binPath += ".exe"
		}
		if b, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build: %v\n%s", err, b)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func runBin(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.String(), "raw sockets require") || strings.Contains(e.String(), "not running elevated") {
		t.Skip("raw sockets need privileges")
	}
	return o.String(), e.String(), code
}

func TestE2EUsageAndVersion(t *testing.T) {
	if _, _, code := runBin(t); code != 2 {
		t.Errorf("no host: exit %d, want 2", code)
	}
	out, _, code := runBin(t, "--version")
	if code != 0 || !strings.HasPrefix(out, "paris-traceroute ") {
		t.Errorf("--version: %q exit %d", out, code)
	}
	if _, _, code := runBin(t, "-a", "nope", "127.0.0.1"); code != 1 {
		t.Errorf("bad algorithm: exit %d, want 1", code)
	}
}

type parisJSON struct {
	Reached bool `json:"reached"`
	Hops    []struct {
		TTL     int `json:"ttl"`
		Replies []*struct {
			Addr string `json:"addr"`
			Kind string `json:"kind"`
		} `json:"replies"`
	} `json:"hops"`
}

func TestE2EParisLoopback(t *testing.T) {
	protos := []string{"udp", "icmp"}
	if runtime.GOOS != "windows" {
		protos = append(protos, "tcp")
	}
	for _, dst := range []string{"127.0.0.1", "::1"} {
		for _, proto := range protos {
			t.Run(proto+"/"+dst, func(t *testing.T) {
				out, stderr, code := runBin(t, "-j", "-n", "-w", "1", "-P", proto, dst)
				if code != 0 {
					if dst == "::1" {
						t.Skipf("no IPv6 loopback: %s", stderr)
					}
					t.Fatalf("exit %d: %s", code, stderr)
				}
				var res parisJSON
				if err := json.Unmarshal([]byte(out), &res); err != nil {
					t.Fatalf("bad JSON: %v\n%s", err, out)
				}
				if !res.Reached || len(res.Hops) != 1 || res.Hops[0].TTL != 1 {
					t.Fatalf("unexpected result %s", out)
				}
				for _, r := range res.Hops[0].Replies {
					if r != nil && r.Addr != dst {
						t.Fatalf("reply from %s, want %s", r.Addr, dst)
					}
				}
			})
		}
	}
}

func TestE2EMDALoopback(t *testing.T) {
	out, stderr, code := runBin(t, "-a", "mda", "-j", "-n", "-w", "1", "127.0.0.1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var res struct {
		Reached bool `json:"reached"`
		Probes  int  `json:"probes"`
		Hops    []struct {
			Interfaces []struct {
				Addr string `json:"addr"`
			} `json:"interfaces"`
		} `json:"hops"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if !res.Reached || len(res.Hops) != 1 || res.Probes < 8 {
		t.Fatalf("unexpected result %s", out)
	}
}

func TestE2ERealHost(t *testing.T) {
	host := os.Getenv("PT_E2E_HOST")
	if host == "" {
		t.Skip("set PT_E2E_HOST to trace a real host")
	}
	for _, args := range [][]string{
		{"-P", "udp"}, {"-P", "icmp"}, {"-a", "mda", "-P", "icmp"},
	} {
		args := append(args, "-j", "-n", "-w", "1", host)
		out, stderr, code := runBin(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, stderr)
		}
		if !strings.Contains(out, `"reached": true`) {
			t.Errorf("%v: destination not reached:\n%s", args, out)
		}
	}
}
