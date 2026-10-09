package main

import (
	"io"
	"testing"
)

func TestParseArgs(t *testing.T) {
	o, host, err := parseArgs([]string{"-a", "mda", "example.com", "--protocol", "icmp", "-n", "--max-ttl=20", "-6"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || o.algo != "mda" || o.proto != "icmp" || !o.numeric || o.maxTTL != 20 || !o.ipv6 {
		t.Fatalf("unexpected options %+v host %q", o, host)
	}
	if o.queries != 3 || o.wait != 3 || o.confidence != 95 || o.retries != 2 {
		t.Fatalf("bad defaults %+v", o)
	}
}

func TestParseArgsErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"a", "b"},
		{"-4", "-6", "host"},
		{"-f", "5", "-m", "4", "host"},
		{"-p", "70000", "host"},
		{"-c", "100", "host"},
		{"-S", "10.0.0.1", "-i", "eth0", "host"},
		{"--bogus", "host"},
	} {
		if _, _, err := parseArgs(args, io.Discard); err == nil {
			t.Errorf("%q: expected an error", args)
		}
	}
}

func TestVersionNeedsNoHost(t *testing.T) {
	o, _, err := parseArgs([]string{"--version"}, io.Discard)
	if err != nil || !o.showVer {
		t.Fatalf("err=%v showVer=%v", err, o.showVer)
	}
}
func TestOriginalShortcuts(t *testing.T) {
	o, _, err := parseArgs([]string{"-T", "-B", "99,8,64", "-z", "50", "host"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.proto != "tcp" || o.confidence != 99 || o.maxBranch != 8 || o.maxChild != 64 || o.delay != 0.05 {
		t.Fatalf("unexpected options %+v", o)
	}
	o, _, err = parseArgs([]string{"-U", "host"}, io.Discard)
	if err != nil || o.proto != "udp" || o.dstPort != 53 {
		t.Fatalf("-U: %+v %v", o, err)
	}
	o, _, err = parseArgs([]string{"-B", "90", "-I", "host"}, io.Discard)
	if err != nil || o.proto != "icmp" || o.confidence != 90 || o.maxBranch != 0 {
		t.Fatalf("-B 90 -I: %+v %v", o, err)
	}
	for _, args := range [][]string{{"-I", "-T", "h"}, {"-B", "x", "h"}, {"-B", "95,0", "h"}, {"-z", "-1", "h"}} {
		if _, _, err := parseArgs(args, io.Discard); err == nil {
			t.Errorf("%q: expected an error", args)
		}
	}
}
