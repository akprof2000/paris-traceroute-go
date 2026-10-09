package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
)

// errUsage reports a command line without exactly one host.
var errUsage = errors.New("usage")

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	algo       string
	proto      string
	ipv4, ipv6 bool
	firstTTL   int
	maxTTL     int
	queries    int
	wait       float64
	dstPort    int
	srcPort    int
	srcAddr    string
	iface      string
	numeric    bool
	maxUndisc  int
	flow       int
	confidence float64
	parallel   int
	retries    int
	jsonOut    bool
	showVer    bool
}

const usageText = `Usage: paris-traceroute [options] host

Traces the route to host keeping the flow identifier of the probes constant,
so that per-flow load balancers do not distort the result (Paris traceroute),
or discovers every load-balanced path (MDA).

Algorithm and probes:
  -a, --algorithm NAME     paris (fixed flow, default) or mda (multipath)
  -P, --protocol NAME      udp (default), icmp or tcp
  -4, -6                   force IPv4 or IPv6
  -p, --dst-port PORT      destination port (default 33457 for udp, 80 for tcp)
  -s, --src-port PORT      base source port, flow f uses PORT+f (default: auto)
  -S, --source ADDR        source address
  -i, --interface NAME     use the address of this network interface
  -F, --flow-id N          flow identifier of the paris algorithm (default 0)

Tracing:
  -f, --first-ttl N        first TTL (default 1)
  -m, --max-ttl N          maximum TTL (default 30)
  -q, --queries N          probes per hop, paris algorithm (default 3)
  -w, --wait SECONDS       time to wait for a reply (default 3)
  -M, --max-undiscovered N stop after N consecutive silent hops (default 3)

MDA:
  -c, --confidence PCT     confidence level of the MDA stopping rule (default 95)
  -r, --retries N          extra attempts for unanswered probes (default 2)
      --parallel N         probes in flight (default 16)

Output:
  -n, --numeric            do not resolve addresses to host names
  -j, --json               print the result as JSON
  -V, --version            print the version and exit
  -h, --help               show this help

Raw sockets are used: run as root (or give the binary CAP_NET_RAW) on Linux,
and from an elevated prompt on Windows. TCP probes are not available on
Windows, which forbids sending TCP through raw sockets.
`

// parseArgs parses the command line. Options may follow the host, as with
// traceroute. Every option has a short and a long form.
func parseArgs(args []string, stderr io.Writer) (options, string, error) {
	var o options
	fs := flag.NewFlagSet("paris-traceroute", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }

	str := func(p *string, def string, names ...string) {
		for _, n := range names {
			fs.StringVar(p, n, def, "")
		}
	}
	num := func(p *int, def int, names ...string) {
		for _, n := range names {
			fs.IntVar(p, n, def, "")
		}
	}
	flt := func(p *float64, def float64, names ...string) {
		for _, n := range names {
			fs.Float64Var(p, n, def, "")
		}
	}
	bln := func(p *bool, names ...string) {
		for _, n := range names {
			fs.BoolVar(p, n, false, "")
		}
	}
	str(&o.algo, "paris", "a", "algorithm")
	str(&o.proto, "udp", "P", "protocol")
	bln(&o.ipv4, "4")
	bln(&o.ipv6, "6")
	num(&o.dstPort, 0, "p", "dst-port")
	num(&o.srcPort, 0, "s", "src-port")
	str(&o.srcAddr, "", "S", "source")
	str(&o.iface, "", "i", "interface")
	num(&o.flow, 0, "F", "flow-id")
	num(&o.firstTTL, 1, "f", "first-ttl")
	num(&o.maxTTL, 30, "m", "max-ttl")
	num(&o.queries, 3, "q", "queries")
	flt(&o.wait, 3, "w", "wait")
	num(&o.maxUndisc, 3, "M", "max-undiscovered")
	flt(&o.confidence, 95, "c", "confidence")
	num(&o.retries, 2, "r", "retries")
	num(&o.parallel, 16, "parallel")
	bln(&o.numeric, "n", "numeric")
	bln(&o.jsonOut, "j", "json")
	bln(&o.showVer, "V", "version")

	var hosts []string
	for {
		if err := fs.Parse(args); err != nil {
			return o, "", err
		}
		if fs.NArg() == 0 {
			break
		}
		hosts = append(hosts, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if o.showVer {
		return o, "", nil
	}
	if len(hosts) != 1 {
		fs.Usage()
		return o, "", errUsage
	}
	return o, hosts[0], o.validate()
}

func (o *options) validate() error {
	switch {
	case o.ipv4 && o.ipv6:
		return fmt.Errorf("-4 and -6 are mutually exclusive")
	case o.firstTTL < 1 || o.firstTTL > 255 || o.maxTTL < o.firstTTL || o.maxTTL > 255:
		return fmt.Errorf("TTLs must satisfy 1 <= first-ttl <= max-ttl <= 255")
	case o.queries < 1 || o.queries > 100:
		return fmt.Errorf("queries must be within 1..100")
	case o.wait <= 0:
		return fmt.Errorf("wait must be positive")
	case o.dstPort < 0 || o.dstPort > 0xffff || o.srcPort < 0 || o.srcPort > 0xffff:
		return fmt.Errorf("port out of range")
	case o.confidence <= 0 || o.confidence >= 100:
		return fmt.Errorf("confidence must be within 0..100 (exclusive)")
	case o.parallel < 1 || o.retries < 0 || o.maxUndisc < 1:
		return fmt.Errorf("parallel and max-undiscovered must be positive, retries non-negative")
	case o.srcAddr != "" && o.iface != "":
		return fmt.Errorf("--source and --interface are mutually exclusive")
	}
	return nil
}

func main() {
	o, host, err := parseArgs(os.Args[1:], os.Stderr)
	if err == flag.ErrHelp {
		os.Exit(0)
	}
	if err == errUsage {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "paris-traceroute:", err)
		os.Exit(2)
	}
	if o.showVer {
		fmt.Printf("paris-traceroute %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}
	if err := run(o, host); err != nil {
		fmt.Fprintln(os.Stderr, "paris-traceroute:", err)
		os.Exit(1)
	}
}
