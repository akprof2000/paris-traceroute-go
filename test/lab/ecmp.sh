#!/bin/bash
# Autotest on a lab network of Linux network namespaces (run as root):
#
#   src --- r1 ==(3-way ECMP, L4 hash)== r2a | r2b | r2c --- r3 --- dst
#
# Checks that paris-traceroute keeps every probe of a flow on one path and
# that MDA finds the three load-balanced interfaces. With ORIG pointing to
# the original paris-traceroute binary, both tools are also compared.
#
# Usage: sudo PT=./paris-traceroute [ORIG=/path/to/original] test/lab/ecmp.sh
set -u
PT=${PT:-./paris-traceroute}
ORIG=${ORIG:-}
D=10.0.9.2
NS="src r1 r2a r2b r2c r3 dst"
fails=0

cleanup() { for n in $NS; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT
cleanup
for n in $NS; do ip netns add $n; done
link() { # ns1 if1 addr1 ns2 if2 addr2
	ip -n $1 link add $2 type veth peer name $5 netns $4
	ip -n $1 addr add $3 dev $2 && ip -n $1 link set $2 up
	ip -n $4 addr add $6 dev $5 && ip -n $4 link set $5 up
}
link src veth-r1  10.0.1.2/24 r1  veth-src 10.0.1.1/24
link r1  veth-r2a 10.0.2.1/24 r2a veth-r1  10.0.2.2/24
link r1  veth-r2b 10.0.3.1/24 r2b veth-r1  10.0.3.2/24
link r1  veth-r2c 10.0.4.1/24 r2c veth-r1  10.0.4.2/24
link r2a veth-r3  10.0.5.1/24 r3  veth-r2a 10.0.5.2/24
link r2b veth-r3  10.0.6.1/24 r3  veth-r2b 10.0.6.2/24
link r2c veth-r3  10.0.7.1/24 r3  veth-r2c 10.0.7.2/24
link r3  veth-dst 10.0.9.1/24 dst veth-r3  10.0.9.2/24
for n in $NS; do
	ip -n $n link set lo up
	ip netns exec $n sysctl -qw net.ipv4.ip_forward=1 net.ipv4.icmp_ratelimit=0 \
		net.ipv4.icmp_msgs_per_sec=100000 net.ipv4.icmp_msgs_burst=100000
done
ip netns exec r1 sysctl -qw net.ipv4.fib_multipath_hash_policy=1
ip -n src route add default via 10.0.1.1
ip -n r1 route add 10.0.9.0/24 nexthop via 10.0.2.2 nexthop via 10.0.3.2 nexthop via 10.0.4.2
ip -n r1 route add 10.0.5.0/24 via 10.0.2.2
ip -n r1 route add 10.0.6.0/24 via 10.0.3.2
ip -n r1 route add 10.0.7.0/24 via 10.0.4.2
for r in r2a:10.0.5.2:10.0.2.1 r2b:10.0.6.2:10.0.3.1 r2c:10.0.7.2:10.0.4.1; do
	IFS=: read n fwd back <<<"$r"
	ip -n $n route add 10.0.9.0/24 via $fwd
	ip -n $n route add 10.0.1.0/24 via $back
done
ip -n r3 route add 10.0.1.0/24 via 10.0.5.1
ip -n dst route add default via 10.0.9.1

in_src() { ip netns exec src "$@"; }
check() { # description, condition result
	if [ "$2" = 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}

for p in udp icmp tcp; do
	out=$(in_src $PT -n -w 1 -P $p $D)
	hop2=$(echo "$out" | awk '$1==2' | grep -oE '10\.0\.[234]\.2' | sort -u | wc -l)
	echo "$out" | grep -qE "^ 4  10\.0\.9\.2"
	check "paris $p reaches the destination at hop 4" $?
	[ "$hop2" = 1 ]
	check "paris $p: all probes of the flow cross one interface at hop 2" $?
done

# Different flows (source ports) must spread over the balanced paths.
seen=$(for f in $(seq 0 15); do in_src $PT -n -w 1 -m 2 -q 1 -F $f -s 40000 $D | awk '$1==2{print $2}'; done | sort -u | wc -l)
[ "$seen" = 3 ]
check "16 flows use all 3 balanced interfaces (saw $seen)" $?

for p in udp tcp; do
	out=$(in_src $PT -n -w 1 -a mda -P $p $D)
	n=$(echo "$out" | grep -E '^ 1  10\.0\.1\.1 -> ' | grep -oE '10\.0\.[234]\.2' | sort -u | wc -l)
	[ "$n" = 3 ]
	check "mda $p finds the 3 load-balanced interfaces" $?
	echo "$out" | grep -q "destination reached"
	check "mda $p reaches the destination" $?
done

if [ -n "$ORIG" ]; then
	same=0
	for sp in $(seq 40000 40015); do
		o=$(in_src $ORIG -n -w 1 -m 2 -q 1 -s $sp $D 2>&1 | awk '$1==2{print $2}')
		# The original sends to port 33456 (its help says 33457).
		g=$(in_src $PT -n -w 1 -m 2 -q 1 -p 33456 -s $sp $D | awk '$1==2{print $2}')
		[ "$o" = "$g" ] && same=$((same + 1))
	done
	[ "$same" = 16 ]
	check "same 5-tuple, same path as the original ($same/16)" $?
	o=$(in_src $ORIG -n -w 1 -a mda -m 6 $D 2>&1 | sed -n '/^Lattice/,$p' | grep -oE '10\.0\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
	g=$(in_src $PT -n -w 1 -a mda $D | sed -n '/^Links/,$p' | grep -oE '10\.0\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
	[ "$o" = "$g" ]
	check "mda finds the same interfaces as the original ($g)" $?
fi

echo "$fails failure(s)"
exit $((fails > 0))
