#!/bin/sh
set -eu

here=$(dirname "$(readlink -f "$0")")
OMCPROXY=${OMCPROXY:-$here/../../build/omcproxy}

if [ -z "${IN_NS:-}" ]; then
    exec unshare -r -n env IN_NS=1 OMCPROXY="$OMCPROXY" "$(readlink -f "$0")"
fi

log=$(mktemp)
proxy_pid=
joiner_pids=

cleanup() {
    for pid in $joiner_pids $proxy_pid; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo "--- up0 memberships at failure ---"
    ip maddr show dev up0 || true
    echo "--- omcproxy log ---"
    cat "$log"
    exit 1
}

sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.all.accept_local=1 net.ipv4.conf.default.accept_local=1
sysctl -qw net.ipv4.igmp_max_memberships=3

ip link add up0 type veth peer name up1
ip link add d1a type veth peer name d1b
ip link set lo up
for i in up0 up1 d1a d1b; do ip link set "$i" up; done
ip addr add 10.0.1.1/24 dev up0
ip addr add 10.0.1.2/24 dev up1
ip addr add 10.1.1.1/24 dev d1a
ip addr add 10.1.1.2/24 dev d1b
sleep 3

"$OMCPROXY" -v up0,d1a >"$log" 2>&1 &
proxy_pid=$!
sleep 2

for i in 1 2 3 4 5; do
    python3 "$here/mcast_join.py" d1b "239.90.90.$i" &
    joiner_pids="$joiner_pids $!"
done
sleep 6

for i in 1 2 3 4 5; do
    ip maddr show dev up0 | grep -q "239.90.90.$i" ||
        fail "upstream join for 239.90.90.$i missing although igmp_max_memberships=3"
done
echo "ok: all 5 upstream joins present with igmp_max_memberships=3"

echo "PASS"
