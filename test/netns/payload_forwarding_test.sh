#!/bin/sh
set -eu

here=$(dirname "$(readlink -f "$0")")
OMCPROXY=${OMCPROXY:-$here/../../build/omcproxy}
GROUP4=239.77.77.77
GROUP6=ff0e::7777
PORT=9977

if [ -z "${IN_NS:-}" ]; then
    exec unshare -r -n env IN_NS=1 OMCPROXY="$OMCPROXY" "$(readlink -f "$0")"
fi

log=$(mktemp)
recv_out=$(mktemp)
proxy_pid=
recv_pid=
send_pid=

cleanup() {
    for pid in $recv_pid $send_pid $proxy_pid; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo "--- ip_mr_cache at failure ---"
    cat /proc/net/ip_mr_cache 2>/dev/null || true
    echo "--- ip6_mr_cache at failure ---"
    cat /proc/net/ip6_mr_cache 2>/dev/null || true
    echo "--- receiver output ---"
    cat "$recv_out" 2>/dev/null || true
    echo "--- omcproxy log ---"
    cat "$log"
    exit 1
}

sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.all.accept_local=1 net.ipv4.conf.default.accept_local=1

ip link add up0 type veth peer name up1
ip link add d1a type veth peer name d1b
ip link set lo up
for i in up0 up1 d1a d1b; do ip link set "$i" up; done
ip addr add 10.0.1.1/24 dev up0
ip addr add 10.0.1.2/24 dev up1
ip addr add 10.1.1.1/24 dev d1a
ip addr add 10.1.1.2/24 dev d1b
ip addr add fd00:1::1/64 dev up0
ip addr add fd00:1::2/64 dev up1
ip addr add fd00:2::1/64 dev d1a
ip addr add fd00:2::2/64 dev d1b
sleep 3

"$OMCPROXY" -v up0,d1a >"$log" 2>&1 &
proxy_pid=$!
sleep 2

python3 "$here/mcast_recv.py" d1b "$GROUP4" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 4
python3 "$here/mcast_send.py" up1 "$GROUP4" "$PORT" 30 0.5 &
send_pid=$!
wait "$recv_pid" || fail "no IPv4 payload forwarded from up1 to d1b"
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: IPv4 payload forwarded from upstream to downstream"

python3 "$here/mcast_recv.py" d1b "$GROUP6" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 4
python3 "$here/mcast_send.py" up1 "$GROUP6" "$PORT" 30 0.5 &
send_pid=$!
wait "$recv_pid" || fail "no IPv6 payload forwarded from up1 to d1b"
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: IPv6 payload forwarded from upstream to downstream"

echo "PASS"
