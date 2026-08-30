#!/bin/sh
set -eu

here=$(dirname "$(readlink -f "$0")")
OMCPROXY=${OMCPROXY:-$here/../../build/omcproxy}
GROUP=239.88.88.88
GROUP6=ff0e::8888
PORT=9988

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
ip addr add 10.1.1.1/16 dev d1a
ip addr add 10.1.0.2/16 dev d1b
ip addr add fd00:1::1/64 dev up0
ip addr add fd00:1::2/64 dev up1
ip addr add fd00:2::1/64 dev d1a
ip addr add fd00:2::2/64 dev d1b
ip addr add fe80::1/64 dev d1b nodad
sleep 3

"$OMCPROXY" -v up0,d1a,strict >"$log" 2>&1 &
proxy_pid=$!
sleep 2

python3 "$here/mcast_recv.py" d1b "$GROUP" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 4
python3 "$here/mcast_send.py" up1 "$GROUP" "$PORT" 90 0.5 &
send_pid=$!
wait "$recv_pid" || fail "strict: no payload while this proxy is the querier"
recv_pid=
echo "ok: strict proxy forwards while it is the querier"

python3 "$here/mcast_query.py" d1b
sleep 2

python3 "$here/mcast_recv.py" d1b "$GROUP" "$PORT" 8 >"$recv_out" &
recv_pid=$!
if wait "$recv_pid"; then
    recv_pid=
    fail "strict: payload still forwarded after losing the querier election"
fi
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: strict proxy stops forwarding after losing the querier election"

python3 "$here/mcast_query.py" d1b 10 4
python3 "$here/mcast_recv.py" d1b "$GROUP" "$PORT" 25 >"$recv_out" &
recv_pid=$!
python3 "$here/mcast_send.py" up1 "$GROUP" "$PORT" 60 0.5 &
send_pid=$!
wait "$recv_pid" || fail "strict: no payload after the other querier expired"
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: strict proxy resumes forwarding after regaining the election"

python3 "$here/mcast_recv.py" d1b "$GROUP6" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 4
python3 "$here/mcast_send.py" up1 "$GROUP6" "$PORT" 120 0.5 &
send_pid=$!
wait "$recv_pid" || fail "strict: no IPv6 payload while this proxy is the MLD querier"
recv_pid=
echo "ok: strict proxy forwards IPv6 while it is the MLD querier"

python3 "$here/mcast_mld_query.py" d1b
sleep 2

python3 "$here/mcast_recv.py" d1b "$GROUP6" "$PORT" 8 >"$recv_out" &
recv_pid=$!
if wait "$recv_pid"; then
    recv_pid=
    fail "strict: IPv6 payload still forwarded after losing the MLD election"
fi
recv_pid=
echo "ok: strict proxy stops forwarding IPv6 after losing the MLD election"

python3 "$here/mcast_mld_query.py" d1b 1000 4
python3 "$here/mcast_recv.py" d1b "$GROUP6" "$PORT" 25 >"$recv_out" &
recv_pid=$!
wait "$recv_pid" || fail "strict: no IPv6 payload after the other MLD querier expired"
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: strict proxy resumes IPv6 forwarding after regaining the MLD election"

kill "$proxy_pid" 2>/dev/null || true
wait "$proxy_pid" 2>/dev/null || true
proxy_pid=

"$OMCPROXY" -v up0,d1a >"$log" 2>&1 &
proxy_pid=$!
sleep 2

python3 "$here/mcast_recv.py" d1b "$GROUP" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 4
python3 "$here/mcast_query.py" d1b
python3 "$here/mcast_send.py" up1 "$GROUP" "$PORT" 30 0.5 &
send_pid=$!
wait "$recv_pid" || fail "default: payload not forwarded after losing the querier election"
recv_pid=
echo "ok: default proxy keeps forwarding after losing the querier election"

echo "PASS"
