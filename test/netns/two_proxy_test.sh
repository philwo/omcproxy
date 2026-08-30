#!/bin/sh
set -eu

here=$(dirname "$(readlink -f "$0")")
OMCPROXY=${OMCPROXY:-$here/../../build/omcproxy}
GROUP=239.77.77.77
PORT=9977

if [ -z "${IN_NS:-}" ]; then
    exec unshare -r -n env IN_NS=1 OMCPROXY="$OMCPROXY" "$(readlink -f "$0")"
fi

log_a=$(mktemp)
log_b=$(mktemp)
recv_out=$(mktemp)
proxy_a=
proxy_b=
recv_pid=
send_pid=

cleanup() {
    for pid in $recv_pid $send_pid $proxy_a $proxy_b; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo "--- receiver output ---"
    cat "$recv_out" 2>/dev/null || true
    echo "--- proxy A log ---"
    cat "$log_a"
    echo "--- proxy B log ---"
    cat "$log_b"
    exit 1
}

child='
    ip link set lo up
    until ip link show up0 >/dev/null 2>&1 && ip link show d0 >/dev/null 2>&1; do
        sleep 0.2
    done
    sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    ip link set up0 up
    ip link set d0 up
    ip addr add "$UPADDR" dev up0
    ip addr add "$DADDR" dev d0
    sleep 2
    exec "$OMCPROXY" -v up0,d0,strict
'

sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.all.accept_local=1 net.ipv4.conf.default.accept_local=1

unshare --net env UPADDR=10.0.1.1/24 DADDR=10.2.0.1/24 sh -c "$child" >"$log_a" 2>&1 &
proxy_a=$!
unshare --net env UPADDR=10.1.1.1/24 DADDR=10.2.0.2/24 sh -c "$child" >"$log_b" 2>&1 &
proxy_b=$!
sleep 1

ip link add br0 type bridge mcast_snooping 0
ip link add upa0 type veth peer name upa
ip link add upb0 type veth peer name upb
ip link add da0 type veth peer name da
ip link add db0 type veth peer name db
ip link set upa netns "$proxy_a" name up0
ip link set da netns "$proxy_a" name d0
ip link set upb netns "$proxy_b" name up0
ip link set db netns "$proxy_b" name d0
ip link set da0 master br0
ip link set db0 master br0
ip link set lo up
for i in br0 upa0 upb0 da0 db0; do ip link set "$i" up; done
ip addr add 10.0.1.2/24 dev upa0
ip addr add 10.1.1.2/24 dev upb0
ip addr add 10.2.0.9/24 dev br0

waited=0
until grep -q "detected other querier 10.2.0.1" "$log_b"; do
    waited=$((waited + 1))
    [ "$waited" -ge 60 ] && fail "proxy B never lost the election to proxy A"
    sleep 1
done
echo "ok: proxy B lost the shared-downlink election to proxy A"

python3 "$here/mcast_recv.py" br0 "$GROUP" "$PORT" 10 >"$recv_out" &
recv_pid=$!
sleep 2
python3 "$here/mcast_send.py" upb0 "$GROUP" "$PORT" 20 0.5 &
send_pid=$!
if wait "$recv_pid"; then
    recv_pid=
    fail "proxy B forwarded although it lost the shared-downlink election"
fi
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: election loser does not forward onto the shared downlink"

python3 "$here/mcast_recv.py" br0 "$GROUP" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 2
python3 "$here/mcast_send.py" upa0 "$GROUP" "$PORT" 30 0.5 &
send_pid=$!
wait "$recv_pid" || fail "election winner did not forward onto the shared downlink"
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: election winner forwards onto the shared downlink"

ip link del db0
sleep 1
kill "$proxy_b"
if ! wait "$proxy_b"; then
    proxy_b=
    fail "proxy B did not exit cleanly after its downlink disappeared"
fi
proxy_b=
echo "ok: loser exits cleanly after its downlink disappeared"

python3 "$here/mcast_recv.py" br0 "$GROUP" "$PORT" 20 >"$recv_out" &
recv_pid=$!
sleep 2
python3 "$here/mcast_send.py" upa0 "$GROUP" "$PORT" 30 0.5 &
send_pid=$!
wait "$recv_pid" || fail "winner stopped forwarding after the other proxy left"
recv_pid=
kill "$send_pid" 2>/dev/null || true
send_pid=
echo "ok: winner keeps forwarding after the other proxy left"

ip link del upa0
sleep 1
kill "$proxy_a"
if ! wait "$proxy_a"; then
    proxy_a=
    fail "proxy A did not exit cleanly after its uplink disappeared with active routes"
fi
proxy_a=
echo "ok: winner exits cleanly after its uplink disappeared with active routes"

echo "PASS"
