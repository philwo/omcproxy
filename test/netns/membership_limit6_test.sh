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
    ip -6 maddr show dev up0 || true
    echo "--- omcproxy log ---"
    cat "$log"
    exit 1
}

ip link add up0 type veth peer name up1
ip link add d1a type veth peer name d1b
ip link set lo up
for i in up0 up1 d1a d1b; do ip link set "$i" up; done
sleep 3

"$OMCPROXY" -v up0,d1a >"$log" 2>&1 &
proxy_pid=$!
sleep 2

sysctl -qw net.core.optmem_max=256

for i in 1 2 3 4 5; do
    python3 "$here/mcast_join.py" d1b "ff0e::5a:$i" &
    joiner_pids="$joiner_pids $!"
done
sleep 6

for i in 1 2 3 4 5; do
    ip -6 maddr show dev up0 | grep -q "ff0e::5a:$i" ||
        fail "upstream join for ff0e::5a:$i missing although optmem_max=256"
done
echo "ok: all 5 upstream joins present with optmem_max=256"

echo "PASS"
