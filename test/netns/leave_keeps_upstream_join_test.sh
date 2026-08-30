#!/bin/sh
set -eu

here=$(dirname "$(readlink -f "$0")")
OMCPROXY=${OMCPROXY:-$here/../../build/omcproxy}
ASMGROUP=ff0e::1234
SSMGROUP=ff3e::1234

if [ -z "${IN_NS:-}" ]; then
    exec unshare -r -n env IN_NS=1 OMCPROXY="$OMCPROXY" "$(readlink -f "$0")"
fi

log=$(mktemp)
proxy_pid=
joiner_a=
joiner_b=

cleanup() {
    for pid in $joiner_a $joiner_b $proxy_pid; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    echo "--- mcfilter6 at failure ---"
    cat /proc/net/mcfilter6
    echo "--- omcproxy log ---"
    cat "$log"
    exit 1
}

has_upstream_join() {
    ip -6 maddr show dev up0 | grep -q "$1"
}

ip link add up0 type veth peer name up1
ip link add d1a type veth peer name d1b
ip link add d2a type veth peer name d2b
ip link set lo up
for i in up0 up1 d1a d1b d2a d2b; do ip link set "$i" up; done
sleep 3

"$OMCPROXY" -v up0,d1a,d2a >"$log" 2>&1 &
proxy_pid=$!
sleep 2

python3 "$here/mcast_join.py" d1b "$ASMGROUP" &
joiner_a=$!
python3 "$here/mcast_join.py" d2b "$ASMGROUP" &
joiner_b=$!
sleep 4

has_upstream_join "$ASMGROUP" || fail "no upstream join after both downstreams joined"
echo "ok: upstream join present with two downstream members"

kill "$joiner_a"
sleep 6
has_upstream_join "$ASMGROUP" || fail "upstream join dropped after leave on d1 although d2 still has a member"
echo "ok: upstream join survives leave on first downstream"

kill "$joiner_b"
sleep 6
if has_upstream_join "$ASMGROUP"; then
    fail "upstream join still present after both downstreams left"
fi
echo "ok: upstream join removed after last downstream left"

S1=2001:db8::1
S1HEX=20010db8000000000000000000000001
S2=2001:db8::2
S2HEX=20010db8000000000000000000000002

upstream_includes() {
    awk -v src="$1" '
        $2 == "up0" && $3 == "ff3e0000000000000000000000001234" && $4 == src && $5 >= 1 { found = 1 }
        END { exit !found }' /proc/net/mcfilter6
}

python3 "$here/mcast_join.py" d1b "$SSMGROUP" "$S1" &
joiner_a=$!
python3 "$here/mcast_join.py" d2b "$SSMGROUP" "$S2" &
joiner_b=$!
sleep 4

upstream_includes "$S1HEX" || fail "ssm: upstream filter lacks $S1 after join on d1"
upstream_includes "$S2HEX" || fail "ssm: upstream filter lacks $S2 after join on d2"
echo "ok: ssm upstream filter includes both sources"

kill "$joiner_a"
sleep 6
has_upstream_join "$SSMGROUP" || fail "ssm: upstream join dropped after leave on d1 although d2 still has a member"
upstream_includes "$S2HEX" || fail "ssm: upstream filter lost $S2 after unrelated leave on d1"
echo "ok: ssm upstream join and $S2 survive leave on first downstream"
if upstream_includes "$S1HEX"; then
    fail "ssm: upstream filter still includes $S1 after leave on d1"
fi
echo "ok: ssm upstream filter dropped $S1 after leave on first downstream"

kill "$joiner_b"
sleep 6
if has_upstream_join "$SSMGROUP"; then
    fail "ssm: upstream join still present after both downstreams left"
fi
echo "ok: ssm upstream join removed after last downstream left"

python3 "$here/mcast_join.py" d1b "$SSMGROUP" &
joiner_a=$!
sleep 4
if has_upstream_join "$SSMGROUP"; then
    fail "ssm: source-less join of an SSM group created an upstream join"
fi
echo "ok: source-less join of an SSM group is ignored"
kill "$joiner_a"

echo "PASS"
