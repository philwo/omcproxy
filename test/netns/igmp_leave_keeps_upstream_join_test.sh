#!/bin/sh
set -eu

here=$(dirname "$(readlink -f "$0")")
OMCPROXY=${OMCPROXY:-$here/../../build/omcproxy}
GROUP=239.66.66.66
GROUPHEX=0xef424242

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
    echo "--- mcfilter at failure ---"
    cat /proc/net/mcfilter
    echo "--- igmp at failure ---"
    cat /proc/net/igmp
    echo "--- omcproxy log ---"
    cat "$log"
    exit 1
}

has_upstream_join() {
    ip maddr show dev up0 | grep -q "$GROUP"
}

sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.all.accept_local=1 net.ipv4.conf.default.accept_local=1

ip link add up0 type veth peer name up1
ip link add d1a type veth peer name d1b
ip link add d2a type veth peer name d2b
ip link set lo up
for i in up0 up1 d1a d1b d2a d2b; do ip link set "$i" up; done
ip addr add 10.0.1.1/24 dev up0
ip addr add 10.0.1.2/24 dev up1
ip addr add 10.1.1.1/24 dev d1a
ip addr add 10.1.1.2/24 dev d1b
ip addr add 10.2.1.1/24 dev d2a
ip addr add 10.2.1.2/24 dev d2b
sleep 3

"$OMCPROXY" -v up0,d1a,d2a >"$log" 2>&1 &
proxy_pid=$!
sleep 2

python3 "$here/mcast_join.py" d1b "$GROUP" &
joiner_a=$!
python3 "$here/mcast_join.py" d2b "$GROUP" &
joiner_b=$!
sleep 4

has_upstream_join || fail "no upstream join after both downstreams joined"
echo "ok: upstream join present with two downstream members"

kill "$joiner_a"
sleep 6
has_upstream_join || fail "upstream join dropped after leave on d1 although d2 still has a member"
echo "ok: upstream join survives leave on first downstream"

kill "$joiner_b"
sleep 6
if has_upstream_join; then
    fail "upstream join still present after both downstreams left"
fi
echo "ok: upstream join removed after last downstream left"

SSMGROUP=232.1.1.1
SSMGROUPHEX=0xe8010101
S1=10.99.0.1
S2=10.99.0.2

src_hex() {
    printf '0x%02x%02x%02x%02x' \
        "$(echo "$1" | cut -d. -f1)" "$(echo "$1" | cut -d. -f2)" \
        "$(echo "$1" | cut -d. -f3)" "$(echo "$1" | cut -d. -f4)"
}
S1HEX=$(src_hex "$S1")
S2HEX=$(src_hex "$S2")

has_upstream_ssm_join() {
    ip maddr show dev up0 | grep -q "$SSMGROUP"
}

upstream_includes() {
    awk -v grp="$SSMGROUPHEX" -v src="$1" '
        $2 == "up0" && $3 == grp && $4 == src && $5 >= 1 { found = 1 }
        END { exit !found }' /proc/net/mcfilter
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
has_upstream_ssm_join || fail "ssm: upstream join dropped after leave on d1 although d2 still has a member"
upstream_includes "$S2HEX" || fail "ssm: upstream filter lost $S2 after unrelated leave on d1"
echo "ok: ssm upstream join and $S2 survive leave on first downstream"
if upstream_includes "$S1HEX"; then
    fail "ssm: upstream filter still includes $S1 after leave on d1"
fi
echo "ok: ssm upstream filter dropped $S1 after leave on first downstream"

kill "$joiner_b"
sleep 6
if has_upstream_ssm_join; then
    fail "ssm: upstream join still present after both downstreams left"
fi
echo "ok: ssm upstream join removed after last downstream left"

echo "PASS"
