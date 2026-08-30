import socket
import struct
import sys

IPV6_HOPOPTS = getattr(socket, "IPV6_HOPOPTS", 54)
ROUTER_ALERT = b"\x00\x00\x05\x02\x00\x00\x01\x00"


def main():
    ifname = sys.argv[1]
    mrc = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    qqic = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    ifindex = socket.if_nametoindex(ifname)

    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    s.setsockopt(socket.IPPROTO_IPV6, IPV6_HOPOPTS, ROUTER_ALERT)
    s.bind(("fe80::1", 0, 0, ifindex))

    pkt = bytearray(28)
    pkt[0] = 130
    struct.pack_into("!H", pkt, 4, mrc)
    pkt[24] = 2
    pkt[25] = qqic

    s.sendto(bytes(pkt), (f"ff02::1%{ifname}", 0))
    print(f"mldv2 general query sent on {ifname}", flush=True)


if __name__ == "__main__":
    main()
