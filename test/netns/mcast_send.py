import socket
import struct
import sys
import time


def main():
    ifname, group = sys.argv[1], sys.argv[2]
    port, count, interval = int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
    ifindex = socket.if_nametoindex(ifname)

    if ":" in group:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 5)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mreqn = struct.pack("=4s4si", b"\0" * 4, b"\0" * 4, ifindex)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 5)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

    for i in range(count):
        s.sendto(b"payload-%d" % i, (group, port))
        time.sleep(interval)


if __name__ == "__main__":
    main()
