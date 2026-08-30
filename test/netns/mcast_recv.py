import socket
import struct
import sys
import time

MCAST_JOIN_GROUP = 42
IP_MULTICAST_ALL = 49
IPV6_MULTICAST_ALL = 29
IP_PKTINFO = 8
IPV6_RECVPKTINFO = 49
IPV6_PKTINFO = 50


def sockaddr_storage(addr):
    if ":" in addr:
        return struct.pack("=HHI16sI", socket.AF_INET6, 0, 0,
                           socket.inet_pton(socket.AF_INET6, addr), 0).ljust(128, b"\0")
    return struct.pack("=HH4s", socket.AF_INET, 0,
                       socket.inet_pton(socket.AF_INET, addr)).ljust(128, b"\0")


def arrival_ifindex(v6, ancdata):
    for level, ctype, data in ancdata:
        if v6 and level == socket.IPPROTO_IPV6 and ctype == IPV6_PKTINFO:
            return struct.unpack("=16si", data)[1]
        if not v6 and level == socket.IPPROTO_IP and ctype == IP_PKTINFO:
            return struct.unpack("=i4s4s", data)[0]
    return 0


def main():
    ifname, group = sys.argv[1], sys.argv[2]
    port, timeout = int(sys.argv[3]), float(sys.argv[4])
    ifindex = socket.if_nametoindex(ifname)
    v6 = ":" in group

    if v6:
        family, level, bindaddr = socket.AF_INET6, socket.IPPROTO_IPV6, "::"
    else:
        family, level, bindaddr = socket.AF_INET, socket.IPPROTO_IP, ""

    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if v6:
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
    else:
        s.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)
        s.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    s.bind((bindaddr, port))
    req = struct.pack("=I4x", ifindex) + sockaddr_storage(group)
    s.setsockopt(level, MCAST_JOIN_GROUP, req)
    print(f"listening on {group} port {port} via {ifname}", flush=True)

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print("timeout", flush=True)
            sys.exit(1)
        s.settimeout(remaining)
        try:
            data, ancdata, flags, src = s.recvmsg(2048, 512)
        except TimeoutError:
            print("timeout", flush=True)
            sys.exit(1)
        arrival = arrival_ifindex(v6, ancdata)
        if arrival == ifindex:
            print(f"received {data!r} from {src[0]}", flush=True)
            return
        print(f"ignored packet arriving on ifindex {arrival}", flush=True)


if __name__ == "__main__":
    main()
