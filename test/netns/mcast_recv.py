import socket
import struct
import sys

MCAST_JOIN_GROUP = 42
IP_MULTICAST_ALL = 49
IPV6_MULTICAST_ALL = 29


def sockaddr_storage(addr):
    if ":" in addr:
        return struct.pack("=HHI16sI", socket.AF_INET6, 0, 0,
                           socket.inet_pton(socket.AF_INET6, addr), 0).ljust(128, b"\0")
    return struct.pack("=HH4s", socket.AF_INET, 0,
                       socket.inet_pton(socket.AF_INET, addr)).ljust(128, b"\0")


def main():
    ifname, group = sys.argv[1], sys.argv[2]
    port, timeout = int(sys.argv[3]), float(sys.argv[4])
    ifindex = socket.if_nametoindex(ifname)

    if ":" in group:
        family, level, bindaddr = socket.AF_INET6, socket.IPPROTO_IPV6, "::"
    else:
        family, level, bindaddr = socket.AF_INET, socket.IPPROTO_IP, ""

    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)
    else:
        s.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)
    s.bind((bindaddr, port))
    req = struct.pack("=I4x", ifindex) + sockaddr_storage(group)
    s.setsockopt(level, MCAST_JOIN_GROUP, req)
    print(f"listening on {group} port {port} via {ifname}", flush=True)

    s.settimeout(timeout)
    try:
        data, src = s.recvfrom(2048)
    except TimeoutError:
        print("timeout", flush=True)
        sys.exit(1)
    print(f"received {data!r} from {src[0]}", flush=True)


if __name__ == "__main__":
    main()
