import signal
import socket
import struct
import sys
import time

MCAST_JOIN_GROUP = 42
MCAST_JOIN_SOURCE_GROUP = 46


def sockaddr_storage(addr):
    if ":" in addr:
        return struct.pack("=HHI16sI", socket.AF_INET6, 0, 0,
                           socket.inet_pton(socket.AF_INET6, addr), 0).ljust(128, b"\0")
    return struct.pack("=HH4s", socket.AF_INET, 0,
                       socket.inet_pton(socket.AF_INET, addr)).ljust(128, b"\0")


def main():
    ifname, group = sys.argv[1], sys.argv[2]
    source = sys.argv[3] if len(sys.argv) > 3 else None
    ifindex = socket.if_nametoindex(ifname)

    if ":" in group:
        family, level = socket.AF_INET6, socket.IPPROTO_IPV6
    else:
        family, level = socket.AF_INET, socket.IPPROTO_IP

    s = socket.socket(family, socket.SOCK_DGRAM)
    if source:
        req = struct.pack("=I4x", ifindex) + sockaddr_storage(group) + \
              sockaddr_storage(source)
        s.setsockopt(level, MCAST_JOIN_SOURCE_GROUP, req)
    else:
        req = struct.pack("=I4x", ifindex) + sockaddr_storage(group)
        s.setsockopt(level, MCAST_JOIN_GROUP, req)

    print(f"joined {group} on {ifname}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
