import socket
import struct
import sys

SO_BINDTODEVICE = 25
IPPROTO_IGMP = 2


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def main():
    ifname = sys.argv[1]
    mrc = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    qqic = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    ifindex = socket.if_nametoindex(ifname)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_IGMP)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, ifname.encode())
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b"\x94\x04\x00\x00")
    mreqn = struct.pack("=4s4si", b"\0" * 4, b"\0" * 4, ifindex)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)

    pkt = bytearray(12)
    pkt[0] = 0x11
    pkt[1] = mrc
    pkt[8] = 2
    pkt[9] = qqic
    csum = checksum(bytes(pkt))
    pkt[2] = csum >> 8
    pkt[3] = csum & 0xFF

    s.sendto(bytes(pkt), ("224.0.0.1", 0))
    print(f"igmpv3 general query sent on {ifname}", flush=True)


if __name__ == "__main__":
    main()
