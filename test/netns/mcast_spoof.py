import socket
import struct
import sys

IPV6_HDRINCL = 36


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def main():
    ifname, src, group = sys.argv[1], sys.argv[2], sys.argv[3]
    port = int(sys.argv[4])
    payload = b"spoof"

    if ":" in group:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_HDRINCL, 1)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        srcaddr = socket.inet_pton(socket.AF_INET6, src)
        dstaddr = socket.inet_pton(socket.AF_INET6, group)
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", port, port, udp_len, 0) + payload
        pseudo = srcaddr + dstaddr + struct.pack("!I3xB", udp_len, 17)
        udp_csum = checksum(pseudo + udp) or 0xFFFF
        udp = struct.pack("!HHHH", port, port, udp_len, udp_csum) + payload
        ip6 = struct.pack("!IHBB", 0x60000000, udp_len, 17, 5) + srcaddr + dstaddr
        s.sendto(ip6 + udp, (group, 0))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        srcaddr = socket.inet_pton(socket.AF_INET, src)
        dstaddr = socket.inet_pton(socket.AF_INET, group)
        udp = struct.pack("!HHHH", port, port, 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 5, 17, 0)
        ip += srcaddr + dstaddr
        s.sendto(ip + udp, (group, 0))
    print(f"spoofed {group} port {port} from {src} via {ifname}", flush=True)


if __name__ == "__main__":
    main()
