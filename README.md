# omcproxy - IGMPv3 and MLDv2 proxy

omcproxy is an IGMPv3 and MLDv2 multicast proxy for Linux routers. This is my
personal fork of [openwrt/omcproxy](https://github.com/openwrt/omcproxy), which
in turn is partly based on [Oryon/pimbd](https://github.com/Oryon/pimbd).

It runs on my Linux PC router at home to make
[Hikari-TV](https://www.hikaritv.net/) work reliably in a dedicated IPTV VLAN.

## Background

NTT's Hikari-TV uses IPv6 multicast to deliver IPTV streams efficiently. In
theory this is beautiful and how the internet is supposed to work - finally
someone going all-in on IPv6 and even the exotic stuff like multicast.

In practice though, no one seems to implement the functionality to handle IPv6
multicast in a home network and internet connection correctly. ;) `omcproxy` was
the only software I could find that actually worked, and with a few patches here
and there, the incident reports from my wife about the TV not working eventually
stopped.

### Multicast Routing

Linux does not route or forward multicast frames across interfaces (such as
between the upstream WAN and my local LAN) by default. Even if we "simply" set
up a few static routes e.g. via
[smcroute](https://github.com/troglobit/smcroute), it wouldn't work, because
NTT's routers only start sending us the multicast traffic after we join the
group and regularly refresh the membership.

An MLDv2-aware proxy daemon is thus required to relay MLD Membership Reports
from the proprietary set-top box to NTT's multicast routers, and forward the
incoming IPv6 multicast payloads downstream.

### Why use a separate VLAN?

Once I got the traffic flow working on my router and the TV showing the
channels, I hit the next issue: My Mikrotik switches (with SwOS) and my TP-Link
Deco APs don't support MLDv2, and even my LANCOM switches had some strange bugs
in their implementation. This leads to traffic being dropped, or broadcast to
all ports, which is especially fun when it hits and overwhelms the Wi-Fi. The
easiest fix was to put the multicast traffic on a separate VLAN and carefully
thread it through to only hit the ethernet port on the switch where the STB is
connected.

## Features

1. Source-Specific Multicast Querier
   - MLDv2 querier (based on RFC 3810)
   - IGMPv3 querier (based on RFC 3376)

2. Multicast Proxying (based on RFC 4605)
   - Kernel-space multicast routing
   - Multiple instances support
   - Address-scope specific proxying

## Scope

omcproxy forwards multicast data in one direction: from the upstream interface
to downstream interfaces with matching subscriptions. Membership signaling from
downstream hosts is aggregated and proxied to the upstream network as the RFC
4605 host portion. Multicast data that originates on a downstream interface is
not forwarded, neither to the upstream interface nor to sibling downstream
interfaces; such flows get an empty kernel route so that they do not generate
repeated cache-miss notifications. This is a deliberate limitation: the target
use case is receiving multicast services (such as IPTV) from an upstream
network, where the upstream provider drops customer-originated multicast anyway.

## Changes in this fork

- Rewritten in modern C23, clang-formatted to Chromium style, zero clang-tidy
  warnings.
- No external dependencies anymore: libubox is replaced by a small epoll and
  timerfd event loop and a vendored intrusive list header.
- Merged the IGMPv3 and MLDv2 wire codecs into one shared, unit-tested,
  fuzz-tested implementation.
- Added a whole bunch of unit tests, network-namespace integration tests,
  sanitizer builds, a libFuzzer harness for the packet parsers. Enabled strict
  compiler warnings and fixed all the findings.
- Many bug fixes and lots of hardening; see the git history for details.

## Building

CMake 3.21+ and Ninja are required.

```sh
cmake --preset default
cmake --build --preset default
```

The binary lands in `build/omcproxy`. Run it as root with one or more proxy
specs, first interface is the upstream:

```sh
omcproxy [-v] <uplink>,<downlink>[,<downlink>...][,scope=<scope>][,strict]
```

With `strict`, a downstream interface only receives forwarded traffic while this
proxy is the elected IGMP/MLD querier on it, as RFC 4605 suggests for LANs with
more than one proxy. The default is to keep forwarding even after losing the
election, which is the safe choice when another device (such as a snooping
switch) sends queries but does not forward multicast itself.

The kernel must support PIM on the multicast routing sockets
(`CONFIG_IP_PIMSM_V1` or `CONFIG_IP_PIMSM_V2`, and `CONFIG_IPV6_PIMSM_V2`).
Common distribution kernels enable these options. OpenWrt's generic kernel
configuration disables IPv4 PIM, so OpenWrt needs a custom kernel configuration
that enables the options. omcproxy uses PIM mode to receive wrong-interface
upcalls for any arrival interface, which it needs to recover forwarding when a
spoofed packet created a multicast route with the wrong parent. Startup fails
when the kernel lacks this support.

## Testing

```sh
ctest --preset default    # unit tests
ctest --preset netns      # integration tests in network namespaces
```

The netns tests need unprivileged user namespaces (or root). The `asan` preset
builds with AddressSanitizer and UndefinedBehaviorSanitizer and has matching
`asan` and `netns-asan` test presets. The `fuzz` preset builds
`build-fuzz/test/fuzz_gmp`, a libFuzzer target for the packet parsers (requires
clang).
