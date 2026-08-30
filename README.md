# omcproxy - IGMPv3 and MLDv2 proxy

omcproxy is an IGMPv3 and MLDv2 multicast proxy for Linux routers. This is a
modernized fork of [openwrt/omcproxy](https://github.com/openwrt/omcproxy),
which is partly based on code of https://github.com/Oryon/pimbd.

## Features

1. Source-Specific Multicast Querier
	- MLDv2 querier (based on RFC 3810)
	- IGMPv3 querier (based on RFC 3376)

2. Multicast Proxying (based on RFC 4605)
	- Kernel-space multicast routing
	- Multiple instances support
	- Address-scope specific proxying

## Scope

omcproxy forwards multicast data in one direction: from the upstream
interface to downstream interfaces with matching subscriptions. Membership
signaling from downstream hosts is aggregated and proxied to the upstream
network as the RFC 4605 host portion. Multicast data that originates on a
downstream interface is not forwarded, neither to the upstream interface
nor to sibling downstream interfaces; such flows get an empty kernel route
so that they do not generate repeated cache-miss notifications. This is a
deliberate limitation: the target use case is receiving multicast services
(such as IPTV) from an upstream network, where the upstream provider drops
customer-originated multicast anyway.

## Changes in this fork

- C23, no external dependencies (libubox is replaced by a small epoll and
  timerfd event loop and a vendored intrusive list header)
- One shared wire codec for IGMPv3 and MLDv2 with a unit-tested record
  parser, checksum, and query timer codecs
- Unit tests, network-namespace integration tests, sanitizer builds, a
  libFuzzer harness for the packet parsers, and a strict warning set,
  all wired into CI
- Many bug fixes; see the git history for details

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

With `strict`, a downstream interface only receives forwarded traffic while
this proxy is the elected IGMP/MLD querier on it, as RFC 4605 suggests for
LANs with more than one proxy. The default is to keep forwarding even after
losing the election, which is the safe choice when another device (such as a
snooping switch) sends queries but does not forward multicast itself.

The kernel must support PIM on the multicast routing sockets
(`CONFIG_IP_PIMSM_V1` or `CONFIG_IP_PIMSM_V2`, and `CONFIG_IPV6_PIMSM_V2`).
Common distribution kernels enable these options. OpenWrt's generic kernel
configuration disables IPv4 PIM, so OpenWrt needs a custom kernel
configuration that enables the options. omcproxy uses PIM mode to receive
wrong-interface upcalls for any arrival interface, which it needs to recover
forwarding when a spoofed packet created a multicast route with the wrong
parent. Startup fails when the kernel lacks this support.

## Testing

```sh
ctest --preset default    # unit tests
ctest --preset netns      # integration tests in network namespaces
```

The netns tests need unprivileged user namespaces (or root). The `asan`
preset builds with AddressSanitizer and UndefinedBehaviorSanitizer and has
matching `asan` and `netns-asan` test presets. The `fuzz` preset builds
`build-fuzz/test/fuzz_gmp`, a libFuzzer target for the packet parsers
(requires clang).
