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

## Building

CMake 3.21+, Ninja, and a system installation of libubox are required.

```sh
cmake --preset default
cmake --build --preset default
```

The binary lands in `build/omcproxy`.
