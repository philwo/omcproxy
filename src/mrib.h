/*
 * Author: Steven Barth <steven at midlink.org>
 *
 * Copyright 2015 Deutsche Telekom AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define icmp6_filter icmpv6_filter
#include <linux/icmpv6.h>
#include <linux/igmp.h>
#undef icmp6_filter

#include <libubox/list.h>

#define MRIB_DEFAULT_LIFETIME 125

#define IPV6_ALL_NODES_INIT                                      \
  {                                                              \
    {                                                            \
      { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 } \
    }                                                            \
  }
#define INADDR_ALLIGMPV3RTRS_GROUP cpu_to_be32(0xe0000016U)

typedef uint32_t MribFilter;
struct MribIface;
struct MribUser;
struct MribQuerier;

typedef void(MribCallback)(struct MribUser* user,
                      const struct in6_addr* Group,
                      const struct in6_addr* source,
                      MribFilter* filter);

typedef void(MribIGMPCallback)(struct MribQuerier* mrib,
                           const struct igmphdr* igmp,
                           size_t len,
                           const struct sockaddr_in* from);

typedef void(MribMLDCallback)(struct MribQuerier* mrib,
                          const struct mld_hdr* mld,
                          size_t len,
                          const struct sockaddr_in6* from);

struct MribUser {
  struct ListHead head;
  struct MribIface* iface;
  MribCallback* cb_newsource;
};

struct MribQuerier {
  struct ListHead head;
  struct MribIface* iface;
  MribIGMPCallback* cb_igmp;
  MribMLDCallback* cb_mld;
};

// Register a new user to mrib
int mrib_attach_user(struct MribUser* user,
                     int ifindex,
                     MribCallback* cb_newsource);

// Deregister a user from mrib
void mrib_detach_user(struct MribUser* user);

// Register a querier to mrib
int mrib_attach_querier(struct MribQuerier* querier,
                        int ifindex,
                        MribIGMPCallback* cb_igmp,
                        MribMLDCallback* cb_mld);

// Deregister a querier from mrib
void mrib_detach_querier(struct MribQuerier* querier);

// Add interface to filter
int mrib_filter_add(MribFilter* filter, struct MribUser* user);

// Send IGMP-packet
int mrib_send_igmp(struct MribQuerier* querier,
                   struct igmpv3_query* igmp,
                   size_t len,
                   const struct sockaddr_in* dest);

// Send MLD-packet
int mrib_send_mld(struct MribQuerier* querier,
                  struct mld_hdr* mld,
                  size_t len,
                  const struct sockaddr_in6* dest);

// Get source address
int mrib_mld_source(struct MribQuerier* q, struct in6_addr* source);
int mrib_igmp_source(struct MribQuerier* q, struct in_addr* source);
