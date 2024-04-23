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

#include <cstring>
#include <net/if.h>
#include <netinet/in.h>

#include <libubox/avl.h>
#include <libubox/list.h>
#include <libubox/uloop.h>

#include "groups.h"
#include "mrib.h"

struct QuerierIface {
  struct ListHead head;
  struct ListHead users;
  struct UloopTimeout timeout;
  struct GroupsConfig cfg;

  omcp_time_t igmp_next_query;
  bool igmp_other_querier;
  int igmp_startup_tries;

  omcp_time_t mld_next_query;
  bool mld_other_querier;
  int mld_startup_tries;

  struct MribQuerier mrib;
  struct Groups groups;
  int ifindex;
};

typedef void(QuerierIfaceCallback)(struct QuerierUserIface* user,
                               const struct in6_addr* group,
                               bool include,
                               const struct in6_addr* sources,
                               size_t len);

struct QuerierUser {
  struct ListHead head;
  struct Groups* groups;
  struct Querier* querier;
};

struct QuerierUserIface {
  struct ListHead head;
  struct QuerierUser user;
  struct QuerierIface* iface;
  QuerierIfaceCallback* user_cb;
};

/* External API */
int querier_init(struct Querier* querier);
void querier_deinit(struct Querier* querier);

int querier_attach(struct QuerierUserIface* user,
                   struct Querier* querier,
                   int ifindex,
                   QuerierIfaceCallback* cb);
void querier_detach(struct QuerierUserIface* user);

/* Internal API */

struct Querier {
  struct ListHead ifaces;
};

#define QUERIER_MAX_SOURCE 75
#define QUERIER_SUPPRESS (1 << 3)

in_addr_t querier_unmap(const struct in6_addr* addr6);

void querier_map(struct in6_addr* addr6, in_addr_t addr4);

int querier_qqi(uint8_t qqic);
int querier_mrd(uint16_t mrc);
uint8_t querier_qqic(int qi);
uint16_t querier_mrc(int mrd);

void igmp_handle(struct MribQuerier* mrib,
                 const struct igmphdr* igmp,
                 size_t len,
                 const struct sockaddr_in* from);

int igmp_send_query(struct QuerierIface* q,
                    const struct in6_addr* Group,
                    const struct ListHead* sources,
                    bool suppress);

void mld_handle(struct MribQuerier* mrib,
                const struct mld_hdr* hdr,
                size_t len,
                const struct sockaddr_in6* from);

ssize_t mld_send_query(struct QuerierIface* q,
                       const struct in6_addr* group,
                       const struct ListHead* sources,
                       bool suppress);
