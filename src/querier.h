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
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include "list.h"

#include "ev.h"
#include "gmp.h"
#include "groups.h"
#include "mrib.h"

struct querier_proto {
  omgp_time_t next_query;
  bool other_querier;
  int startup_tries;
};

struct querier_iface {
  struct list_head head;
  struct list_head users;
  struct ev_timer timeout;
  struct groups_config cfg;

  struct querier_proto proto[2];

  struct mrib_querier mrib;
  struct groups groups;
  int ifindex;
};

struct querier;
struct querier_user;
struct querier_user_iface;

typedef void(querier_iface_cb)(struct querier_user_iface* user,
                               const struct in6_addr* group,
                               bool include,
                               const struct in6_addr* sources,
                               size_t len);

struct querier_user {
  struct list_head head;
  struct groups* groups;
  struct querier* querier;
};

struct querier_user_iface {
  struct list_head head;
  struct querier_user user;
  struct querier_iface* iface;
  querier_iface_cb* user_cb;
};

/* External API */
int querier_init(struct querier* querier);
void querier_deinit(struct querier* querier);

int querier_attach(struct querier_user_iface* user,
                   struct querier* querier,
                   int ifindex,
                   querier_iface_cb* cb);
void querier_detach(struct querier_user_iface* user);

/* Internal API */

struct querier {
  struct list_head ifaces;
};

#define QUERIER_MAX_SOURCE 75
#define QUERIER_MAX_GROUPS 256
#define QUERIER_SUPPRESS (1 << 3)
