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

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

#include "addr.h"
#include "querier.h"

static struct list_head ifaces = LIST_HEAD_INIT(ifaces);

// Handle querier update event from a querier-interface
static void querier_announce_iface(struct querier_user_iface* user,
                                   omgp_time_t now,
                                   const struct group* group,
                                   bool enabled) {
  bool include = true;
  size_t cnt = 0;
  struct in6_addr sources[QUERIER_MAX_SOURCE];

  if (enabled) {
    struct group_source* source;
    group_for_each_active_source (source, group, now) {
      if (cnt >= QUERIER_MAX_SOURCE) {
        break;
      }
      sources[cnt++] = source->addr;
    }

    include = group_is_included(group, now);
  }

  if (user->user_cb) {
    user->user_cb(user, &group->addr, include, sources, cnt);
  }
}

// Handle changes from a querier for a given group (called by a group-state as
// callback)
static void querier_announce_change(struct groups* groups,
                                    struct group* group,
                                    omgp_time_t now) {
  struct querier_iface* iface =
      container_of(groups, struct querier_iface, groups);

  // Only recognize changes to non-link-local groups
  struct querier_user_iface* user;
  list_for_each_entry (user, &iface->users, head) {
    querier_announce_iface(user, now, group, true);
  }
}

// Send query for a group + sources (called by a group-state as callback)
static void querier_send_query(struct groups* groups,
                               const struct in6_addr* group,
                               const struct list_head* sources,
                               bool suppress) {
  struct querier_iface* iface =
      container_of(groups, struct querier_iface, groups);
  char addrbuf[ADDR_BUFLEN];
  addr_ntop(addrbuf, sizeof(addrbuf), group);

  L_DEBUG("%s: sending %s-specific query for %s on %d (S: %d)", __FUNCTION__,
          (!sources) ? "group" : "source", addrbuf, iface->ifindex, suppress);

  bool v4 = IN6_IS_ADDR_V4MAPPED(group);
  if (v4 && !iface->proto[GMP_IGMP].other_querier) {
    igmp_send_query(iface, group, sources, suppress);
  } else if (!v4 && !iface->proto[GMP_MLD].other_querier) {
    mld_send_query(iface, group, sources, suppress);
  }
}

// Expire interface timers and send queries (called by timer as callback)
static void querier_iface_timer(struct ev_timer* timeout) {
  struct querier_iface* iface =
      container_of(timeout, struct querier_iface, timeout);
  omgp_time_t now = omgp_time();
  omgp_time_t next_event = now + 3600 * OMGP_TIME_PER_SECOND;

  for (int family = GMP_IGMP; family <= GMP_MLD; ++family) {
    struct querier_proto* protocol = &iface->proto[family];
    struct groups_config* config =
        (family == GMP_MLD) ? &iface->groups.cfg_v6 : &iface->groups.cfg_v4;

    if (protocol->next_query <= now) {
      if (protocol->other_querier) {
        *config = iface->cfg;
        protocol->other_querier = false;
      }

      if (family == GMP_MLD) {
        mld_send_query(iface, NULL, NULL, false);
      } else {
        igmp_send_query(iface, NULL, NULL, false);
      }
      L_DEBUG("%s: sending generic %s-query on %d (S: 0)", __FUNCTION__,
              (family == GMP_MLD) ? "MLD" : "IGMP", iface->ifindex);

      if (protocol->startup_tries > 0) {
        --protocol->startup_tries;
      }

      protocol->next_query =
          now + ((protocol->startup_tries > 0) ? (config->query_interval / 4)
                                               : config->query_interval);
    }

    if (protocol->next_query < next_event) {
      next_event = protocol->next_query;
    }
  }

  ev_timer_set(&iface->timeout, (next_event > now) ? next_event - now : 0);
}

// Attach an interface to a querier-instance
int querier_attach(struct querier_user_iface* user,
                   struct querier* querier,
                   int ifindex,
                   querier_iface_cb* cb) {
  struct querier_iface* c;
  struct querier_iface* iface = NULL;
  list_for_each_entry (c, &ifaces, head) {
    if (c->ifindex == ifindex) {
      iface = c;
      break;
    }
  }

  if (!iface) {
    iface = calloc(1, sizeof(*iface));
    if (!iface) {
      return -ENOMEM;
    }

    list_add(&iface->head, &ifaces);
    INIT_LIST_HEAD(&iface->users);

    iface->ifindex = ifindex;
    iface->timeout.cb = querier_iface_timer;

    groups_init(&iface->groups);
    iface->groups.source_limit = QUERIER_MAX_SOURCE;
    iface->groups.group_limit = QUERIER_MAX_GROUPS;
    iface->groups.cb_update = querier_announce_change;
    iface->groups.cb_query = querier_send_query;
    iface->cfg = iface->groups.cfg_v6;
    iface->proto[GMP_IGMP].startup_tries = iface->groups.cfg_v4.robustness;
    iface->proto[GMP_MLD].startup_tries = iface->groups.cfg_v6.robustness;

    int res =
        mrib_attach_querier(&iface->mrib, ifindex, igmp_handle, mld_handle);
    if (res) {
      groups_deinit(&iface->groups);
      list_del(&iface->head);
      free(iface);
      return res;
    }

    ev_timer_set(&iface->timeout, 0);
  }

  list_add(&user->head, &iface->users);
  user->iface = iface;

  list_add(&user->user.head, &querier->ifaces);
  user->user_cb = cb;
  user->user.querier = querier;
  user->user.groups = &iface->groups;

  omgp_time_t now = omgp_time();
  struct group* group;
  groups_for_each_group (group, &iface->groups) {
    querier_announce_iface(user, now, group, true);
  }

  return 0;
}

// Detach an interface from a querier-instance
void querier_detach(struct querier_user_iface* user) {
  struct querier_iface* iface = user->iface;
  list_del(&user->user.head);
  list_del(&user->head);

  omgp_time_t now = omgp_time();
  struct group* group;
  groups_for_each_group (group, &iface->groups) {
    querier_announce_iface(user, now, group, false);
  }

  if (list_empty(&iface->users)) {
    ev_timer_cancel(&iface->timeout);
    groups_deinit(&iface->groups);
    mrib_detach_querier(&iface->mrib);
    list_del(&iface->head);
    free(iface);
  }
}

// Initialize querier-instance
int querier_init(struct querier* querier) {
  memset(querier, 0, sizeof(*querier));
  INIT_LIST_HEAD(&querier->ifaces);
  return 0;
}

// Cleanup querier-instance
void querier_deinit(struct querier* querier) {
  struct querier_user* user;
  struct querier_user* n;
  list_for_each_entry_safe (user, n, &querier->ifaces, head) {
    querier_detach(container_of(user, struct querier_user_iface, user));
  }
}
