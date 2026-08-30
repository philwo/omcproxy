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

#include "groups.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "addr.h"

// Remove a source-definition for a group
static void groups_remove_source(struct group* group,
                                 struct group_source* source) {
  --group->source_count;
  list_del(&source->head);
  free(source);
}

// Clear all sources of a certain group
static void groups_clear_sources(struct group* group) {
  struct group_source* s;
  struct group_source* n;
  list_for_each_entry_safe (s, n, &group->sources, head) {
    groups_remove_source(group, s);
  }
}

static void groups_remove_unlisted_sources(struct group* group,
                                           const struct in6_addr* addrs,
                                           size_t len) {
  struct group_source* source;
  struct group_source* next;
  list_for_each_entry_safe (source, next, &group->sources, head) {
    bool listed = false;
    for (size_t i = 0; i < len; ++i) {
      if (IN6_ARE_ADDR_EQUAL(&source->addr, &addrs[i])) {
        listed = true;
        break;
      }
    }
    if (!listed) {
      groups_remove_source(group, source);
    }
  }
}

// Remove a group and all associated sources from the group state
static void groups_remove_group(struct groups* groups,
                                struct group* group,
                                omgp_time_t now) {
  groups_clear_sources(group);
  group->exclude_until = 0;

  if (groups->cb_update) {
    groups->cb_update(groups, group, now);
  }

  list_del(&group->head);
  free(group);
  --groups->group_count;
}

// Consume a batch of queried sources after a transmission attempt. An
// unsuppressed attempt rebases the lowered deadline on the actual attempt
// time and the remaining schedule (capped at the natural deadline), so an
// overdue dispatch or a failed send cannot expire the source before its
// queries were sent plus one response window. Suppressed queries must not
// modify timers (RFC 3810 7.6.1). A skipped attempt means another querier
// won the election: cancel the schedule and leave the timers it set alone.
static void finish_source_batch(struct group* group,
                                struct list_head* batch,
                                enum groups_query_result result,
                                bool suppress,
                                omgp_time_t now,
                                omgp_time_t next_transmit,
                                omgp_time_t interval) {
  struct group_source* source;
  list_for_each_entry (source, batch, head) {
    if (result == GROUPS_QUERY_SENT) {
      --source->retransmit;
    } else if (result == GROUPS_QUERY_SKIPPED) {
      source->retransmit = 0;
    }
    if (result != GROUPS_QUERY_SKIPPED && !suppress &&
        source->include_until > 0 &&
        source->include_until < source->expire_cap) {
      omgp_time_t deadline = now + (source->retransmit + 1) * interval;
      if (deadline > source->expire_cap) {
        deadline = source->expire_cap;
      }
      if (deadline > source->include_until) {
        source->include_until = deadline;
      }
    }
    if (source->retransmit > 0) {
      group->next_source_transmit = next_transmit;
    }
  }
  list_splice_init(batch, &group->sources);
}

// Expire a group and / or its associated sources depending on the current time
static omgp_time_t expire_group(struct groups* groups,
                                struct group* group,
                                omgp_time_t now,
                                omgp_time_t next_event) {
  struct groups_config* cfg =
      IN6_IS_ADDR_V4MAPPED(&group->addr) ? &groups->cfg_v4 : &groups->cfg_v6;
  omgp_time_t llqi = now + cfg->last_listener_query_interval;
  omgp_time_t llqt = now + (cfg->last_listener_query_interval *
                            cfg->last_listener_query_count);

  // Handle group and source-specific query retransmission
  struct list_head suppressed = LIST_HEAD_INIT(suppressed);
  struct list_head unsuppressed = LIST_HEAD_INIT(unsuppressed);
  struct group_source* s;
  struct group_source* s2;

  if (group->retransmit > 0 && group->expire_cap <= now) {
    group->retransmit = 0;
    group->next_generic_transmit = 0;
  }

  bool source_retransmit = false;
  list_for_each_entry (s, &group->sources, head) {
    if (s->retransmit > 0 && s->expire_cap <= now) {
      s->retransmit = 0;
    }
    if (s->retransmit > 0) {
      source_retransmit = true;
    }
  }
  if (!source_retransmit) {
    group->next_source_transmit = 0;
  }

  if (group->next_source_transmit > 0 && group->next_source_transmit <= now) {
    group->next_source_transmit = 0;

    list_for_each_entry_safe (s, s2, &group->sources, head) {
      if (s->retransmit > 0) {
        list_move_tail(&s->head,
                       (s->include_until > llqt) ? &suppressed : &unsuppressed);
      }
    }
  }

  // Handle group-specific query retransmission
  if (group->retransmit > 0 && group->next_generic_transmit <= now) {
    group->next_generic_transmit = 0;

    bool suppress = group->exclude_until > llqt;
    enum groups_query_result result =
        groups->cb_query
            ? groups->cb_query(groups, &group->addr, NULL, suppress)
            : GROUPS_QUERY_SENT;
    if (result == GROUPS_QUERY_SENT) {
      --group->retransmit;
    } else if (result == GROUPS_QUERY_SKIPPED) {
      group->retransmit = 0;
    }

    if (result != GROUPS_QUERY_SKIPPED && !suppress &&
        group->exclude_until > 0 && group->exclude_until < group->expire_cap) {
      omgp_time_t deadline =
          now + (group->retransmit + 1) * cfg->last_listener_query_interval;
      if (deadline > group->expire_cap) {
        deadline = group->expire_cap;
      }
      if (deadline > group->exclude_until) {
        group->exclude_until = deadline;
      }
    }

    if (group->retransmit > 0) {
      group->next_generic_transmit = llqi;
    }

    // Skip suppresed source-specific query (RFC 3810 7.6.3.2)
    finish_source_batch(group, &suppressed, result, true, now, llqi,
                        cfg->last_listener_query_interval);
  }

  if (group->next_generic_transmit > 0 &&
      group->next_generic_transmit < next_event) {
    next_event = group->next_generic_transmit;
  }

  if (!list_empty(&suppressed)) {
    enum groups_query_result result =
        groups->cb_query
            ? groups->cb_query(groups, &group->addr, &suppressed, true)
            : GROUPS_QUERY_SENT;
    finish_source_batch(group, &suppressed, result, true, now, llqi,
                        cfg->last_listener_query_interval);
  }

  if (!list_empty(&unsuppressed)) {
    enum groups_query_result result =
        groups->cb_query
            ? groups->cb_query(groups, &group->addr, &unsuppressed, false)
            : GROUPS_QUERY_SENT;
    finish_source_batch(group, &unsuppressed, result, false, now, llqi,
                        cfg->last_listener_query_interval);
  }

  if (group->next_source_transmit > 0 &&
      group->next_source_transmit < next_event) {
    next_event = group->next_source_transmit;
  }

  // Handle source and group expiry
  bool changed = false;
  if (group->exclude_until > 0) {
    if (group_is_included(group, now)) {
      // Leaving exclude mode
      group->exclude_until = 0;
      changed = true;
    } else if (group->exclude_until > now &&
               group->exclude_until < next_event) {
      next_event = group->exclude_until;
    }
  }

  list_for_each_entry_safe (s, s2, &group->sources, head) {
    if (s->include_until > 0) {
      if (!source_is_included(s, now)) {
        s->include_until = 0;
        changed = true;
      } else if (s->include_until > now && s->include_until < next_event) {
        next_event = s->include_until;
      }
    }

    if (group->exclude_until == 0 && s->include_until == 0) {
      groups_remove_source(group, s);
    }
  }

  if (group->exclude_until == 0 && group->source_count == 0) {
    groups_remove_group(groups, group, now);
  } else if (changed && groups->cb_update) {
    groups->cb_update(groups, group, now);
  }

  return next_event;
}

// Rearm the global groups-timer if the next event is before timer expiration
static void rearm_timer(struct groups* groups, omgp_time_t msecs) {
  omgp_time_t remain = ev_timer_remaining(&groups->timer);
  if (remain < 0 || remain >= msecs) {
    ev_timer_set(&groups->timer, msecs);
  }
}

// Expire all groups of a group-state (called by timer as callback)
static void expire_groups(struct ev_timer* t) {
  struct groups* groups = container_of(t, struct groups, timer);
  omgp_time_t now = omgp_time();
  omgp_time_t next_event = now + 3600 * OMGP_TIME_PER_SECOND;

  struct group* group;
  struct group* n;
  list_for_each_entry_safe (group, n, &groups->groups, head) {
    next_event = expire_group(groups, group, now, next_event);
  }

  rearm_timer(groups, (next_event > now) ? next_event - now : 0);
}

// Initialize a group-state
void groups_init(struct groups* groups) {
  INIT_LIST_HEAD(&groups->groups);
  groups->timer.cb = expire_groups;
  groups->group_count = 0;
  groups->group_limit = SIZE_MAX;
  groups->source_limit = SIZE_MAX;

  groups_update_config(groups, false, OMGP_TIME_PER_SECOND * 10,
                       125 * OMGP_TIME_PER_SECOND, 2);
  groups_update_config(groups, true, OMGP_TIME_PER_SECOND * 10,
                       125 * OMGP_TIME_PER_SECOND, 2);
}

// Cleanup a group-state
void groups_deinit(struct groups* groups) {
  omgp_time_t now = omgp_time();
  struct group* group;
  struct group* safe;
  list_for_each_entry_safe (group, safe, &groups->groups, head) {
    groups_remove_group(groups, group, now);
  }
  ev_timer_cancel(&groups->timer);
}

// Get group-object for a given group, create if requested
static struct group* groups_get_group(struct groups* groups,
                                      const struct in6_addr* addr,
                                      bool* created) {
  struct group* c;
  struct group* group = NULL;
  groups_for_each_group (c, groups) {
    if (IN6_ARE_ADDR_EQUAL(&c->addr, addr)) {
      group = c;
      break;
    }
  }

  if (!group && created) {
    if (groups->group_count < groups->group_limit) {
      group = calloc(1, sizeof(*group));
    }
    if (group) {
      group->addr = *addr;
      list_add_tail(&group->head, &groups->groups);
      ++groups->group_count;
      INIT_LIST_HEAD(&group->sources);
    }
    *created = group != NULL;
  } else if (created) {
    *created = false;
  }
  return group;
}

// Get source-object for a given source, create if requested
static struct group_source* groups_get_source(struct groups* groups,
                                              struct group* group,
                                              const struct in6_addr* addr,
                                              bool* created) {
  struct group_source* c;
  struct group_source* source = NULL;
  group_for_each_source (c, group) {
    if (IN6_ARE_ADDR_EQUAL(&c->addr, addr)) {
      source = c;
    }
  }

  if (!source && created && group->source_count < groups->source_limit) {
    source = calloc(1, sizeof(*source));
    if (source) {
      source->addr = *addr;
      list_add_tail(&source->head, &group->sources);
      ++group->source_count;
    }
    *created = source != NULL;
  } else if (created) {
    *created = false;
  }

  return source;
}

// Update the IGMP/MLD timers of a group-state
void groups_update_config(struct groups* groups,
                          bool v6,
                          omgp_time_t query_response_interval,
                          omgp_time_t query_interval,
                          int robustness) {
  struct groups_config* cfg = v6 ? &groups->cfg_v6 : &groups->cfg_v4;
  cfg->query_response_interval = query_response_interval;
  cfg->query_interval = query_interval;
  cfg->robustness = robustness;
  cfg->last_listener_query_count = cfg->robustness;
  cfg->last_listener_query_interval = 1 * OMGP_TIME_PER_SECOND;
}

// Update timers for a given group (called when receiving queries from other
// queriers)
void groups_update_timers(struct groups* groups,
                          const struct in6_addr* groupaddr,
                          const struct in6_addr* addrs,
                          size_t len,
                          omgp_time_t last_listener_query_interval,
                          int last_listener_query_count) {
  char addrbuf[ADDR_BUFLEN];
  addr_ntop(addrbuf, sizeof(addrbuf), groupaddr);
  struct group* group = groups_get_group(groups, groupaddr, NULL);
  if (!group) {
    L_DEBUG("%s: no state for queried group %s", __FUNCTION__, addrbuf);
    return;
  }

  omgp_time_t now = omgp_time();
  omgp_time_t llqt =
      now + (last_listener_query_interval * last_listener_query_count);

  if (len == 0) {
    if (group->exclude_until > llqt) {
      group->exclude_until = llqt;
    }
    if (group->expire_cap > group->exclude_until) {
      group->expire_cap = group->exclude_until;
    }
  } else {
    size_t unknown = 0;
    for (size_t i = 0; i < len; ++i) {
      struct group_source* source =
          groups_get_source(groups, group, &addrs[i], NULL);
      if (!source) {
        ++unknown;
        continue;
      }

      if (source->include_until > llqt) {
        source->include_until = llqt;
      }
      if (source->expire_cap > source->include_until) {
        source->expire_cap = source->include_until;
      }
    }
    if (unknown) {
      L_DEBUG("%s: %d unknown sources queried for group %s", __FUNCTION__,
              (int)unknown, addrbuf);
    }
  }

  rearm_timer(groups, llqt - now);
}

// Update state of a given group (on reception of node's IGMP/MLD packets)
void groups_update_state(struct groups* groups,
                         const struct in6_addr* groupaddr,
                         const struct in6_addr* addrs,
                         size_t len,
                         enum groups_update update) {
  bool created = false;
  bool changed = false;
  char addrbuf[ADDR_BUFLEN];
  addr_ntop(addrbuf, sizeof(addrbuf), groupaddr);
  L_DEBUG("%s: %s (+%d sources) => %d", __FUNCTION__, addrbuf, (int)len,
          update);

  struct group* group = groups_get_group(groups, groupaddr, &created);
  if (!group) {
    L_ERR("%s: failed to allocate group for %s", __FUNCTION__, addrbuf);
    return;
  }

  if (created) {
    changed = true;
  }

  omgp_time_t now = omgp_time();
  omgp_time_t next_event = OMGP_TIME_MAX;
  struct groups_config* cfg =
      IN6_IS_ADDR_V4MAPPED(&group->addr) ? &groups->cfg_v4 : &groups->cfg_v6;

  // Backwards compatibility modes
  if (group->compat_v2_until > now || group->compat_v1_until > now) {
    if (update == UPDATE_BLOCK) {
      return;
    }

    if (group->compat_v1_until > now &&
        (update == UPDATE_DONE || update == UPDATE_TO_IN)) {
      return;
    }

    if (update == UPDATE_TO_EX) {
      len = 0;
    }
  }

  if (update == UPDATE_REPORT || update == UPDATE_REPORT_V1 ||
      update == UPDATE_DONE) {
    omgp_time_t compat_until = now + cfg->query_response_interval +
                               (cfg->robustness * cfg->query_interval);

    if (update == UPDATE_REPORT_V1) {
      group->compat_v1_until = compat_until;
    } else if (update == UPDATE_REPORT) {
      group->compat_v2_until = compat_until;
    }

    update = (update == UPDATE_DONE) ? UPDATE_TO_IN : UPDATE_IS_EXCLUDE;
    len = 0;
  }

  bool include = group_is_included(group, now);
  omgp_time_t filter_until = group->exclude_until;
  if (!include && filter_until <= now) {
    filter_until = group->expire_cap;
  }
  bool is_include = update == UPDATE_IS_INCLUDE || update == UPDATE_TO_IN ||
                    update == UPDATE_ALLOW;

  int llqc = cfg->last_listener_query_count;
  omgp_time_t mali = now + (cfg->robustness * cfg->query_interval) +
                     cfg->query_response_interval;
  omgp_time_t llqt = now + (cfg->last_listener_query_interval * llqc);

  // RFC 3810 7.4
  struct list_head queried = LIST_HEAD_INIT(queried);
  for (size_t i = 0; i < len; ++i) {
    bool duplicate = false;
    for (size_t j = 0; j < i && !duplicate; ++j) {
      duplicate = IN6_ARE_ADDR_EQUAL(&addrs[i], &addrs[j]);
    }
    if (duplicate) {
      continue;
    }

    bool* create = (include && update == UPDATE_BLOCK) ? NULL : &created;
    struct group_source* source =
        groups_get_source(groups, group, &addrs[i], create);

    if (include && update == UPDATE_BLOCK) {
      if (source) {
        list_move_tail(&source->head, &queried);
      }
    } else {
      bool query = false;
      if (!source) {
        list_splice(&queried, &group->sources);
        groups_update_state(groups, groupaddr, NULL, 0, UPDATE_IS_EXCLUDE);
        L_WARN("%s: failed to allocate source for %s, fallback to ASM",
               __FUNCTION__, addrbuf);
        return;
      }

      if (created) {
        changed = true;
      } else if (include && update == UPDATE_TO_EX) {
        query = true;
      }

      if (source->include_until <= now && update == UPDATE_SET_IN) {
        source->include_until = mali;
        source->expire_cap = mali;
        changed = true;
      } else if (source->include_until > now && update == UPDATE_SET_EX) {
        source->include_until = now;
        source->expire_cap = now;
        changed = true;
      }

      if (!include && (update == UPDATE_BLOCK || update == UPDATE_TO_EX) &&
          (created || source->include_until > now)) {
        query = true;
      }

      if ((is_include || (!include && created))) {
        if (source->include_until <= now) {
          changed = true;
        }

        source->include_until =
            (is_include || update == UPDATE_IS_EXCLUDE) ? mali : filter_until;
        source->expire_cap = source->include_until;

        if (next_event > mali) {
          next_event = mali;
        }
      }

      if (query) {
        list_move_tail(&source->head, &queried);
      }
    }
  }

  if (update == UPDATE_IS_EXCLUDE || update == UPDATE_TO_EX ||
      update == UPDATE_SET_EX) {
    if (include || !list_empty(&group->sources)) {
      changed = true;
    }

    groups_remove_unlisted_sources(group, addrs, len);
    group->exclude_until = mali;
    group->expire_cap = mali;

    if (next_event > mali) {
      next_event = mali;
    }
  }

  if (update == UPDATE_SET_IN) {
    if (!include || !list_empty(&group->sources)) {
      changed = true;
      next_event = now;
    }

    groups_remove_unlisted_sources(group, addrs, len);
    group->exclude_until = now;
    group->expire_cap = now;
  }

  // Prepare queries
  if (update == UPDATE_TO_IN) {
    struct group_source* source;
    struct group_source* n;
    list_for_each_entry_safe (source, n, &group->sources, head) {
      if (source->include_until <= now) {
        continue;
      }

      size_t i;
      for (i = 0; i < len && !IN6_ARE_ADDR_EQUAL(&source->addr, &addrs[i]);
           ++i) {
      }
      if (i == len) {
        list_move_tail(&source->head, &queried);
      }
    }
  }

  if (!list_empty(&queried)) {
    struct group_source* source;
    list_for_each_entry (source, &queried, head) {
      if (source->include_until > llqt) {
        source->include_until = llqt;
        source->retransmit = llqc;
        group->next_source_transmit = now;
        next_event = now;
      } else if (source->retransmit > 0) {
        group->next_source_transmit = now;
        next_event = now;
      }
    }

    list_splice(&queried, &group->sources);
  }

  if (!include && update == UPDATE_TO_IN) {
    if (group->exclude_until > llqt) {
      group->exclude_until = llqt;
    }

    group->next_generic_transmit = now;
    group->retransmit = llqc;
    next_event = now;
  }

  if (changed && groups->cb_update) {
    groups->cb_update(groups, group, now);
  }

  if (group_is_included(group, now) && group->source_count == 0) {
    next_event = now;
  }

  if (next_event < OMGP_TIME_MAX) {
    rearm_timer(groups, next_event - now);
  }

  if (changed) {
    L_DEBUG("%s: %s => %s (+%d sources)", __FUNCTION__, addrbuf,
            (group_is_included(group, now)) ? "included" : "excluded",
            (int)group->source_count);
  }
}

// Get group object of a given group
const struct group* groups_get(struct groups* groups,
                               const struct in6_addr* addr) {
  return groups_get_group(groups, addr, NULL);
}

// Test if a group (and source) is requested in the current group state
// (i.e. for deciding if it should be routed / forwarded)
bool groups_includes_group(struct groups* groups,
                           const struct in6_addr* addr,
                           const struct in6_addr* src,
                           omgp_time_t time) {
  struct group* group = groups_get_group(groups, addr, NULL);
  if (group) {
    if (!src) {
      return !group_is_included(group, time) || group->source_count > 0;
    }

    struct group_source* source = groups_get_source(groups, group, src, NULL);
    if ((!group_is_included(group, time) &&
         (!source || source_is_included(source, time))) ||
        (group_is_included(group, time) && source &&
         source_is_included(source, time))) {
      return true;
    }
  }
  return false;
}
