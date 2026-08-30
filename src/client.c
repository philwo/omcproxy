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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "client.h"

#define CLIENT_RETRY_MIN (1 * OMGP_TIME_PER_SECOND)
#define CLIENT_RETRY_MAX (64 * OMGP_TIME_PER_SECOND)

struct client_sock {
  struct list_head head;
  int fd;
  size_t groups;
};

// Desired membership state and the state last applied to the kernel
struct client_membership {
  struct list_head head;
  struct in6_addr group;
  struct client_sock* sock;
  bool dirty;
  bool include;
  size_t cnt;
  bool applied_include;
  size_t applied_cnt;
  struct in6_addr sources[CLIENT_MAX_SOURCES];
  struct in6_addr applied[CLIENT_MAX_SOURCES];
};

static int client_family(const struct in6_addr* group) {
  return IN6_IS_ADDR_V4MAPPED(group) ? AF_INET : AF_INET6;
}

static struct list_head* client_socks(struct client* client, int family) {
  return (family == AF_INET) ? &client->socks_v4 : &client->socks_v6;
}

static void client_fill_addr(struct sockaddr_storage* ss,
                             int family,
                             const struct in6_addr* addr) {
  if (family == AF_INET) {
    struct sockaddr_in* sin = (struct sockaddr_in*)ss;
    sin->sin_family = AF_INET;
    client_unmap(&sin->sin_addr, addr);
  } else {
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = *addr;
  }
}

// Open one more membership socket for the family
static int client_sock_open(struct client* client,
                            int family,
                            struct client_sock** out) {
  struct client_sock* sock = calloc(1, sizeof(*sock));
  if (!sock) {
    return -ENOMEM;
  }

  sock->fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sock->fd < 0) {
    int res = -errno;
    free(sock);
    return res;
  }

  list_add_tail(&sock->head, client_socks(client, family));
  *out = sock;
  return 0;
}

// Join the group on a pool socket with room, growing the pool on ENOBUFS
static int client_membership_join(struct client* client,
                                  struct client_membership* m) {
  int family = client_family(&m->group);
  int sol = (family == AF_INET) ? SOL_IP : SOL_IPV6;
  struct group_req req = {.gr_interface = (uint32_t)client->ifindex};
  client_fill_addr(&req.gr_group, family, &m->group);

  struct client_sock* sock;
  list_for_each_entry (sock, client_socks(client, family), head) {
    if (!setsockopt(sock->fd, sol, MCAST_JOIN_GROUP, &req, sizeof(req))) {
      m->sock = sock;
      ++sock->groups;
      return 0;
    }
    if (errno != ENOBUFS) {
      return -errno;
    }
  }

  int res = client_sock_open(client, family, &sock);
  if (res) {
    return res;
  }

  if (setsockopt(sock->fd, sol, MCAST_JOIN_GROUP, &req, sizeof(req))) {
    res = -errno;
    list_del(&sock->head);
    close(sock->fd);
    free(sock);
    return res;
  }

  m->sock = sock;
  ++sock->groups;
  return 0;
}

static void client_membership_leave(struct client* client,
                                    struct client_membership* m) {
  if (!m->sock) {
    return;
  }

  int family = client_family(&m->group);
  int sol = (family == AF_INET) ? SOL_IP : SOL_IPV6;
  struct group_req req = {.gr_interface = (uint32_t)client->ifindex};
  client_fill_addr(&req.gr_group, family, &m->group);

  setsockopt(m->sock->fd, sol, MCAST_LEAVE_GROUP, &req, sizeof(req));
  --m->sock->groups;
  m->sock = NULL;
}

static bool client_filter_applied(const struct client_membership* m) {
  return m->applied_include == m->include && m->applied_cnt == m->cnt &&
         !memcmp(m->applied, m->sources, m->cnt * sizeof(m->sources[0]));
}

static int client_membership_filter(struct client* client,
                                    struct client_membership* m) {
  int family = client_family(&m->group);
  int sol = (family == AF_INET) ? SOL_IP : SOL_IPV6;
  size_t len = GROUP_FILTER_SIZE(m->cnt);
  union {
    struct group_filter f;
    uint8_t buf[GROUP_FILTER_SIZE(CLIENT_MAX_SOURCES)];
  } fu;
  struct group_filter* filter = &fu.f;

  memset(&fu, 0, len);
  filter->gf_interface = (uint32_t)client->ifindex;
  filter->gf_fmode = m->include ? MCAST_INCLUDE : MCAST_EXCLUDE;
  filter->gf_numsrc = (uint32_t)m->cnt;
  client_fill_addr(&filter->gf_group, family, &m->group);
  for (size_t i = 0; i < m->cnt; ++i) {
    client_fill_addr(&filter->gf_slist[i], family, &m->sources[i]);
  }

  if (setsockopt(m->sock->fd, sol, MCAST_MSFILTER, filter, (socklen_t)len)) {
    return -errno;
  }

  m->applied_include = m->include;
  m->applied_cnt = m->cnt;
  memcpy(m->applied, m->sources, m->cnt * sizeof(m->sources[0]));
  return 0;
}

// Drive the kernel state towards the desired state; keep the membership
// dirty for a retry when a step fails. A failed filter update keeps the
// current (broader) kernel filter rather than dropping the membership.
static void client_membership_apply(struct client* client,
                                    struct client_membership* m) {
  char addrbuf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &m->group, addrbuf, sizeof(addrbuf));

  if (m->include && m->cnt == 0) {
    client_membership_leave(client, m);
    list_del(&m->head);
    free(m);
    return;
  }

  if (!m->sock) {
    int res = client_membership_join(client, m);
    if (res) {
      L_WARN("%s: failed to join %s on %d: %s%s", __FUNCTION__, addrbuf,
             client->ifindex, strerror(-res),
             (res == -ENOBUFS) ? " (check igmp_max_memberships?)" : "");
      m->dirty = true;
      return;
    }
    m->applied_include = false;
    m->applied_cnt = 0;
  }

  if (client_filter_applied(m)) {
    m->dirty = false;
    return;
  }

  int res = client_membership_filter(client, m);
  if (res) {
    L_WARN("%s: failed to apply source filter for %s on %d: %s%s", __FUNCTION__,
           addrbuf, client->ifindex, strerror(-res),
           (res == -ENOBUFS) ? " (check igmp_max_msf?)" : "");
    m->dirty = true;
    return;
  }

  m->dirty = false;
}

static bool client_dirty(struct client* client) {
  struct client_membership* m;
  list_for_each_entry (m, &client->memberships, head) {
    if (m->dirty) {
      return true;
    }
  }
  return false;
}

static void client_reschedule(struct client* client) {
  if (!client_dirty(client)) {
    ev_timer_cancel(&client->retry);
    client->backoff = CLIENT_RETRY_MIN;
    return;
  }

  if (client->retry.pending) {
    return;
  }

  ev_timer_set(&client->retry, client->backoff);
}

// Reapply memberships whose kernel state diverges (called by timer)
static void client_retry(struct ev_timer* t) {
  struct client* client = container_of(t, struct client, retry);
  if (client->backoff < CLIENT_RETRY_MAX) {
    client->backoff *= 2;
  }

  struct client_membership* m;
  struct client_membership* n;
  list_for_each_entry_safe (m, n, &client->memberships, head) {
    if (m->dirty) {
      client_membership_apply(client, m);
    }
  }

  client_reschedule(client);
}

// Add / update / remove a client entry for a multicast group
void client_set(struct client* client,
                const struct in6_addr* group,
                bool include,
                const struct in6_addr sources[],
                size_t cnt) {
  if (cnt > CLIENT_MAX_SOURCES) {
    cnt = CLIENT_MAX_SOURCES;
  }

  struct client_membership* c;
  struct client_membership* m = NULL;
  list_for_each_entry (c, &client->memberships, head) {
    if (IN6_ARE_ADDR_EQUAL(&c->group, group)) {
      m = c;
      break;
    }
  }

  char addrbuf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, group, addrbuf, sizeof(addrbuf));
  L_DEBUG("%s: %s on %d => %s (+%d sources)", __FUNCTION__, addrbuf,
          client->ifindex, (include) ? "include" : "exclude", (int)cnt);

  if (!m) {
    if (include && cnt == 0) {
      return;
    }

    m = calloc(1, sizeof(*m));
    if (!m) {
      L_ERR("%s: failed to allocate membership for %s", __FUNCTION__, addrbuf);
      return;
    }
    m->group = *group;
    list_add_tail(&m->head, &client->memberships);
  }

  m->include = include;
  m->cnt = cnt;
  if (cnt) {
    memcpy(m->sources, sources, cnt * sizeof(*sources));
  }
  m->dirty = true;

  client_membership_apply(client, m);
  client_reschedule(client);
}

// Initialize client-instance
int client_init(struct client* client, int ifindex) {
  client->ifindex = ifindex;
  client->backoff = CLIENT_RETRY_MIN;
  client->retry = (struct ev_timer){.cb = client_retry};
  INIT_LIST_HEAD(&client->socks_v4);
  INIT_LIST_HEAD(&client->socks_v6);
  INIT_LIST_HEAD(&client->memberships);

  struct client_sock* sock;
  int res = client_sock_open(client, AF_INET, &sock);
  if (res) {
    return res;
  }
  res = client_sock_open(client, AF_INET6, &sock);
  if (res) {
    client_deinit(client);
    return res;
  }
  return 0;
}

// Cleanup client-instance
void client_deinit(struct client* client) {
  ev_timer_cancel(&client->retry);

  struct client_membership* m;
  struct client_membership* n;
  list_for_each_entry_safe (m, n, &client->memberships, head) {
    list_del(&m->head);
    free(m);
  }

  struct client_sock* sock;
  struct client_sock* sock2;
  list_for_each_entry_safe (sock, sock2, &client->socks_v4, head) {
    list_del(&sock->head);
    close(sock->fd);
    free(sock);
  }
  list_for_each_entry_safe (sock, sock2, &client->socks_v6, head) {
    list_del(&sock->head);
    close(sock->fd);
    free(sock);
  }
  client->ifindex = 0;
}
