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
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/mroute6.h>
#include <netinet/in.h>
#include "list.h"

#include "client.h"

// Add / update / remove a client entry for a multicast group
int client_set(struct client* client,
               const struct in6_addr* group,
               bool include,
               const struct in6_addr sources[],
               size_t cnt) {
  int family = (IN6_IS_ADDR_V4MAPPED(group)) ? AF_INET : AF_INET6;
  int sol = (family == AF_INET) ? SOL_IP : SOL_IPV6;
  char addrbuf[INET6_ADDRSTRLEN];

  if (cnt > CLIENT_MAX_SOURCES) {
    cnt = CLIENT_MAX_SOURCES;
  }
  size_t len =
      sizeof(struct group_filter) + cnt * sizeof(struct sockaddr_storage);
  union {
    struct group_filter f;
    uint8_t buf[sizeof(struct group_filter) +
                CLIENT_MAX_SOURCES * sizeof(struct sockaddr_storage)];
  } storage;
  struct group_filter* filter = &storage.f;
  struct sockaddr_in* in_addr = (struct sockaddr_in*)&filter->gf_group;
  struct sockaddr_in6* in6_addr = (struct sockaddr_in6*)&filter->gf_group;

  inet_ntop(AF_INET6, group, addrbuf, sizeof(addrbuf));
  L_DEBUG("%s: %s on %d => %s (+%d sources)", __FUNCTION__, addrbuf,
          client->ifindex, (include) ? "include" : "exclude", (int)cnt);

  // Construct MSFILTER for outgoing IGMP / MLD
  memset(&storage, 0, len);
  filter->gf_interface = (uint32_t)client->ifindex;
  filter->gf_fmode = include ? MCAST_INCLUDE : MCAST_EXCLUDE;
  filter->gf_group.ss_family = (sa_family_t)family;
  filter->gf_numsrc = (uint32_t)cnt;

  if (family == AF_INET) {
    client_unmap(&in_addr->sin_addr, group);
  } else {
    in6_addr->sin6_addr = *group;
  }

  for (size_t i = 0; i < cnt; ++i) {
    filter->gf_slist[i].ss_family = (sa_family_t)family;

    in_addr = (struct sockaddr_in*)&filter->gf_slist[i];
    in6_addr = (struct sockaddr_in6*)&filter->gf_slist[i];

    if (family == AF_INET) {
      client_unmap(&in_addr->sin_addr, &sources[i]);
    } else {
      in6_addr->sin6_addr = sources[i];
    }
  }

  int fd = (family == AF_INET) ? client->igmp_fd : client->mld_fd;
  setsockopt(fd, sol, MCAST_LEAVE_GROUP, filter, sizeof(struct group_req));
  if (!include || cnt > 0) {
    if (setsockopt(fd, sol, MCAST_JOIN_GROUP, filter,
                   sizeof(struct group_req)) &&
        family == AF_INET && errno == ENOBUFS) {
      L_WARN(
          "proxy: kernel denied joining multicast group. check "
          "igmp_max_memberships?");
      return -errno;
    }

    if (setsockopt(fd, sol, MCAST_MSFILTER, filter, (socklen_t)len)) {
      return -errno;
    }
  }
  return 0;
}

// Initialize client-instance
int client_init(struct client* client, int ifindex) {
  *client = (struct client){.igmp_fd = -1, .mld_fd = -1};
  client->igmp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (client->igmp_fd < 0) {
    return -errno;
  }

  client->mld_fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (client->mld_fd < 0) {
    int err = -errno;
    close(client->igmp_fd);
    client->igmp_fd = -1;
    return err;
  }

  client->ifindex = ifindex;
  return 0;
}

// Cleanup client-instance
void client_deinit(struct client* client) {
  if (client->igmp_fd >= 0) {
    close(client->igmp_fd);
  }
  if (client->mld_fd >= 0) {
    close(client->mld_fd);
  }
  *client = (struct client){.igmp_fd = -1, .mld_fd = -1};
}
