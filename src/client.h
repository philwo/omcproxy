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

#include <cstdlib>
#include <netinet/in.h>

#include "omcproxy.h"

struct Client {
  int igmp_fd;
  int mld_fd;
  int ifindex;
};

// Register a new interface to proxy
int client_init(struct Client* client, int ifindex);

// Deregister a new interface from proxy
void client_deinit(struct Client* client);

// Set / update / delete a multicast proxy entry
int client_set(struct Client* client,
               const struct in6_addr* group,
               bool include,
               const struct in6_addr sources[],
               size_t cnt);

// Unmap IPv4 address
void client_unmap(struct in_addr* addr4, const struct in6_addr* addr6);
