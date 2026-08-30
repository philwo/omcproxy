/*
 * Copyright 2015 Steven Barth <steven at midlink.org>
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

#include <endian.h>
#include <netinet/in.h>

#define ADDR_BUFLEN INET6_ADDRSTRLEN

const char* addr_ntop(char* buf, size_t len, const struct in6_addr* addr);

static inline void addr_map(struct in6_addr* addr6, in_addr_t addr4) {
  addr6->s6_addr32[0] = 0;
  addr6->s6_addr32[1] = 0;
  addr6->s6_addr32[2] = htobe32(0xffff);
  addr6->s6_addr32[3] = addr4;
}

static inline in_addr_t addr_unmap(const struct in6_addr* addr6) {
  return addr6->s6_addr32[3];
}

static inline bool addr_is_ssm(const struct in6_addr* addr) {
  if (IN6_IS_ADDR_V4MAPPED(addr)) {
    return addr->s6_addr[12] == 232;
  }
  return addr->s6_addr[0] == 0xff && (addr->s6_addr[1] & 0xf0) == 0x30 &&
         addr->s6_addr[2] == 0 && addr->s6_addr[3] == 0;
}
