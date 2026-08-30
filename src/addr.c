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

#include <arpa/inet.h>
#include <string.h>

#include "addr.h"

const char* addr_ntop(char* buf, size_t len, const struct in6_addr* addr) {
  const char* res;
  if (IN6_IS_ADDR_V4MAPPED(addr)) {
    struct in_addr v4;
    memcpy(&v4, &addr->s6_addr[12], sizeof(v4));
    res = inet_ntop(AF_INET, &v4, buf, (socklen_t)len);
  } else {
    res = inet_ntop(AF_INET6, addr, buf, (socklen_t)len);
  }
  return res ? res : "?";
}
