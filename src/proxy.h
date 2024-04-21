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

#include <cstdint>
#include <netinet/in.h>

// minimum scope to proxy (use only one, includes higher scopes)
// source: https://datatracker.ietf.org/doc/html/rfc7346#section-2
enum ProxyScope {
  PROXY_REALMLOCAL = 0x3,
  PROXY_ADMINLOCAL = 0x4,
  PROXY_SITELOCAL = 0x5,
  PROXY_ORGLOCAL = 0x8,
  PROXY_GLOBAL = 0xe,
};

class ProxyFlags {
 private:
  ProxyScope scope;
  bool flushable;
  bool unused;

 public:
  ProxyFlags(ProxyScope scope, bool flushable, bool unused)
      : scope(scope), flushable(flushable), unused(unused) {}

  explicit ProxyFlags(ProxyScope scope) : ProxyFlags(scope, false, false) {}

  ProxyFlags() : ProxyFlags(PROXY_GLOBAL) {}

  ProxyScope GetScope();
  bool MatchScope(const struct in6_addr* addr);

  [[nodiscard]] bool IsFlushable() const;
  [[nodiscard]] bool IsUnused() const;
  void SetUnused(bool unused);
};

int proxy_set(unsigned int uplink,
              const unsigned int downlinks[],
              size_t downlinks_cnt,
              ProxyFlags flags);

void proxy_update(bool all);
void proxy_flush();
