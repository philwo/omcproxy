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

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define PROXY_MAX_DOWNLINKS 32

enum proxy_flags {
  PROXY_SCOPE_UNSPEC = 0,

  // minimum scope to proxy (use only one, includes higher scopes)
  PROXY_REALMLOCAL = 3,
  PROXY_ADMINLOCAL = 4,
  PROXY_SITELOCAL = 5,
  PROXY_ORGLOCAL = 8,
  PROXY_GLOBAL = 0xe,

  PROXY_SCOPE_MASK = 0xf,

  // forward to a downlink only while we are that interface's querier
  PROXY_FLAG_STRICT = 0x10,
};

int proxy_set(int uplink,
              const int downlinks[],
              size_t downlinks_cnt,
              enum proxy_flags flags);

void proxy_flush(void);
