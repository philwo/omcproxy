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

#include <stddef.h>

#include "proxy.h"

#define CONFIG_MAX_DOWNLINKS PROXY_MAX_DOWNLINKS

struct proxy_config {
  const char* uplink;
  const char* downlinks[CONFIG_MAX_DOWNLINKS];
  size_t downlink_count;
  enum proxy_flags flags;
};

int config_parse_proxy(char* spec, struct proxy_config* out);
