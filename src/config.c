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

#include <errno.h>
#include <string.h>

#include "config.h"

static const struct {
  const char* name;
  enum proxy_flags flags;
} config_scopes[] = {
    {"global", PROXY_GLOBAL},    {"organization", PROXY_ORGLOCAL},
    {"site", PROXY_SITELOCAL},   {"admin", PROXY_ADMINLOCAL},
    {"realm", PROXY_REALMLOCAL},
};

int config_parse_proxy(char* spec, struct proxy_config* out) {
  *out = (struct proxy_config){0};

  char* state = NULL;
  for (char* c = strtok_r(spec, ",", &state); c;
       c = strtok_r(NULL, ",", &state)) {
    if (!strncmp(c, "scope=", 6)) {
      const char* scope = &c[6];
      enum proxy_flags flags = 0;
      for (size_t i = 0; i < sizeof(config_scopes) / sizeof(config_scopes[0]);
           ++i) {
        if (!strcmp(scope, config_scopes[i].name)) {
          flags = config_scopes[i].flags;
        }
      }
      if (!flags) {
        return -EINVAL;
      }
      out->flags = flags;
    } else if (!out->uplink) {
      out->uplink = c;
    } else {
      if (out->downlink_count >= CONFIG_MAX_DOWNLINKS) {
        return -EINVAL;
      }
      out->downlinks[out->downlink_count++] = c;
    }
  }

  if (!out->uplink) {
    return -EINVAL;
  }

  return 0;
}
