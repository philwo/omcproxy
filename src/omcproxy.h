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

#ifndef L_PREFIX
#define L_PREFIX ""
#endif /* !L_PREFIX */

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <sys/types.h>
#include <syslog.h>

#include <libubox/utils.h>

typedef int64_t omcp_time_t;
#define OMCP_TIME_MAX INT64_MAX
#define OMCP_TIME_PER_SECOND INT64_C(1000)

extern long log_level;

omcp_time_t omcp_time();

// Logging macros

#define L_INTERNAL(level, ...)             \
  do {                                     \
    if (log_level >= level)                \
      syslog(level, L_PREFIX __VA_ARGS__); \
  } while (0)

#define L_ERR(...) L_INTERNAL(LOG_ERR, __VA_ARGS__)
#define L_WARN(...) L_INTERNAL(LOG_WARNING, __VA_ARGS__)
#define L_INFO(...) L_INTERNAL(LOG_INFO, __VA_ARGS__)
#define L_DEBUG(...) L_INTERNAL(LOG_DEBUG, __VA_ARGS__)
