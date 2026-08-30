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

#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>

typedef int64_t omgp_time_t;
#define OMGP_TIME_MAX INT64_MAX
#define OMGP_TIME_PER_SECOND INT64_C(1000)

omgp_time_t omgp_time(void);

#ifndef L_LEVEL
#define L_LEVEL LOG_WARNING
#endif

#define L_INTERNAL(level, ...) syslog(level, __VA_ARGS__)

#define L_ERR(...) L_INTERNAL(LOG_ERR, __VA_ARGS__)
#define L_WARN(...) L_INTERNAL(LOG_WARNING, __VA_ARGS__)
#define L_NOTICE(...) L_INTERNAL(LOG_NOTICE, __VA_ARGS__)
#define L_INFO(...) L_INTERNAL(LOG_INFO, __VA_ARGS__)
#define L_DEBUG(...) L_INTERNAL(LOG_DEBUG, __VA_ARGS__)

#ifndef container_of
#define container_of(ptr, type, member) \
  ((type*)((char*)ptr - offsetof(type, member)))
#endif
