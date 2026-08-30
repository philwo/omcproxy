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

#include <stdbool.h>
#include <stdint.h>

#include "list.h"
#include "omcproxy.h"

#define EV_READ (UINT32_C(1) << 0)
#define EV_EDGE (UINT32_C(1) << 1)

struct ev_fd;
typedef void(ev_fd_cb)(struct ev_fd* efd, uint32_t events);

struct ev_fd {
  int fd;
  ev_fd_cb* cb;
  bool registered;
};

struct ev_timer;
typedef void(ev_timer_cb)(struct ev_timer* timer);

struct ev_timer {
  struct list_head head;
  ev_timer_cb* cb;
  omgp_time_t deadline;
  bool pending;
};

int ev_init(void);
void ev_deinit(void);
int ev_run(void);
void ev_break(void);

int ev_fd_add(struct ev_fd* efd, int fd, uint32_t events, ev_fd_cb* cb);
void ev_fd_del(struct ev_fd* efd);

void ev_timer_set(struct ev_timer* timer, omgp_time_t msecs);
void ev_timer_cancel(struct ev_timer* timer);
omgp_time_t ev_timer_remaining(const struct ev_timer* timer);
