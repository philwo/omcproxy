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
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "ev.h"

static int ev_epoll_fd = -1;
static int ev_timer_fd = -1;
static bool ev_running;
static LIST_HEAD(ev_timers);

omgp_time_t omgp_time(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((omgp_time_t)ts.tv_sec * OMGP_TIME_PER_SECOND) +
         ((omgp_time_t)ts.tv_nsec / (1000000000 / OMGP_TIME_PER_SECOND));
}

static void ev_arm_timerfd(void) {
  struct itimerspec its = {};
  if (!list_empty(&ev_timers)) {
    struct ev_timer* t = list_first_entry(&ev_timers, struct ev_timer, head);
    its.it_value.tv_sec = t->deadline / OMGP_TIME_PER_SECOND;
    its.it_value.tv_nsec = (t->deadline % OMGP_TIME_PER_SECOND) * 1000000;
    if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0) {
      its.it_value.tv_nsec = 1;
    }
  }
  timerfd_settime(ev_timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
}

static void ev_run_timers(void) {
  omgp_time_t now = omgp_time();
  while (!list_empty(&ev_timers)) {
    struct ev_timer* t = list_first_entry(&ev_timers, struct ev_timer, head);
    if (t->deadline > now) {
      break;
    }

    list_del(&t->head);
    t->pending = false;
    t->cb(t);
    now = omgp_time();
  }
  ev_arm_timerfd();
}

int ev_init(void) {
  ev_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (ev_epoll_fd < 0) {
    return -errno;
  }

  ev_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (ev_timer_fd < 0) {
    int err = -errno;
    close(ev_epoll_fd);
    ev_epoll_fd = -1;
    return err;
  }

  struct epoll_event ev = {.events = EPOLLIN, .data = {.ptr = NULL}};
  if (epoll_ctl(ev_epoll_fd, EPOLL_CTL_ADD, ev_timer_fd, &ev)) {
    int err = -errno;
    ev_deinit();
    return err;
  }

  return 0;
}

void ev_deinit(void) {
  struct ev_timer* t;
  struct ev_timer* n;
  list_for_each_entry_safe (t, n, &ev_timers, head) {
    ev_timer_cancel(t);
  }

  if (ev_timer_fd >= 0) {
    close(ev_timer_fd);
    ev_timer_fd = -1;
  }
  if (ev_epoll_fd >= 0) {
    close(ev_epoll_fd);
    ev_epoll_fd = -1;
  }
}

int ev_run(void) {
  ev_running = true;
  while (ev_running) {
    struct epoll_event events[8];
    int n = epoll_wait(ev_epoll_fd, events, 8, -1);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -errno;
    }

    for (int i = 0; i < n && ev_running; ++i) {
      if (!events[i].data.ptr) {
        uint64_t expirations;
        while (read(ev_timer_fd, &expirations, sizeof(expirations)) > 0) {
        }
        ev_run_timers();
      } else {
        struct ev_fd* efd = events[i].data.ptr;
        uint32_t out = 0;
        if (events[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
          out |= EV_READ;
        }
        efd->cb(efd, out);
      }
    }
  }
  return 0;
}

void ev_break(void) {
  ev_running = false;
}

int ev_fd_add(struct ev_fd* efd, int fd, uint32_t events, ev_fd_cb* cb) {
  efd->fd = fd;
  efd->cb = cb;

  struct epoll_event ev = {.data = {.ptr = efd}};
  if (events & EV_READ) {
    ev.events |= EPOLLIN;
  }
  if (events & EV_EDGE) {
    ev.events |= EPOLLET;
  }

  if (epoll_ctl(ev_epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
    return -errno;
  }

  efd->registered = true;
  return 0;
}

void ev_fd_del(struct ev_fd* efd) {
  if (!efd->registered) {
    return;
  }
  epoll_ctl(ev_epoll_fd, EPOLL_CTL_DEL, efd->fd, NULL);
  efd->registered = false;
}

void ev_timer_set(struct ev_timer* timer, omgp_time_t msecs) {
  ev_timer_cancel(timer);
  timer->deadline = omgp_time() + msecs;

  struct list_head* pos = &ev_timers;
  struct ev_timer* t;
  list_for_each_entry (t, &ev_timers, head) {
    if (t->deadline > timer->deadline) {
      pos = &t->head;
      break;
    }
  }
  list_add_tail(&timer->head, pos);
  timer->pending = true;
  ev_arm_timerfd();
}

void ev_timer_cancel(struct ev_timer* timer) {
  if (!timer->pending) {
    return;
  }
  list_del(&timer->head);
  timer->pending = false;
  ev_arm_timerfd();
}

omgp_time_t ev_timer_remaining(const struct ev_timer* timer) {
  if (!timer->pending) {
    return -1;
  }
  return timer->deadline - omgp_time();
}
