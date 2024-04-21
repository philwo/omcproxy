/*
 * uloop - event loop implementation
 *
 * Copyright (C) 2010-2016 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>

#include "uloop.h"
#include "utils.h"

struct UloopFDEvent {
  struct UloopFD* fd;
  unsigned int events;
};

struct UloopFDStack {
  struct UloopFDStack* next;
  struct UloopFD* fd;
  unsigned int events;
};

static struct UloopFDStack* fd_stack = nullptr;

#define ULOOP_MAX_EVENTS 10

static struct ListHead timeouts = LIST_HEAD_INIT(timeouts);
static struct ListHead processes = LIST_HEAD_INIT(processes);
static struct ListHead signals = LIST_HEAD_INIT(signals);

static int poll_fd = -1;
bool uloop_cancelled = false;
bool uloop_handle_sigchld = true;
static int uloop_status = 0;
static bool do_sigchld = false;

static struct UloopFDEvent cur_fds[ULOOP_MAX_EVENTS];
static int cur_fd, cur_nfds;
static int uloop_run_depth = 0;

uloop_fd_handler uloop_fd_set_cb = nullptr;

static int uloop_init_pollfd() {
  if (poll_fd >= 0) {
    return 0;
  }

  poll_fd = epoll_create(32);
  if (poll_fd < 0) {
    return -1;
  }

  fcntl(poll_fd, F_SETFD, fcntl(poll_fd, F_GETFD) | FD_CLOEXEC);
  return 0;
}

static int register_poll(struct UloopFD* fd, unsigned int flags) {
  struct epoll_event ev {};
  int op = fd->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

  memset(&ev, 0, sizeof(struct epoll_event));

  if (flags & ULOOP_READ) {
    ev.events |= EPOLLIN | EPOLLRDHUP;
  }

  if (flags & ULOOP_WRITE) {
    ev.events |= EPOLLOUT;
  }

  if (flags & ULOOP_EDGE_TRIGGER) {
    ev.events |= EPOLLET;
  }

  ev.data.ptr = fd;

  return epoll_ctl(poll_fd, op, fd->fd, &ev);
}

static struct epoll_event events[ULOOP_MAX_EVENTS];

static int __uloop_fd_delete(struct UloopFD* sock) {
  sock->flags = 0;
  return epoll_ctl(poll_fd, EPOLL_CTL_DEL, sock->fd, nullptr);
}

static int uloop_fetch_events(int timeout) {
  int n, nfds;

  nfds = epoll_wait(poll_fd, events, ARRAY_SIZE(events), timeout);
  for (n = 0; n < nfds; ++n) {
    struct UloopFDEvent* cur = &cur_fds[n];
    struct UloopFD* u = static_cast<UloopFD*>(events[n].data.ptr);
    unsigned int ev = 0;

    cur->fd = u;
    if (!u) {
      continue;
    }

    if (events[n].events & (EPOLLERR | EPOLLHUP)) {
      u->error = true;
      if (!(u->flags & ULOOP_ERROR_CB)) {
        uloop_fd_delete(u);
      }
    }

    if (!(events[n].events &
          (EPOLLRDHUP | EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP))) {
      cur->fd = nullptr;
      continue;
    }

    if (events[n].events & EPOLLRDHUP) {
      u->eof = true;
    }

    if (events[n].events & EPOLLIN) {
      ev |= ULOOP_READ;
    }

    if (events[n].events & EPOLLOUT) {
      ev |= ULOOP_WRITE;
    }

    cur->events = ev;
  }

  return nfds;
}

static void set_signo(uint64_t* signums, int signo) {
  if (signo >= 1 && signo <= 64) {
    *signums |= (1u << (signo - 1));
  }
}

static bool get_signo(uint64_t signums, int signo) {
  return (signo >= 1) && (signo <= 64) && (signums & (1u << (signo - 1)));
}

static void signal_consume(struct UloopFD* fd, unsigned int events) {
  struct UloopSignal *usig, *usig_next;
  uint64_t signums = 0;
  uint8_t buf[32];
  ssize_t nsigs;

  do {
    nsigs = read(fd->fd, buf, sizeof(buf));

    for (ssize_t i = 0; i < nsigs; i++) {
      set_signo(&signums, buf[i]);
    }
  } while (nsigs > 0);

  list_for_each_entry_safe(usig, usig_next, &signals,
                           list) if (get_signo(signums, usig->signo))
      usig->cb(usig);
}

static int waker_pipe = -1;
static struct UloopFD waker_fd = {
    .cb = signal_consume,
    .fd = -1,
};

static void waker_init_fd(int fd) {
  fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

static int waker_init(void) {
  int fds[2];

  if (waker_pipe >= 0) {
    return 0;
  }

  if (pipe(fds) < 0) {
    return -1;
  }

  waker_init_fd(fds[0]);
  waker_init_fd(fds[1]);
  waker_pipe = fds[1];

  waker_fd.fd = fds[0];
  waker_fd.cb = signal_consume;
  uloop_fd_add(&waker_fd, ULOOP_READ);

  return 0;
}

static void uloop_setup_signals(bool add);

int uloop_init(void) {
  if (uloop_init_pollfd() < 0) {
    return -1;
  }

  if (waker_init() < 0) {
    uloop_done();
    return -1;
  }

  uloop_setup_signals(true);

  return 0;
}

static bool uloop_fd_stack_event(struct UloopFD* fd, int events) {
  struct UloopFDStack* cur;

  /*
   * Do not buffer events for level-triggered fds, they will keep firing.
   * Caller needs to take care of recursion issues.
   */
  if (!(fd->flags & ULOOP_EDGE_TRIGGER)) {
    return false;
  }

  for (cur = fd_stack; cur; cur = cur->next) {
    if (cur->fd != fd) {
      continue;
    }

    if (events < 0) {
      cur->fd = nullptr;
    } else {
      cur->events |= events | ULOOP_EVENT_BUFFERED;
    }

    return true;
  }

  return false;
}

static void uloop_run_events(int64_t timeout) {
  struct UloopFDEvent* cur;
  struct UloopFD* fd;

  if (!cur_nfds) {
    cur_fd = 0;
    cur_nfds = uloop_fetch_events(timeout);
    if (cur_nfds < 0) {
      cur_nfds = 0;
    }
  }

  while (cur_nfds > 0) {
    struct UloopFDStack stack_cur {};
    unsigned int events;

    cur = &cur_fds[cur_fd++];
    cur_nfds--;

    fd = cur->fd;
    events = cur->events;
    if (!fd) {
      continue;
    }

    if (!fd->cb) {
      continue;
    }

    if (uloop_fd_stack_event(fd, cur->events)) {
      continue;
    }

    stack_cur.next = fd_stack;
    stack_cur.fd = fd;
    fd_stack = &stack_cur;
    do {
      stack_cur.events = 0;
      fd->cb(fd, events);
      events = stack_cur.events & ULOOP_EVENT_MASK;
    } while (stack_cur.fd && events);
    fd_stack = stack_cur.next;

    return;
  }
}

int uloop_fd_add(struct UloopFD* sock, unsigned int flags) {
  unsigned int fl;
  int ret;

  if (!(flags & (ULOOP_READ | ULOOP_WRITE))) {
    return uloop_fd_delete(sock);
  }

  if (!sock->registered && !(flags & ULOOP_BLOCKING)) {
    fl = fcntl(sock->fd, F_GETFL, 0);
    fl |= O_NONBLOCK;
    fcntl(sock->fd, F_SETFL, fl);
  }

  ret = register_poll(sock, flags);
  if (ret < 0) {
    goto out;
  }

  if (uloop_fd_set_cb) {
    uloop_fd_set_cb(sock, flags);
  }

  sock->flags = flags;
  sock->registered = true;
  sock->eof = false;
  sock->error = false;

out:
  return ret;
}

int uloop_fd_delete(struct UloopFD* fd) {
  int ret;
  int i;

  for (i = 0; i < cur_nfds; i++) {
    if (cur_fds[cur_fd + i].fd != fd) {
      continue;
    }

    cur_fds[cur_fd + i].fd = nullptr;
  }

  if (!fd->registered) {
    return 0;
  }

  if (uloop_fd_set_cb) {
    uloop_fd_set_cb(fd, 0);
  }

  fd->registered = false;
  uloop_fd_stack_event(fd, -1);
  ret = __uloop_fd_delete(fd);
  fd->flags = 0;

  return ret;
}

static int64_t tv_diff(struct timeval* t1, struct timeval* t2) {
  return (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_usec - t2->tv_usec) / 1000;
}

int uloop_timeout_add(struct UloopTimeout* timeout) {
  struct UloopTimeout* tmp;
  struct ListHead* h = &timeouts;

  if (timeout->pending) {
    return -1;
  }

  list_for_each_entry(tmp, &timeouts, list) {
    if (tv_diff(&tmp->time, &timeout->time) > 0) {
      h = &tmp->list;
      break;
    }
  }

  list_add_tail(&timeout->list, h);
  timeout->pending = true;

  return 0;
}

static void uloop_gettime(struct timeval* tv) {
  struct timespec ts {};

  clock_gettime(CLOCK_MONOTONIC, &ts);
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec / 1000;
}

int uloop_timeout_set(struct UloopTimeout* timeout, time_t msecs) {
  struct timeval* time = &timeout->time;

  if (timeout->pending) {
    uloop_timeout_cancel(timeout);
  }

  uloop_gettime(time);

  time->tv_sec += msecs / 1000;
  time->tv_usec += (msecs % 1000) * 1000;

  if (time->tv_usec > 1000000) {
    time->tv_sec++;
    time->tv_usec -= 1000000;
  }

  return uloop_timeout_add(timeout);
}

int uloop_timeout_cancel(struct UloopTimeout* timeout) {
  if (!timeout->pending) {
    return -1;
  }

  list_del(&timeout->list);
  timeout->pending = false;

  return 0;
}

int64_t uloop_timeout_remaining64(struct UloopTimeout* timeout) {
  struct timeval now {};

  if (!timeout->pending) {
    return -1;
  }

  uloop_gettime(&now);

  return tv_diff(&timeout->time, &now);
}

int uloop_process_delete(struct UloopProcess* p) {
  if (!p->pending) {
    return -1;
  }

  list_del(&p->list);
  p->pending = false;

  return 0;
}

static void uloop_handle_processes() {
  struct UloopProcess *p, *tmp;
  pid_t pid;
  int ret;

  do_sigchld = false;

  while (true) {
    pid = waitpid(-1, &ret, WNOHANG);
    if (pid < 0 && errno == EINTR) {
      continue;
    }

    if (pid <= 0) {
      return;
    }

    list_for_each_entry_safe(p, tmp, &processes, list) {
      if (p->pid < pid) {
        continue;
      }

      if (p->pid > pid) {
        break;
      }

      uloop_process_delete(p);
      p->cb(p, ret);
    }
  }
}

static void uloop_signal_wake(int signo) {
  uint8_t sigbyte = signo;

  if (signo == SIGCHLD) {
    do_sigchld = true;
  }

  do {
    if (write(waker_pipe, &sigbyte, 1) < 0) {
      if (errno == EINTR) {
        continue;
      }
    }
    break;
  } while (true);
}

static void uloop_handle_sigint(int signo) {
  uloop_status = signo;
  uloop_cancelled = true;
  uloop_signal_wake(signo);
}

static void uloop_install_handler(int signum,
                                  void (*handler)(int),
                                  struct sigaction* old,
                                  bool add) {
  struct sigaction s {};
  struct sigaction* act;

  act = nullptr;
  sigaction(signum, nullptr, &s);

  if (add) {
    if (s.sa_handler ==
        SIG_DFL) { /* Do not override existing custom signal handlers */
      memcpy(old, &s, sizeof(struct sigaction));
      s.sa_handler = handler;
      s.sa_flags = 0;
      act = &s;
    }
  } else if (s.sa_handler ==
             handler) { /* Do not restore if someone modified our handler */
    act = old;
  }

  if (act != nullptr) {
    sigaction(signum, act, nullptr);
  }
}

static void uloop_ignore_signal(int signum, bool ignore) {
  struct sigaction s {};
  sighandler_t new_handler = nullptr;

  sigaction(signum, nullptr, &s);

  if (ignore) {
    if (s.sa_handler ==
        SIG_DFL) { /* Ignore only if there isn't any custom handler */
      new_handler = SIG_IGN;
    }
  } else {
    if (s.sa_handler ==
        SIG_IGN) { /* Restore only if noone modified our SIG_IGN */
      new_handler = SIG_DFL;
    }
  }

  if (new_handler) {
    s.sa_handler = new_handler;
    s.sa_flags = 0;
    sigaction(signum, &s, nullptr);
  }
}

static void uloop_setup_signals(bool add) {
  static struct sigaction old_sigint, old_sigchld, old_sigterm;

  uloop_install_handler(SIGINT, uloop_handle_sigint, &old_sigint, add);
  uloop_install_handler(SIGTERM, uloop_handle_sigint, &old_sigterm, add);

  if (uloop_handle_sigchld) {
    uloop_install_handler(SIGCHLD, uloop_signal_wake, &old_sigchld, add);
  }

  uloop_ignore_signal(SIGPIPE, add);
}

int uloop_get_next_timeout() {
  struct UloopTimeout* timeout;
  struct timeval tv {};
  int64_t diff;

  if (list_empty(&timeouts)) {
    return -1;
  }

  uloop_gettime(&tv);

  timeout = list_first_entry(&timeouts, struct UloopTimeout, list);
  diff = tv_diff(&timeout->time, &tv);
  if (diff < 0) {
    return 0;
  }
  if (diff > INT_MAX) {
    return INT_MAX;
  }

  return diff;
}

static void uloop_process_timeouts() {
  struct UloopTimeout* t;
  struct timeval tv {};

  if (list_empty(&timeouts)) {
    return;
  }

  uloop_gettime(&tv);
  while (!list_empty(&timeouts)) {
    t = list_first_entry(&timeouts, struct UloopTimeout, list);

    if (tv_diff(&t->time, &tv) > 0) {
      break;
    }

    uloop_timeout_cancel(t);
    if (t->cb) {
      t->cb(t);
    }
  }
}

static void uloop_clear_timeouts() {
  struct UloopTimeout *t, *tmp;

  list_for_each_entry_safe(t, tmp, &timeouts, list) uloop_timeout_cancel(t);
}

static void uloop_clear_processes() {
  struct UloopProcess *p, *tmp;

  list_for_each_entry_safe(p, tmp, &processes, list) uloop_process_delete(p);
}

int uloop_run_timeout(int timeout) {
  uloop_run_depth++;

  uloop_status = 0;
  uloop_cancelled = false;
  do {
    uloop_process_timeouts();

    if (do_sigchld) {
      uloop_handle_processes();
    }

    if (uloop_cancelled) {
      break;
    }

    int next_time = uloop_get_next_timeout();
    if (timeout >= 0 && (next_time < 0 || timeout < next_time)) {
      next_time = timeout;
    }
    uloop_run_events(next_time);
  } while (!uloop_cancelled && timeout < 0);

  --uloop_run_depth;

  return uloop_status;
}

int uloop_run() {
  return uloop_run_timeout(-1);
}

void uloop_done() {
  uloop_setup_signals(false);

  if (poll_fd >= 0) {
    close(poll_fd);
    poll_fd = -1;
  }

  if (waker_pipe >= 0) {
    uloop_fd_delete(&waker_fd);
    close(waker_pipe);
    close(waker_fd.fd);
    waker_pipe = -1;
  }

  uloop_clear_timeouts();
  uloop_clear_processes();
}

void uloop_end() {
  uloop_cancelled = true;
}
