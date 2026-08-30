#include "ev_stub.h"

omgp_time_t stub_now = INT64_C(1) << 20;
struct ev_fd* stub_fds[STUB_MAX_FDS];
size_t stub_fd_count;

static LIST_HEAD(stub_timers);

omgp_time_t omgp_time(void) {
  return stub_now;
}

int ev_fd_add(struct ev_fd* efd, int fd, uint32_t events, ev_fd_cb* cb) {
  (void)events;
  efd->fd = fd;
  efd->cb = cb;
  efd->registered = true;
  if (stub_fd_count < STUB_MAX_FDS) {
    stub_fds[stub_fd_count++] = efd;
  }
  return 0;
}

void ev_fd_del(struct ev_fd* efd) {
  if (!efd->registered) {
    return;
  }
  efd->registered = false;
  for (size_t i = 0; i < stub_fd_count; ++i) {
    if (stub_fds[i] == efd) {
      stub_fds[i] = stub_fds[--stub_fd_count];
      break;
    }
  }
}

void ev_timer_cancel(struct ev_timer* timer) {
  if (!timer->pending) {
    return;
  }
  list_del(&timer->head);
  timer->pending = false;
}

void ev_timer_set(struct ev_timer* timer, omgp_time_t msecs) {
  ev_timer_cancel(timer);
  timer->deadline = stub_now + msecs;

  struct list_head* pos = &stub_timers;
  struct ev_timer* t;
  list_for_each_entry (t, &stub_timers, head) {
    if (t->deadline > timer->deadline) {
      pos = &t->head;
      break;
    }
  }
  list_add_tail(&timer->head, pos);
  timer->pending = true;
}

omgp_time_t ev_timer_remaining(const struct ev_timer* timer) {
  if (!timer->pending) {
    return -1;
  }
  omgp_time_t remaining = timer->deadline - stub_now;
  return (remaining > 0) ? remaining : 0;
}

void stub_advance(omgp_time_t delta) {
  omgp_time_t end = stub_now + delta;
  while (!list_empty(&stub_timers)) {
    struct ev_timer* t = list_first_entry(&stub_timers, struct ev_timer, head);
    if (t->deadline > end) {
      break;
    }

    if (t->deadline > stub_now) {
      stub_now = t->deadline;
    }
    list_del(&t->head);
    t->pending = false;
    t->cb(t);
  }
  stub_now = end;
}
