#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "src/ev.h"

#include "test.h"

static int fire_order[8];
static int fire_count;

static struct ev_timer t1;
static struct ev_timer t2;
static struct ev_timer t3;

static void record_1(struct ev_timer* t) {
  (void)t;
  fire_order[fire_count++] = 1;
}
static void record_2(struct ev_timer* t) {
  (void)t;
  fire_order[fire_count++] = 2;
}

static void record_3_and_break(struct ev_timer* t) {
  (void)t;
  fire_order[fire_count++] = 3;
  ev_break();
}

static void test_timer_ordering(void) {
  fire_count = 0;
  t1 = (struct ev_timer){.cb = record_1};
  t2 = (struct ev_timer){.cb = record_2};
  t3 = (struct ev_timer){.cb = record_3_and_break};
  ev_timer_set(&t2, 20);
  ev_timer_set(&t1, 5);
  ev_timer_set(&t3, 40);
  CHECK(ev_run() == 0);
  CHECK(fire_count == 3);
  CHECK(fire_order[0] == 1);
  CHECK(fire_order[1] == 2);
  CHECK(fire_order[2] == 3);
}

static void test_timer_cancel(void) {
  fire_count = 0;
  t1 = (struct ev_timer){.cb = record_1};
  t3 = (struct ev_timer){.cb = record_3_and_break};
  ev_timer_set(&t1, 5);
  ev_timer_set(&t3, 30);
  ev_timer_cancel(&t1);
  CHECK(ev_timer_remaining(&t1) == -1);
  CHECK(ev_run() == 0);
  CHECK(fire_count == 1);
  CHECK(fire_order[0] == 3);
}

static int rearm_left;

static void rearm_cb(struct ev_timer* t) {
  ++fire_count;
  if (--rearm_left > 0) {
    ev_timer_set(t, 5);
  } else {
    ev_break();
  }
}

static void test_timer_rearm_in_callback(void) {
  fire_count = 0;
  rearm_left = 3;
  t1 = (struct ev_timer){.cb = rearm_cb};
  ev_timer_set(&t1, 5);
  CHECK(ev_run() == 0);
  CHECK(fire_count == 3);
}

static void test_timer_remaining(void) {
  t1 = (struct ev_timer){.cb = record_1};
  ev_timer_set(&t1, 1000);
  omgp_time_t rem = ev_timer_remaining(&t1);
  CHECK(rem > 900 && rem <= 1000);
  ev_timer_cancel(&t1);
}

static void test_timer_remaining_overdue_pending(void) {
  t1 = (struct ev_timer){.cb = record_1};
  ev_timer_set(&t1, 0);
  struct timespec ts = {.tv_nsec = 2000000};
  nanosleep(&ts, NULL);
  CHECK(t1.pending);
  CHECK(ev_timer_remaining(&t1) == 0);
  ev_timer_cancel(&t1);
}

static int sp[2];
static struct ev_fd efd;
static int fd_events;
static char fd_buf[16];

static void read_all_cb(struct ev_fd* e, uint32_t events) {
  CHECK(events & EV_READ);
  ++fd_events;
  while (read(e->fd, fd_buf, sizeof(fd_buf)) > 0) {
  }
  ev_break();
}

static void test_fd_readiness(void) {
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) == 0);
  fd_events = 0;
  CHECK(ev_fd_add(&efd, sp[0], EV_READ | EV_EDGE, read_all_cb) == 0);
  CHECK(write(sp[1], "x", 1) == 1);
  CHECK(ev_run() == 0);
  CHECK(fd_events == 1);
  ev_fd_del(&efd);
  close(sp[0]);
  close(sp[1]);
}

static void read_one_cb(struct ev_fd* e, uint32_t events) {
  (void)events;
  ++fd_events;
  char c;
  CHECK(read(e->fd, &c, 1) == 1);
}

static void break_cb(struct ev_timer* t) {
  (void)t;
  ev_break();
}

static void test_fd_edge_triggered(void) {
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) == 0);
  fd_events = 0;
  CHECK(ev_fd_add(&efd, sp[0], EV_READ | EV_EDGE, read_one_cb) == 0);
  CHECK(write(sp[1], "xy", 2) == 2);
  t1 = (struct ev_timer){.cb = break_cb};
  ev_timer_set(&t1, 50);
  CHECK(ev_run() == 0);
  CHECK(fd_events == 1);

  fd_events = 0;
  CHECK(write(sp[1], "z", 1) == 1);
  ev_timer_set(&t1, 50);
  CHECK(ev_run() == 0);
  CHECK(fd_events == 1);

  ev_fd_del(&efd);
  close(sp[0]);
  close(sp[1]);
}

int main(void) {
  CHECK(ev_init() == 0);
  test_timer_ordering();
  test_timer_cancel();
  test_timer_rearm_in_callback();
  test_timer_remaining();
  test_timer_remaining_overdue_pending();
  test_fd_readiness();
  test_fd_edge_triggered();
  ev_deinit();
  return test_result();
}
