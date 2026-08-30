#include <stdlib.h>

#include "ev_stub.h"

omgp_time_t stub_now = INT64_C(1) << 20;

#define STUB_MAX_TIMERS 16

static struct uloop_timeout* stub_timers[STUB_MAX_TIMERS];
static omgp_time_t stub_deadlines[STUB_MAX_TIMERS];

omgp_time_t omgp_time(void) {
  return stub_now;
}

int uloop_timeout_cancel(struct uloop_timeout* timeout) {
  for (int i = 0; i < STUB_MAX_TIMERS; ++i) {
    if (stub_timers[i] == timeout) {
      stub_timers[i] = NULL;
    }
  }
  timeout->pending = false;
  return 0;
}

int uloop_timeout_set(struct uloop_timeout* timeout, int msecs) {
  uloop_timeout_cancel(timeout);
  for (int i = 0; i < STUB_MAX_TIMERS; ++i) {
    if (!stub_timers[i]) {
      stub_timers[i] = timeout;
      stub_deadlines[i] = stub_now + msecs;
      timeout->pending = true;
      return 0;
    }
  }
  abort();
}

int64_t uloop_timeout_remaining64(struct uloop_timeout* timeout) {
  for (int i = 0; i < STUB_MAX_TIMERS; ++i) {
    if (stub_timers[i] == timeout) {
      return stub_deadlines[i] - stub_now;
    }
  }
  return -1;
}

void stub_advance(omgp_time_t delta) {
  omgp_time_t end = stub_now + delta;
  for (;;) {
    int best = -1;
    for (int i = 0; i < STUB_MAX_TIMERS; ++i) {
      if (stub_timers[i] &&
          (best < 0 || stub_deadlines[i] < stub_deadlines[best])) {
        best = i;
      }
    }
    if (best < 0 || stub_deadlines[best] > end) {
      break;
    }

    struct uloop_timeout* t = stub_timers[best];
    if (stub_deadlines[best] > stub_now) {
      stub_now = stub_deadlines[best];
    }
    stub_timers[best] = NULL;
    t->pending = false;
    t->cb(t);
  }
  stub_now = end;
}
