#pragma once

#include <stddef.h>

#include "src/ev.h"

#define STUB_MAX_FDS 4

extern omgp_time_t stub_now;
extern struct ev_fd* stub_fds[STUB_MAX_FDS];
extern size_t stub_fd_count;

void stub_advance(omgp_time_t delta);
