/*
 * uloop - event loop implementation
 *
 * Copyright (C) 2010-2013 Felix Fietkau <nbd@openwrt.org>
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

#pragma once

#include <sys/time.h>
#include <sys/types.h>
#include <csignal>
#include <cstdint>

#include "list.h"

struct UloopFD;
struct UloopTimeout;
struct UloopProcess;
struct UloopSignal;

typedef void (*uloop_fd_handler)(struct UloopFD* u, unsigned int events);
typedef void (*uloop_timeout_handler)(struct UloopTimeout* t);
typedef void (*uloop_process_handler)(struct UloopProcess* c, int ret);
typedef void (*uloop_signal_handler)(struct UloopSignal* s);

#define ULOOP_READ (1 << 0)
#define ULOOP_WRITE (1 << 1)
#define ULOOP_EDGE_TRIGGER (1 << 2)
#define ULOOP_BLOCKING (1 << 3)

#define ULOOP_EVENT_MASK (ULOOP_READ | ULOOP_WRITE)

/* internal flags */
#define ULOOP_EVENT_BUFFERED (1 << 4)

#define ULOOP_ERROR_CB (1 << 6)

struct UloopFD {
  uloop_fd_handler cb;
  int fd;
  bool eof;
  bool error;
  bool registered;
  uint8_t flags;
};

struct UloopTimeout {
  struct ListHead list;
  bool pending;

  uloop_timeout_handler cb;
  struct timeval time;
};

struct UloopProcess {
  struct ListHead list;
  bool pending;

  uloop_process_handler cb;
  pid_t pid;
};

struct UloopSignal {
  struct ListHead list;

  uloop_signal_handler cb;
  int signo;
};

extern bool uloop_cancelled;
extern bool uloop_handle_sigchld;
extern uloop_fd_handler uloop_fd_set_cb;

int uloop_fd_add(struct UloopFD* sock, unsigned int flags);
int uloop_fd_delete(struct UloopFD* sock);

int uloop_get_next_timeout();
int uloop_timeout_add(struct UloopTimeout* timeout);
int uloop_timeout_set(struct UloopTimeout* timeout, time_t msecs);
int uloop_timeout_cancel(struct UloopTimeout* timeout);
int64_t uloop_timeout_remaining64(struct UloopTimeout* timeout);

int uloop_process_delete(struct UloopProcess* p);

void uloop_end();

int uloop_init();
int uloop_run_timeout(int timeout);
int uloop_run();
void uloop_done();
