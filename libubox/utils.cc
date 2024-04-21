/*
 * utils - misc libubox utility functions
 *
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
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

#include <cerrno>
#include <cstring>

#include "utils.h"

int mkdir_p(char* dir, mode_t mask) {
  char* l;
  int ret;

  ret = mkdir(dir, mask);
  if (!ret || errno == EEXIST) {
    return 0;
  }
  if (errno != ENOENT) {
    return -1;
  }

  l = strrchr(dir, '/');
  if (!l || l == dir) {
    return -1;
  }

  *l = '\0';

  if (mkdir_p(dir, mask)) {
    return -1;
  }

  *l = '/';

  ret = mkdir(dir, mask);
  if (!ret || errno == EEXIST) {
    return 0;
  } else {
    return -1;
  }
}
