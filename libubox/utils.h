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

#pragma once

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdint>
#include <ctime>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define constant_swap32(x)                                       \
  ((uint32_t)((((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
              (((uint32_t)(x) & (uint32_t)0x0000ff00UL) << 8) |  \
              (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >> 8) |  \
              (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#define eval_once(func, x) \
  ({                       \
    __typeof__(x) __x = x; \
    func(__x);             \
  })

#define cpu_to_be32(x) eval_once(constant_swap32, x)
#define be32_to_cpu(x) eval_once(constant_swap32, x)

int mkdir_p(char* dir, mode_t mask);
