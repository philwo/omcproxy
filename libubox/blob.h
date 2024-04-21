/*
 * blob - library for generating/parsing tagged binary data
 *
 * Copyright (C) 2010 Felix Fietkau <nbd@openwrt.org>
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

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#define BLOB_COOKIE 0x01234567

enum {
  BLOB_ATTR_UNSPEC,
  BLOB_ATTR_NESTED,
  BLOB_ATTR_BINARY,
  BLOB_ATTR_STRING,
  BLOB_ATTR_INT8,
  BLOB_ATTR_INT16,
  BLOB_ATTR_INT32,
  BLOB_ATTR_INT64,
  BLOB_ATTR_DOUBLE,
  BLOB_ATTR_LAST
};

#define BLOB_ATTR_ID_MASK 0x7f000000
#define BLOB_ATTR_ID_SHIFT 24
#define BLOB_ATTR_LEN_MASK 0x00ffffff
#define BLOB_ATTR_ALIGN 4
#define BLOB_ATTR_EXTENDED 0x80000000

struct blob_attr {
  uint32_t id_len;
  char data[];
} __attribute__((packed));

struct blob_buf {
  struct blob_attr* head;
  bool (*grow)(struct blob_buf* buf, size_t minlen);
  size_t buflen;
  void* buf;
};

/*
 * blob_data: returns the data pointer for an attribute
 */
void* blob_data(const struct blob_attr* attr);

/*
 * blob_id: returns the id of an attribute
 */
unsigned int blob_id(const struct blob_attr* attr);

bool blob_is_extended(const struct blob_attr* attr);

/*
 * blob_len: returns the length of the attribute's payload
 */
size_t blob_len(const struct blob_attr* attr);

/*
 * blob_raw_len: returns the complete length of an attribute (including the
 * header)
 */
size_t blob_raw_len(const struct blob_attr* attr);

/*
 * blob_pad_len: returns the padded length of an attribute (including the
 * header)
 */
size_t blob_pad_len(const struct blob_attr* attr);

struct blob_attr* blob_next(const struct blob_attr* attr);

extern void blob_fill_pad(struct blob_attr* attr);
extern void blob_set_raw_len(struct blob_attr* attr, size_t len);
extern int blob_buf_init(struct blob_buf* buf, int id);
extern void blob_buf_free(struct blob_buf* buf);
extern bool blob_buf_grow(struct blob_buf* buf, size_t required);
extern struct blob_attr* blob_new(struct blob_buf* buf, int id, int payload);
extern void blob_nest_end(struct blob_buf* buf, void* cookie);
extern bool blob_check_type(const void* ptr, size_t len, int type);

#define __blob_for_each_attr(pos, attr, rem)                            \
  for (pos = (struct blob_attr*)attr;                                   \
       rem >= sizeof(struct blob_attr) && (blob_pad_len(pos) <= rem) && \
       (blob_pad_len(pos) >= sizeof(struct blob_attr));                 \
       rem -= blob_pad_len(pos), pos = blob_next(pos))
