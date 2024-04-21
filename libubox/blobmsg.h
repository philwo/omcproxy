/*
 * Copyright (C) 2010-2012 Felix Fietkau <nbd@openwrt.org>
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

#include <stdarg.h>
#include "blob.h"

#define BLOBMSG_ALIGN 2
#define BLOBMSG_PADDING(len) \
  (((len) + (1 << BLOBMSG_ALIGN) - 1) & ~((1 << BLOBMSG_ALIGN) - 1))

enum blobmsg_type {
  BLOBMSG_TYPE_UNSPEC,
  BLOBMSG_TYPE_ARRAY,
  BLOBMSG_TYPE_TABLE,
  BLOBMSG_TYPE_STRING,
  BLOBMSG_TYPE_INT64,
  BLOBMSG_TYPE_INT32,
  BLOBMSG_TYPE_INT16,
  BLOBMSG_TYPE_INT8,
  BLOBMSG_TYPE_BOOL = BLOBMSG_TYPE_INT8,
  BLOBMSG_TYPE_DOUBLE,
  __BLOBMSG_TYPE_LAST,
  BLOBMSG_TYPE_LAST = __BLOBMSG_TYPE_LAST - 1,
  BLOBMSG_CAST_INT64 = __BLOBMSG_TYPE_LAST,
};

struct blobmsg_hdr {
  uint16_t namelen;
  uint8_t name[];
} __attribute__((packed));

struct blobmsg_policy {
  const char* name;
  enum blobmsg_type type;
};

int blobmsg_hdrlen(unsigned int namelen);

int blobmsg_type(const struct blob_attr* attr);

uint16_t blobmsg_namelen(const struct blobmsg_hdr* hdr);

void* blobmsg_data(const struct blob_attr* attr);

size_t blobmsg_data_len(const struct blob_attr* attr);

/*
 * blobmsg_check_attr_len: validate a list of attributes
 *
 * This method should be safer implementation of blobmsg_check_attr.
 * It will limit all memory access performed on the blob to the
 * range [attr, attr + len] (upper bound non inclusive) and is
 * thus suited for checking of untrusted blob attributes.
 */
bool blobmsg_check_attr_len(const struct blob_attr* attr,
                            bool name,
                            size_t len);

int blobmsg_parse(const struct blobmsg_policy* policy,
                  int policy_len,
                  struct blob_attr** tb,
                  void* data,
                  unsigned int len);

int blobmsg_add_field(struct blob_buf* buf,
                      int type,
                      const char* name,
                      const void* data,
                      unsigned int len);

int blobmsg_add_string(struct blob_buf* buf,
                       const char* name,
                       const char* string);

void* blobmsg_open_nested(struct blob_buf* buf, const char* name, bool array);

void* blobmsg_open_array(struct blob_buf* buf, const char* name);

void blobmsg_close_array(struct blob_buf* buf, void* cookie);

char* blobmsg_get_string(struct blob_attr* attr);

#define blobmsg_for_each_attr(pos, attr, rem)                           \
  for (rem = attr ? blobmsg_data_len(attr) : 0,                         \
      pos = (struct blob_attr*)(attr ? blobmsg_data(attr) : NULL);      \
       rem >= sizeof(struct blob_attr) && (blob_pad_len(pos) <= rem) && \
       (blob_pad_len(pos) >= sizeof(struct blob_attr));                 \
       rem -= blob_pad_len(pos), pos = blob_next(pos))
