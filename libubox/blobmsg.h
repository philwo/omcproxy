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
} __packed;

struct blobmsg_policy {
  const char* name;
  enum blobmsg_type type;
};

int blobmsg_hdrlen(unsigned int namelen);

void blobmsg_clear_name(struct blob_attr* attr);

const char* blobmsg_name(const struct blob_attr* attr);

int blobmsg_type(const struct blob_attr* attr);

uint16_t blobmsg_namelen(const struct blobmsg_hdr* hdr);

void* blobmsg_data(const struct blob_attr* attr);

size_t blobmsg_data_len(const struct blob_attr* attr);

size_t blobmsg_len(const struct blob_attr* attr);

/*
 * blobmsg_check_attr: validate a list of attributes
 *
 * This method may be used with trusted data only. Providing
 * malformed blobs will cause out of bounds memory access.
 */
bool blobmsg_check_attr(const struct blob_attr* attr, bool name);

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

/*
 * blobmsg_check_attr_list: validate a list of attributes
 *
 * This method may be used with trusted data only. Providing
 * malformed blobs will cause out of bounds memory access.
 */
bool blobmsg_check_attr_list(const struct blob_attr* attr, int type);

/*
 * blobmsg_check_attr_list_len: validate a list of untrusted attributes
 *
 * This method should be safer implementation of blobmsg_check_attr_list.
 * It will limit all memory access performed on the blob to the
 * range [attr, attr + len] (upper bound non inclusive) and is
 * thus suited for checking of untrusted blob attributes.
 */
bool blobmsg_check_attr_list_len(const struct blob_attr* attr,
                                 int type,
                                 size_t len);

/*
 * blobmsg_check_array: validate array/table and return size
 *
 * Checks if all elements of an array or table are valid and have
 * the specified type. Returns the number of elements in the array
 *
 * This method may be used with trusted data only. Providing
 * malformed blobs will cause out of bounds memory access.
 */
int blobmsg_check_array(const struct blob_attr* attr, int type);

/*
 * blobmsg_check_array_len: validate untrusted array/table and return size
 *
 * Checks if all elements of an array or table are valid and have
 * the specified type. Returns the number of elements in the array.
 *
 * This method should be safer implementation of blobmsg_check_array.
 * It will limit all memory access performed on the blob to the
 * range [attr, attr + len] (upper bound non inclusive) and is
 * thus suited for checking of untrusted blob attributes.
 */
int blobmsg_check_array_len(const struct blob_attr* attr, int type, size_t len);

int blobmsg_parse(const struct blobmsg_policy* policy,
                  int policy_len,
                  struct blob_attr** tb,
                  void* data,
                  unsigned int len);
int blobmsg_parse_array(const struct blobmsg_policy* policy,
                        int policy_len,
                        struct blob_attr** tb,
                        void* data,
                        unsigned int len);

int blobmsg_add_field(struct blob_buf* buf,
                      int type,
                      const char* name,
                      const void* data,
                      unsigned int len);

int blobmsg_parse_attr(const struct blobmsg_policy* policy,
                       int policy_len,
                       struct blob_attr** tb,
                       struct blob_attr* data);

int blobmsg_parse_array_attr(const struct blobmsg_policy* policy,
                             int policy_len,
                             struct blob_attr** tb,
                             struct blob_attr* data);

int blobmsg_add_double(struct blob_buf* buf, const char* name, double val);

int blobmsg_add_u8(struct blob_buf* buf, const char* name, uint8_t val);

int blobmsg_add_u16(struct blob_buf* buf, const char* name, uint16_t val);

int blobmsg_add_u32(struct blob_buf* buf, const char* name, uint32_t val);

int blobmsg_add_u64(struct blob_buf* buf, const char* name, uint64_t val);

int blobmsg_add_string(struct blob_buf* buf,
                       const char* name,
                       const char* string);

int blobmsg_add_blob(struct blob_buf* buf, struct blob_attr* attr);

void* blobmsg_open_nested(struct blob_buf* buf, const char* name, bool array);

void* blobmsg_open_array(struct blob_buf* buf, const char* name);

void* blobmsg_open_table(struct blob_buf* buf, const char* name);

void blobmsg_close_array(struct blob_buf* buf, void* cookie);

void blobmsg_close_table(struct blob_buf* buf, void* cookie);

int blobmsg_buf_init(struct blob_buf* buf);

uint8_t blobmsg_get_u8(struct blob_attr* attr);

bool blobmsg_get_bool(struct blob_attr* attr);

uint16_t blobmsg_get_u16(struct blob_attr* attr);

uint32_t blobmsg_get_u32(struct blob_attr* attr);

uint64_t blobmsg_get_u64(struct blob_attr* attr);

uint64_t blobmsg_cast_u64(struct blob_attr* attr);

int64_t blobmsg_cast_s64(struct blob_attr* attr);

double blobmsg_get_double(struct blob_attr* attr);

char* blobmsg_get_string(struct blob_attr* attr);

void* blobmsg_alloc_string_buffer(struct blob_buf* buf,
                                  const char* name,
                                  unsigned int maxlen);
void* blobmsg_realloc_string_buffer(struct blob_buf* buf, unsigned int maxlen);
void blobmsg_add_string_buffer(struct blob_buf* buf);

int blobmsg_vprintf(struct blob_buf* buf,
                    const char* name,
                    const char* format,
                    va_list arg);
int blobmsg_printf(struct blob_buf* buf,
                   const char* name,
                   const char* format,
                   ...) __attribute__((format(printf, 3, 4)));

#define blobmsg_for_each_attr(pos, attr, rem)                           \
  for (rem = attr ? blobmsg_data_len(attr) : 0,                         \
      pos = (struct blob_attr*)(attr ? blobmsg_data(attr) : NULL);      \
       rem >= sizeof(struct blob_attr) && (blob_pad_len(pos) <= rem) && \
       (blob_pad_len(pos) >= sizeof(struct blob_attr));                 \
       rem -= blob_pad_len(pos), pos = blob_next(pos))

#define __blobmsg_for_each_attr(pos, attr, rem)                         \
  for (pos = (struct blob_attr*)(attr ? blobmsg_data(attr) : NULL);     \
       rem >= sizeof(struct blob_attr) && (blob_pad_len(pos) <= rem) && \
       (blob_pad_len(pos) >= sizeof(struct blob_attr));                 \
       rem -= blob_pad_len(pos), pos = blob_next(pos))
