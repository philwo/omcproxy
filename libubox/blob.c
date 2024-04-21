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

#include "blob.h"

/*
 * blob_data: returns the data pointer for an attribute
 */
void* blob_data(const struct blob_attr* attr) {
  return (void*)attr->data;
}

/*
 * blob_id: returns the id of an attribute
 */
unsigned int blob_id(const struct blob_attr* attr) {
  return (be32_to_cpu(attr->id_len) & BLOB_ATTR_ID_MASK) >> BLOB_ATTR_ID_SHIFT;
}

bool blob_is_extended(const struct blob_attr* attr) {
  return (attr->id_len & cpu_to_be32(BLOB_ATTR_EXTENDED)) != 0;
}

/*
 * blob_len: returns the length of the attribute's payload
 */
size_t blob_len(const struct blob_attr* attr) {
  return (be32_to_cpu(attr->id_len) & BLOB_ATTR_LEN_MASK) -
         sizeof(struct blob_attr);
}

/*
 * blob_raw_len: returns the complete length of an attribute (including the
 * header)
 */
size_t blob_raw_len(const struct blob_attr* attr) {
  return blob_len(attr) + sizeof(struct blob_attr);
}

/*
 * blob_pad_len: returns the padded length of an attribute (including the
 * header)
 */
size_t blob_pad_len(const struct blob_attr* attr) {
  return (blob_raw_len(attr) + BLOB_ATTR_ALIGN - 1) & ~(BLOB_ATTR_ALIGN - 1);
}

struct blob_attr* blob_next(const struct blob_attr* attr) {
  return (struct blob_attr*)((char*)attr + blob_pad_len(attr));
}

static bool blob_buffer_grow(struct blob_buf* buf, size_t minlen) {
  struct blob_buf* new;
  size_t delta = ((minlen / 256) + 1) * 256;
  new = realloc(buf->buf, buf->buflen + delta);
  if (new) {
    buf->buf = new;
    memset(buf->buf + buf->buflen, 0, delta);
    buf->buflen += delta;
  }
  return new != NULL;
}

static void blob_init(struct blob_attr* attr, int id, unsigned int len) {
  len &= BLOB_ATTR_LEN_MASK;
  len |= (id << BLOB_ATTR_ID_SHIFT) & BLOB_ATTR_ID_MASK;
  attr->id_len = cpu_to_be32(len);
}

static struct blob_attr* offset_to_attr(struct blob_buf* buf, int offset) {
  void* ptr = (char*)buf->buf + offset - BLOB_COOKIE;
  return ptr;
}

static int attr_to_offset(struct blob_buf* buf, struct blob_attr* attr) {
  return (char*)attr - (char*)buf->buf + BLOB_COOKIE;
}

bool blob_buf_grow(struct blob_buf* buf, size_t required) {
  int offset_head = attr_to_offset(buf, buf->head);

  if ((buf->buflen + required) > BLOB_ATTR_LEN_MASK) {
    return false;
  }
  if (!buf->grow || !buf->grow(buf, required)) {
    return false;
  }

  buf->head = offset_to_attr(buf, offset_head);
  return true;
}

static struct blob_attr* blob_add(struct blob_buf* buf,
                                  struct blob_attr* pos,
                                  int id,
                                  int payload) {
  int offset = attr_to_offset(buf, pos);
  unsigned long required =
      (offset - BLOB_COOKIE + sizeof(struct blob_attr) + payload) - buf->buflen;
  struct blob_attr* attr;

  if (required > 0) {
    if (!blob_buf_grow(buf, required)) {
      return NULL;
    }
    attr = offset_to_attr(buf, offset);
  } else {
    attr = pos;
  }

  blob_init(attr, id, payload + sizeof(struct blob_attr));
  blob_fill_pad(attr);
  return attr;
}

int blob_buf_init(struct blob_buf* buf, int id) {
  if (!buf->grow) {
    buf->grow = blob_buffer_grow;
  }

  buf->head = buf->buf;
  if (blob_add(buf, buf->buf, id, 0) == NULL) {
    return -ENOMEM;
  }

  return 0;
}

void blob_buf_free(struct blob_buf* buf) {
  free(buf->buf);
  buf->buf = NULL;
  buf->head = NULL;
  buf->buflen = 0;
}

void blob_fill_pad(struct blob_attr* attr) {
  char* buf = (char*)attr;
  size_t len = blob_pad_len(attr);
  size_t delta = len - blob_raw_len(attr);

  if (delta > 0) {
    memset(buf + len - delta, 0, delta);
  }
}

void blob_set_raw_len(struct blob_attr* attr, unsigned int len) {
  len &= BLOB_ATTR_LEN_MASK;
  attr->id_len &= ~cpu_to_be32(BLOB_ATTR_LEN_MASK);
  attr->id_len |= cpu_to_be32(len);
}

struct blob_attr* blob_new(struct blob_buf* buf, int id, int payload) {
  struct blob_attr* attr;

  attr = blob_add(buf, blob_next(buf->head), id, payload);
  if (!attr) {
    return NULL;
  }

  blob_set_raw_len(buf->head, blob_pad_len(buf->head) + blob_pad_len(attr));
  return attr;
}

void blob_nest_end(struct blob_buf* buf, void* cookie) {
  struct blob_attr* attr = offset_to_attr(buf, (unsigned long)cookie);
  blob_set_raw_len(attr, blob_pad_len(attr) + blob_len(buf->head));
  buf->head = attr;
}

static const size_t blob_type_minlen[BLOB_ATTR_LAST] = {
    [BLOB_ATTR_STRING] = 1,
    [BLOB_ATTR_INT8] = sizeof(uint8_t),
    [BLOB_ATTR_INT16] = sizeof(uint16_t),
    [BLOB_ATTR_INT32] = sizeof(uint32_t),
    [BLOB_ATTR_INT64] = sizeof(uint64_t),
    [BLOB_ATTR_DOUBLE] = sizeof(double),
};

bool blob_check_type(const void* ptr, unsigned int len, int type) {
  const char* data = ptr;

  if (type >= BLOB_ATTR_LAST) {
    return false;
  }

  if (type >= BLOB_ATTR_INT8 && type <= BLOB_ATTR_INT64) {
    if (len != blob_type_minlen[type]) {
      return false;
    }
  } else {
    if (len < blob_type_minlen[type]) {
      return false;
    }
  }

  if (type == BLOB_ATTR_STRING && data[len - 1] != 0) {
    return false;
  }

  return true;
}
