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
  int id =
      (be32_to_cpu(attr->id_len) & BLOB_ATTR_ID_MASK) >> BLOB_ATTR_ID_SHIFT;
  return id;
}

bool blob_is_extended(const struct blob_attr* attr) {
  return !!(attr->id_len & cpu_to_be32(BLOB_ATTR_EXTENDED));
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
  unsigned int len = blob_raw_len(attr);
  len = (len + BLOB_ATTR_ALIGN - 1) & ~(BLOB_ATTR_ALIGN - 1);
  return len;
}

uint8_t blob_get_u8(const struct blob_attr* attr) {
  return *((uint8_t*)attr->data);
}

uint16_t blob_get_u16(const struct blob_attr* attr) {
  uint16_t* tmp = (uint16_t*)attr->data;
  return be16_to_cpu(*tmp);
}

uint32_t blob_get_u32(const struct blob_attr* attr) {
  uint32_t* tmp = (uint32_t*)attr->data;
  return be32_to_cpu(*tmp);
}

uint64_t blob_get_u64(const struct blob_attr* attr) {
  uint32_t* ptr = (uint32_t*)blob_data(attr);
  uint64_t tmp = ((uint64_t)be32_to_cpu(ptr[0])) << 32;
  tmp |= be32_to_cpu(ptr[1]);
  return tmp;
}

int8_t blob_get_int8(const struct blob_attr* attr) {
  return blob_get_u8(attr);
}

int16_t blob_get_int16(const struct blob_attr* attr) {
  return blob_get_u16(attr);
}

int32_t blob_get_int32(const struct blob_attr* attr) {
  return blob_get_u32(attr);
}

int64_t blob_get_int64(const struct blob_attr* attr) {
  return blob_get_u64(attr);
}

const char* blob_get_string(const struct blob_attr* attr) {
  return attr->data;
}

struct blob_attr* blob_next(const struct blob_attr* attr) {
  return (struct blob_attr*)((char*)attr + blob_pad_len(attr));
}

struct blob_attr* blob_put_string(struct blob_buf* buf,
                                  int id,
                                  const char* str) {
  return blob_put(buf, id, str, strlen(str) + 1);
}

struct blob_attr* blob_put_u8(struct blob_buf* buf, int id, uint8_t val) {
  return blob_put(buf, id, &val, sizeof(val));
}

struct blob_attr* blob_put_u16(struct blob_buf* buf, int id, uint16_t val) {
  val = cpu_to_be16(val);
  return blob_put(buf, id, &val, sizeof(val));
}

struct blob_attr* blob_put_u32(struct blob_buf* buf, int id, uint32_t val) {
  val = cpu_to_be32(val);
  return blob_put(buf, id, &val, sizeof(val));
}

struct blob_attr* blob_put_u64(struct blob_buf* buf, int id, uint64_t val) {
  val = cpu_to_be64(val);
  return blob_put(buf, id, &val, sizeof(val));
}

static bool blob_buffer_grow(struct blob_buf* buf, int minlen) {
  struct blob_buf* new;
  int delta = ((minlen / 256) + 1) * 256;
  new = realloc(buf->buf, buf->buflen + delta);
  if (new) {
    buf->buf = new;
    memset(buf->buf + buf->buflen, 0, delta);
    buf->buflen += delta;
  }
  return !!new;
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

bool blob_buf_grow(struct blob_buf* buf, int required) {
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
  int required =
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
  int len = blob_pad_len(attr);
  int delta = len - blob_raw_len(attr);

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

struct blob_attr* blob_put_raw(struct blob_buf* buf,
                               const void* ptr,
                               unsigned int len) {
  struct blob_attr* attr;

  if (len < sizeof(struct blob_attr) || !ptr) {
    return NULL;
  }

  attr = blob_add(buf, blob_next(buf->head), 0, len - sizeof(struct blob_attr));
  if (!attr) {
    return NULL;
  }
  blob_set_raw_len(buf->head, blob_pad_len(buf->head) + len);
  memcpy(attr, ptr, len);
  return attr;
}

struct blob_attr* blob_put(struct blob_buf* buf,
                           int id,
                           const void* ptr,
                           unsigned int len) {
  struct blob_attr* attr;

  attr = blob_new(buf, id, len);
  if (!attr) {
    return NULL;
  }

  if (ptr) {
    memcpy(blob_data(attr), ptr, len);
  }
  return attr;
}

void* blob_nest_start(struct blob_buf* buf, int id) {
  unsigned long offset = attr_to_offset(buf, buf->head);
  buf->head = blob_new(buf, id, 0);
  if (!buf->head) {
    return NULL;
  }
  return (void*)offset;
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

static int blob_parse_attr(struct blob_attr* attr,
                           size_t attr_len,
                           struct blob_attr** data,
                           const struct blob_attr_info* info,
                           int max) {
  int id;
  size_t len;
  int found = 0;
  size_t data_len;

  if (!attr || attr_len < sizeof(struct blob_attr)) {
    return 0;
  }

  id = blob_id(attr);
  if (id >= max) {
    return 0;
  }

  len = blob_raw_len(attr);
  if (len > attr_len || len < sizeof(struct blob_attr)) {
    return 0;
  }

  data_len = blob_len(attr);
  if (data_len > len) {
    return 0;
  }

  if (info) {
    int type = info[id].type;

    if (type < BLOB_ATTR_LAST) {
      if (!blob_check_type(blob_data(attr), data_len, type)) {
        return 0;
      }
    }

    if (info[id].minlen && len < info[id].minlen) {
      return 0;
    }

    if (info[id].maxlen && len > info[id].maxlen) {
      return 0;
    }

    if (info[id].validate && !info[id].validate(&info[id], attr)) {
      return 0;
    }
  }

  if (!data[id]) {
    found++;
  }

  data[id] = attr;
  return found;
}

int blob_parse_untrusted(struct blob_attr* attr,
                         size_t attr_len,
                         struct blob_attr** data,
                         const struct blob_attr_info* info,
                         int max) {
  struct blob_attr* pos;
  size_t len = 0;
  int found = 0;
  size_t rem;

  if (!attr || attr_len < sizeof(struct blob_attr)) {
    return 0;
  }

  len = blob_raw_len(attr);
  if (attr_len < len) {
    return 0;
  }

  memset(data, 0, sizeof(struct blob_attr*) * max);
  blob_for_each_attr_len(pos, attr, len, rem) {
    found += blob_parse_attr(pos, rem, data, info, max);
  }

  return found;
}

/* use only on trusted input, otherwise consider blob_parse_untrusted */
int blob_parse(struct blob_attr* attr,
               struct blob_attr** data,
               const struct blob_attr_info* info,
               int max) {
  struct blob_attr* pos;
  int found = 0;
  size_t rem;

  memset(data, 0, sizeof(struct blob_attr*) * max);
  blob_for_each_attr(pos, attr, rem) {
    found += blob_parse_attr(pos, rem, data, info, max);
  }

  return found;
}

bool blob_attr_equal(const struct blob_attr* a1, const struct blob_attr* a2) {
  if (!a1 && !a2) {
    return true;
  }

  if (!a1 || !a2) {
    return false;
  }

  if (blob_pad_len(a1) != blob_pad_len(a2)) {
    return false;
  }

  return !memcmp(a1, a2, blob_pad_len(a1));
}

struct blob_attr* blob_memdup(struct blob_attr* attr) {
  struct blob_attr* ret;
  int size = blob_pad_len(attr);

  ret = malloc(size);
  if (!ret) {
    return NULL;
  }

  memcpy(ret, attr, size);
  return ret;
}
