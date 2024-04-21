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
#include "blobmsg.h"

static const int blob_type[__BLOBMSG_TYPE_LAST] = {
    [BLOBMSG_TYPE_INT8] = BLOB_ATTR_INT8,
    [BLOBMSG_TYPE_INT16] = BLOB_ATTR_INT16,
    [BLOBMSG_TYPE_INT32] = BLOB_ATTR_INT32,
    [BLOBMSG_TYPE_INT64] = BLOB_ATTR_INT64,
    [BLOBMSG_TYPE_DOUBLE] = BLOB_ATTR_DOUBLE,
    [BLOBMSG_TYPE_STRING] = BLOB_ATTR_STRING,
    [BLOBMSG_TYPE_UNSPEC] = BLOB_ATTR_BINARY,
};

int blobmsg_hdrlen(unsigned int namelen) {
  return BLOBMSG_PADDING(sizeof(struct blobmsg_hdr) + namelen + 1);
}

int blobmsg_type(const struct blob_attr* attr) {
  return blob_id(attr);
}

uint16_t blobmsg_namelen(const struct blobmsg_hdr* hdr) {
  return be16_to_cpu(hdr->namelen);
}

void* blobmsg_data(const struct blob_attr* attr) {
  struct blobmsg_hdr* hdr;
  char* data;

  if (!attr) {
    return NULL;
  }

  hdr = (struct blobmsg_hdr*)blob_data(attr);
  data = (char*)blob_data(attr);

  if (blob_is_extended(attr)) {
    data += blobmsg_hdrlen(blobmsg_namelen(hdr));
  }

  return data;
}

size_t blobmsg_data_len(const struct blob_attr* attr) {
  uint8_t *start, *end;

  if (!attr) {
    return 0;
  }

  start = (uint8_t*)blob_data(attr);
  end = (uint8_t*)blobmsg_data(attr);

  return blob_len(attr) - (end - start);
}

int blobmsg_add_string(struct blob_buf* buf,
                       const char* name,
                       const char* string) {
  return blobmsg_add_field(buf, BLOBMSG_TYPE_STRING, name, string,
                           strlen(string) + 1);
}

void* blobmsg_open_array(struct blob_buf* buf, const char* name) {
  return blobmsg_open_nested(buf, name, true);
}

void blobmsg_close_array(struct blob_buf* buf, void* cookie) {
  blob_nest_end(buf, cookie);
}

char* blobmsg_get_string(struct blob_attr* attr) {
  if (!attr) {
    return NULL;
  }

  return (char*)blobmsg_data(attr);
}

static bool blobmsg_check_name(const struct blob_attr* attr, bool name) {
  const struct blobmsg_hdr* hdr;
  uint16_t namelen;

  if (!blob_is_extended(attr)) {
    return !name;
  }

  if (blob_len(attr) < sizeof(struct blobmsg_hdr)) {
    return false;
  }

  hdr = (const struct blobmsg_hdr*)blob_data(attr);
  if (name && !hdr->namelen) {
    return false;
  }

  namelen = blobmsg_namelen(hdr);
  if (blob_len(attr) < (size_t)blobmsg_hdrlen(namelen)) {
    return false;
  }

  if (hdr->name[namelen] != 0) {
    return false;
  }

  return true;
}

bool blobmsg_check_attr_len(const struct blob_attr* attr,
                            bool name,
                            size_t len) {
  const char* data;
  size_t data_len;
  int id;

  if (len < sizeof(struct blob_attr)) {
    return false;
  }

  data_len = blob_raw_len(attr);
  if (data_len < sizeof(struct blob_attr) || data_len > len) {
    return false;
  }

  if (!blobmsg_check_name(attr, name)) {
    return false;
  }

  id = blob_id(attr);
  if (id > BLOBMSG_TYPE_LAST) {
    return false;
  }

  if (!blob_type[id]) {
    return true;
  }

  data = blobmsg_data(attr);
  data_len = blobmsg_data_len(attr);

  return blob_check_type(data, data_len, blob_type[id]);
}

int blobmsg_parse(const struct blobmsg_policy* policy,
                  int policy_len,
                  struct blob_attr** tb,
                  void* data,
                  unsigned int len) {
  const struct blobmsg_hdr* hdr;
  struct blob_attr* attr;
  uint8_t* pslen;
  int i;

  memset(tb, 0, policy_len * sizeof(*tb));
  if (!data || !len) {
    return -EINVAL;
  }
  pslen = alloca(policy_len);
  for (i = 0; i < policy_len; i++) {
    if (!policy[i].name) {
      continue;
    }

    pslen[i] = strlen(policy[i].name);
  }

  __blob_for_each_attr(attr, data, len) {
    if (!blobmsg_check_attr_len(attr, false, len)) {
      return -1;
    }

    if (!blob_is_extended(attr)) {
      continue;
    }

    hdr = blob_data(attr);
    for (i = 0; i < policy_len; i++) {
      if (!policy[i].name) {
        continue;
      }

      if (policy[i].type != BLOBMSG_TYPE_UNSPEC &&
          policy[i].type != BLOBMSG_CAST_INT64 &&
          blob_id(attr) != policy[i].type) {
        continue;
      }

      if (policy[i].type == BLOBMSG_CAST_INT64 &&
          (blob_id(attr) != BLOBMSG_TYPE_INT64 &&
           blob_id(attr) != BLOBMSG_TYPE_INT32 &&
           blob_id(attr) != BLOBMSG_TYPE_INT16 &&
           blob_id(attr) != BLOBMSG_TYPE_INT8)) {
        continue;
      }

      if (blobmsg_namelen(hdr) != pslen[i]) {
        continue;
      }

      if (tb[i]) {
        continue;
      }

      if (strcmp(policy[i].name, (char*)hdr->name) != 0) {
        continue;
      }

      tb[i] = attr;
    }
  }

  return 0;
}

static struct blob_attr* blobmsg_new(struct blob_buf* buf,
                                     int type,
                                     const char* name,
                                     int payload_len,
                                     void** data) {
  struct blob_attr* attr;
  struct blobmsg_hdr* hdr;
  int attrlen, namelen;
  char *pad_start, *pad_end;

  if (!name) {
    name = "";
  }

  namelen = strlen(name);
  attrlen = blobmsg_hdrlen(namelen) + payload_len;
  attr = blob_new(buf, type, attrlen);
  if (!attr) {
    return NULL;
  }

  attr->id_len |= be32_to_cpu(BLOB_ATTR_EXTENDED);
  hdr = blob_data(attr);
  hdr->namelen = cpu_to_be16(namelen);

  memcpy(hdr->name, name, namelen);
  hdr->name[namelen] = '\0';

  pad_end = *data = blobmsg_data(attr);
  pad_start = (char*)&hdr->name[namelen];
  if (pad_start < pad_end) {
    memset(pad_start, 0, pad_end - pad_start);
  }

  return attr;
}

static int attr_to_offset(struct blob_buf* buf, struct blob_attr* attr) {
  return (char*)attr - (char*)buf->buf + BLOB_COOKIE;
}

void* blobmsg_open_nested(struct blob_buf* buf, const char* name, bool array) {
  struct blob_attr* head;
  int type = array ? BLOBMSG_TYPE_ARRAY : BLOBMSG_TYPE_TABLE;
  unsigned long offset = attr_to_offset(buf, buf->head);
  void* data;

  if (!name) {
    name = "";
  }

  head = blobmsg_new(buf, type, name, 0, &data);
  if (!head) {
    return NULL;
  }
  blob_set_raw_len(buf->head,
                   blob_pad_len(buf->head) - blobmsg_hdrlen(strlen(name)));
  buf->head = head;
  return (void*)offset;
}

int blobmsg_add_field(struct blob_buf* buf,
                      int type,
                      const char* name,
                      const void* data,
                      unsigned int len) {
  struct blob_attr* attr;
  void* data_dest;

  attr = blobmsg_new(buf, type, name, len, &data_dest);
  if (!attr) {
    return -1;
  }

  if (len > 0) {
    memcpy(data_dest, data, len);
  }

  return 0;
}
