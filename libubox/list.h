/*-
 * Copyright (c) 2011 Felix Fietkau <nbd@openwrt.org>
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <cstddef>

#ifndef container_of
#define container_of(ptr, type, member)                         \
  ({                                                            \
    const __typeof__(((type*)nullptr)->member)* __mptr = (ptr); \
    (type*)((char*)__mptr - offsetof(type, member));            \
  })
#endif

#ifndef container_of_safe
#define container_of_safe(ptr, type, member)                            \
  ({                                                                    \
    const __typeof__(((type*)nullptr)->member)* __mptr = (ptr);         \
    __mptr ? (type*)((char*)__mptr - offsetof(type, member)) : nullptr; \
  })
#endif

struct ListHead {
  struct ListHead* next;
  struct ListHead* prev;
};

#define LIST_HEAD_INIT(name) \
  { &(name), &(name) }
#undef LIST_HEAD
#define LIST_HEAD(name) struct ListHead name = LIST_HEAD_INIT(name)

void INIT_LIST_HEAD(struct ListHead* list);

bool list_empty(const struct ListHead* head);

bool list_is_first(const struct ListHead* list, const struct ListHead* head);

bool list_is_last(const struct ListHead* list, const struct ListHead* head);

void _list_del(struct ListHead* entry);

void list_del(struct ListHead* entry);

void _list_add(struct ListHead* _new,
               struct ListHead* prev,
               struct ListHead* next);

#define list_entry(ptr, type, field) container_of(ptr, type, field)
#define list_first_entry(ptr, type, field) list_entry((ptr)->next, type, field)

#define list_for_each_entry(p, h, field)                                 \
  for (p = list_first_entry(h, __typeof__(*p), field); &p->field != (h); \
       p = list_entry(p->field.next, __typeof__(*p), field))

#define list_for_each_entry_safe(p, n, h, field)            \
  for (p = list_first_entry(h, __typeof__(*p), field),      \
      n = list_entry(p->field.next, __typeof__(*p), field); \
       &p->field != (h);                                    \
       p = n, n = list_entry(n->field.next, __typeof__(*n), field))

void list_add(struct ListHead* _new, struct ListHead* head);

void list_add_tail(struct ListHead* _new, struct ListHead* head);

void list_move_tail(struct ListHead* entry, struct ListHead* head);

void _list_splice(const struct ListHead* list,
                  struct ListHead* prev,
                  struct ListHead* next);

void list_splice(const struct ListHead* list, struct ListHead* head);

void list_splice_init(struct ListHead* list, struct ListHead* head);
