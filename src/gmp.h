/*
 * Copyright 2015 Steven Barth <steven at midlink.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

enum gmp_family {
  GMP_IGMP = 0,
  GMP_MLD = 1,
};

uint16_t gmp_checksum(const void* data, size_t len);

int gmp_float8_decode(uint8_t value);
uint8_t gmp_float8_encode(int value);
int gmp_float16_decode(uint16_t value);
uint16_t gmp_float16_encode(int value);

struct igmphdr;
struct in6_addr;
struct list_head;
struct mld_hdr;
struct mrib_querier;
struct querier_iface;
struct sockaddr_in;
struct sockaddr_in6;

void igmp_handle(struct mrib_querier* mrib,
                 const struct igmphdr* igmp,
                 size_t len,
                 const struct sockaddr_in* from);
void mld_handle(struct mrib_querier* mrib,
                const struct mld_hdr* hdr,
                size_t len,
                const struct sockaddr_in6* from);
int gmp_send_query(struct querier_iface* q,
                   enum gmp_family family,
                   const struct in6_addr* group,
                   const struct list_head* sources,
                   bool suppress);
