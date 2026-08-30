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

#include <string.h>

#include "gmp.h"

uint16_t gmp_checksum(const void* data, size_t len) {
  const uint8_t* p = data;
  uint32_t sum = 0;

  while (len > 1) {
    uint16_t word;
    memcpy(&word, p, sizeof(word));
    sum += word;
    sum = (sum + (sum >> 16)) & 0xffff;
    p += 2;
    len -= 2;
  }

  if (len == 1) {
    uint16_t word = 0;
    memcpy(&word, p, 1);
    sum += word;
    sum = (sum + (sum >> 16)) & 0xffff;
  }

  return (uint16_t)~sum;
}
