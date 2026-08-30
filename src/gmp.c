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

static int gmp_float_decode(unsigned int value,
                            unsigned int flag_bit,
                            unsigned int exp_shift,
                            unsigned int mant_mask) {
  if (!(value & flag_bit)) {
    return (int)value;
  }

  unsigned int exp = (value >> exp_shift) & 0x7;
  unsigned int mant = (value & mant_mask) | (mant_mask + 1);
  return (int)(mant << (exp + 3));
}

static unsigned int gmp_float_encode(int value,
                                     unsigned int flag_bit,
                                     unsigned int exp_shift,
                                     unsigned int mant_mask) {
  if (value < (int)flag_bit) {
    return (unsigned int)value;
  }

  unsigned int exp = 3;
  while (((unsigned int)value >> exp) > (2 * mant_mask + 1) && exp <= 10) {
    ++exp;
  }

  if (exp > 10) {
    return flag_bit | (mant_mask << exp_shift) | mant_mask;
  }

  return flag_bit | ((exp - 3) << exp_shift) |
         (((unsigned int)value >> exp) & mant_mask);
}

int gmp_float8_decode(uint8_t value) {
  return gmp_float_decode(value, 0x80, 4, 0xf);
}

uint8_t gmp_float8_encode(int value) {
  return (uint8_t)gmp_float_encode(value, 0x80, 4, 0xf);
}

int gmp_float16_decode(uint16_t value) {
  return gmp_float_decode(value, 0x8000, 12, 0xfff);
}

uint16_t gmp_float16_encode(int value) {
  return (uint16_t)gmp_float_encode(value, 0x8000, 12, 0xfff);
}
