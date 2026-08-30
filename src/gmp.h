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
