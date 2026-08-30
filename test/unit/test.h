#pragma once

#include <stdio.h>

static int test_failures;

#define CHECK(cond)                                                   \
  do {                                                                \
    if (!(cond)) {                                                    \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++test_failures;                                                \
    }                                                                 \
  } while (0)

static inline int test_result(void) {
  if (test_failures) {
    fprintf(stderr, "%d check(s) failed\n", test_failures);
    return 1;
  }
  printf("all checks passed\n");
  return 0;
}
