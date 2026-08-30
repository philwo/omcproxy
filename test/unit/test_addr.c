#include <arpa/inet.h>
#include <string.h>

#include "src/addr.h"

#include "test.h"

static struct in6_addr addr(const char* s) {
  struct in6_addr a;
  CHECK(inet_pton(AF_INET6, s, &a) == 1);
  return a;
}

static void test_formats_ipv6(void) {
  char buf[ADDR_BUFLEN];
  struct in6_addr a = addr("ff05::1234");
  CHECK(strcmp(addr_ntop(buf, sizeof(buf), &a), "ff05::1234") == 0);
}

static void test_formats_v4mapped_as_ipv4(void) {
  char buf[ADDR_BUFLEN];
  struct in6_addr a = addr("::ffff:239.1.2.3");
  CHECK(strcmp(addr_ntop(buf, sizeof(buf), &a), "239.1.2.3") == 0);
}

static void test_small_buffer_returns_placeholder(void) {
  char buf[4];
  struct in6_addr a = addr("2001:db8::1");
  CHECK(strcmp(addr_ntop(buf, sizeof(buf), &a), "?") == 0);
}

static void test_full_length_address_fits(void) {
  char buf[ADDR_BUFLEN];
  struct in6_addr a = addr("2001:db8:1234:5678:9abc:def0:1234:5678");
  CHECK(strcmp(addr_ntop(buf, sizeof(buf), &a),
               "2001:db8:1234:5678:9abc:def0:1234:5678") == 0);
}

int main(void) {
  test_formats_ipv6();
  test_formats_v4mapped_as_ipv4();
  test_small_buffer_returns_placeholder();
  test_full_length_address_fits();
  return test_result();
}
