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

static void test_ssm_ranges(void) {
  struct in6_addr a;

  a = addr("ff35::1");
  CHECK(addr_is_ssm(&a));
  a = addr("ff3e::8000:1");
  CHECK(addr_is_ssm(&a));
  a = addr("::ffff:232.1.2.3");
  CHECK(addr_is_ssm(&a));

  a = addr("ff3e:40:2001:db8::1234");
  CHECK(!addr_is_ssm(&a));
  a = addr("ff35:100::1");
  CHECK(!addr_is_ssm(&a));
  a = addr("ff0e::1");
  CHECK(!addr_is_ssm(&a));
  a = addr("ff7e::1");
  CHECK(!addr_is_ssm(&a));
  a = addr("::ffff:224.1.1.1");
  CHECK(!addr_is_ssm(&a));
  a = addr("::ffff:239.1.2.3");
  CHECK(!addr_is_ssm(&a));
}

static void test_linklocal_requires_fe80_64(void) {
  struct in6_addr a;

  a = addr("fe80::1");
  CHECK(addr_is_linklocal(&a));
  a = addr("fe80::0123:4567:89ab:cdef");
  CHECK(addr_is_linklocal(&a));

  a = addr("fe80:1::1");
  CHECK(!addr_is_linklocal(&a));
  a = addr("fe80:0:0:1::1");
  CHECK(!addr_is_linklocal(&a));
  a = addr("fe81::1");
  CHECK(!addr_is_linklocal(&a));
  a = addr("febf::1");
  CHECK(!addr_is_linklocal(&a));
  a = addr("fec0::1");
  CHECK(!addr_is_linklocal(&a));
  a = addr("2001:db8::1");
  CHECK(!addr_is_linklocal(&a));
}

int main(void) {
  test_formats_ipv6();
  test_formats_v4mapped_as_ipv4();
  test_small_buffer_returns_placeholder();
  test_full_length_address_fits();
  test_ssm_ranges();
  test_linklocal_requires_fe80_64();
  return test_result();
}
