#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

#include "src/querier.h"

#include "ev_stub.h"
#include "mrib_stub.h"
#include "test.h"

static struct querier_iface q;

static _Alignas(16) uint8_t pkt[2048];

static struct in6_addr addr(const char* s) {
  struct in6_addr a;
  CHECK(inet_pton(AF_INET6, s, &a) == 1);
  return a;
}

static in_addr_t addr4(const char* s) {
  struct in_addr a;
  CHECK(inet_pton(AF_INET, s, &a) == 1);
  return a.s_addr;
}

static void noop_timer(struct ev_timer* t) {
  (void)t;
}

static void setup(void) {
  ev_timer_cancel(&q.timeout);
  memset(&q, 0, sizeof(q));
  INIT_LIST_HEAD(&q.users);
  q.timeout.cb = noop_timer;
  q.ifindex = 7;
  groups_init(&q.groups);
  q.groups.source_limit = QUERIER_MAX_SOURCE;
  q.groups.group_limit = QUERIER_MAX_GROUPS;
  q.cfg = q.groups.cfg_v6;
  stub_igmp_source.s_addr = addr4("192.168.1.1");
  stub_mld_source = addr("fe80::1");
  stub_sent_len = 0;
  stub_sent_family = 0;
}

static void teardown(void) {
  groups_deinit(&q.groups);
  ev_timer_cancel(&q.timeout);
}

static struct sockaddr_in from4(void) {
  struct sockaddr_in from = {.sin_family = AF_INET};
  from.sin_addr.s_addr = addr4("192.168.1.2");
  return from;
}

static struct sockaddr_in6 from6(void) {
  struct sockaddr_in6 from = {.sin6_family = AF_INET6};
  from.sin6_addr = addr("fe80::2");
  return from;
}

static size_t build_igmp_report(uint8_t* buf,
                                uint8_t rec_type,
                                in_addr_t grp,
                                const in_addr_t* srcs,
                                size_t nsrc) {
  memset(buf, 0, 8 + 8 + 4 * nsrc);
  buf[0] = 0x22;
  buf[7] = 1;
  buf[8] = rec_type;
  buf[10] = (uint8_t)(nsrc >> 8);
  buf[11] = (uint8_t)nsrc;
  memcpy(&buf[12], &grp, 4);
  for (size_t i = 0; i < nsrc; ++i) {
    memcpy(&buf[16 + 4 * i], &srcs[i], 4);
  }
  return 8 + 8 + 4 * nsrc;
}

static size_t build_igmp_query(uint8_t* buf,
                               in_addr_t grp,
                               const in_addr_t* srcs,
                               size_t nsrc,
                               bool suppress) {
  memset(buf, 0, 12 + 4 * nsrc);
  buf[0] = 0x11;
  buf[1] = 100;
  memcpy(&buf[4], &grp, 4);
  buf[8] = 2 | (suppress ? 0x8 : 0);
  buf[10] = (uint8_t)(nsrc >> 8);
  buf[11] = (uint8_t)nsrc;
  for (size_t i = 0; i < nsrc; ++i) {
    memcpy(&buf[12 + 4 * i], &srcs[i], 4);
  }
  return 12 + 4 * nsrc;
}

static size_t build_mld_report(uint8_t* buf,
                               uint8_t rec_type,
                               const struct in6_addr* grp,
                               const struct in6_addr* srcs,
                               size_t nsrc) {
  memset(buf, 0, 8 + 20 + 16 * nsrc);
  buf[0] = 143;
  buf[7] = 1;
  buf[8] = rec_type;
  buf[10] = (uint8_t)(nsrc >> 8);
  buf[11] = (uint8_t)nsrc;
  memcpy(&buf[12], grp, 16);
  for (size_t i = 0; i < nsrc; ++i) {
    memcpy(&buf[28 + 16 * i], &srcs[i], 16);
  }
  return 8 + 20 + 16 * nsrc;
}

static void igmp_input(size_t len) {
  struct sockaddr_in from = from4();
  igmp_handle(&q.mrib, (const struct igmphdr*)pkt, len, &from);
}

static void mld_input(size_t len) {
  struct sockaddr_in6 from = from6();
  mld_handle(&q.mrib, (const struct mld_hdr*)pkt, len, &from);
}

static void test_igmp_report_exclude(void) {
  setup();
  struct in6_addr grp;
  struct in6_addr any;
  querier_map(&grp, addr4("239.1.2.3"));
  querier_map(&any, addr4("10.0.0.1"));

  igmp_input(
      build_igmp_report(pkt, UPDATE_IS_EXCLUDE, addr4("239.1.2.3"), NULL, 0));
  CHECK(groups_includes_group(&q.groups, &grp, &any, stub_now));

  teardown();
}

static void test_igmp_report_include_sources(void) {
  setup();
  struct in6_addr grp;
  struct in6_addr s1;
  struct in6_addr s2;
  struct in6_addr s3;
  querier_map(&grp, addr4("232.1.1.1"));
  querier_map(&s1, addr4("10.0.0.1"));
  querier_map(&s2, addr4("10.0.0.2"));
  querier_map(&s3, addr4("10.0.0.3"));

  in_addr_t srcs[2] = {addr4("10.0.0.1"), addr4("10.0.0.2")};
  igmp_input(
      build_igmp_report(pkt, UPDATE_IS_INCLUDE, addr4("232.1.1.1"), srcs, 2));
  CHECK(groups_includes_group(&q.groups, &grp, &s1, stub_now));
  CHECK(groups_includes_group(&q.groups, &grp, &s2, stub_now));
  CHECK(!groups_includes_group(&q.groups, &grp, &s3, stub_now));

  teardown();
}

static void test_igmp_report_truncated(void) {
  setup();
  struct in6_addr grp;
  querier_map(&grp, addr4("239.1.2.3"));

  size_t len =
      build_igmp_report(pkt, UPDATE_IS_EXCLUDE, addr4("239.1.2.3"), NULL, 0);
  pkt[11] = 5;
  igmp_input(len);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  igmp_input(10);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_igmp_v2_report_and_leave(void) {
  setup();
  struct in6_addr grp;
  querier_map(&grp, addr4("239.5.5.5"));

  memset(pkt, 0, 8);
  pkt[0] = 0x16;
  in_addr_t g = addr4("239.5.5.5");
  memcpy(&pkt[4], &g, 4);
  igmp_input(8);
  CHECK(groups_includes_group(&q.groups, &grp, NULL, stub_now));

  pkt[0] = 0x17;
  igmp_input(8);
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_igmp_query_updates_source_timers(void) {
  setup();
  struct in6_addr grp;
  struct in6_addr s1;
  querier_map(&grp, addr4("232.7.7.7"));
  querier_map(&s1, addr4("10.0.0.7"));

  in_addr_t srcs[1] = {addr4("10.0.0.7")};
  igmp_input(
      build_igmp_report(pkt, UPDATE_IS_INCLUDE, addr4("232.7.7.7"), srcs, 1));
  CHECK(groups_includes_group(&q.groups, &grp, &s1, stub_now));

  igmp_input(build_igmp_query(pkt, addr4("232.7.7.7"), srcs, 1, false));
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_igmp_query_suppress_respected(void) {
  setup();
  struct in6_addr grp;
  querier_map(&grp, addr4("239.8.8.8"));

  igmp_input(
      build_igmp_report(pkt, UPDATE_IS_EXCLUDE, addr4("239.8.8.8"), NULL, 0));
  igmp_input(build_igmp_query(pkt, addr4("239.8.8.8"), NULL, 0, true));
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) != NULL);

  teardown();
}

static void test_igmp_send_general_query(void) {
  setup();
  CHECK(igmp_send_query(&q, NULL, NULL, false) == 0);
  CHECK(stub_sent_family == 4);
  CHECK(stub_sent_len == 12);
  CHECK(stub_sent[0] == 0x11);

  teardown();
}

static void test_mld_report_exclude(void) {
  setup();
  struct in6_addr grp = addr("ff05::1234");
  struct in6_addr any = addr("2001:db8::1");

  mld_input(build_mld_report(pkt, UPDATE_IS_EXCLUDE, &grp, NULL, 0));
  CHECK(groups_includes_group(&q.groups, &grp, &any, stub_now));

  teardown();
}

static void test_mld_report_include_sources(void) {
  setup();
  struct in6_addr grp = addr("ff35::8000:1");
  struct in6_addr srcs[2] = {addr("2001:db8::1"), addr("2001:db8::2")};
  struct in6_addr s3 = addr("2001:db8::3");

  mld_input(build_mld_report(pkt, UPDATE_IS_INCLUDE, &grp, srcs, 2));
  CHECK(groups_includes_group(&q.groups, &grp, &srcs[0], stub_now));
  CHECK(groups_includes_group(&q.groups, &grp, &srcs[1], stub_now));
  CHECK(!groups_includes_group(&q.groups, &grp, &s3, stub_now));

  teardown();
}

static void test_mld_report_truncated(void) {
  setup();
  struct in6_addr grp = addr("ff05::1234");

  size_t len = build_mld_report(pkt, UPDATE_IS_EXCLUDE, &grp, NULL, 0);
  pkt[11] = 5;
  mld_input(len);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_mld_v1_report_and_done(void) {
  setup();
  struct in6_addr grp = addr("ff05::5555");

  memset(pkt, 0, 24);
  pkt[0] = 131;
  memcpy(&pkt[8], &grp, 16);
  mld_input(24);
  CHECK(groups_includes_group(&q.groups, &grp, NULL, stub_now));

  pkt[0] = 132;
  mld_input(24);
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_mld_send_source_specific_query(void) {
  setup();
  struct in6_addr grp = addr("ff35::8000:9");

  struct group_source s1 = {.addr = addr("2001:db8::1")};
  struct group_source s2 = {.addr = addr("2001:db8::2")};
  struct list_head sources = LIST_HEAD_INIT(sources);
  list_add_tail(&s1.head, &sources);
  list_add_tail(&s2.head, &sources);

  CHECK(mld_send_query(&q, &grp, &sources, false) == 0);
  CHECK(stub_sent_family == 6);
  CHECK(stub_sent_len == 28 + 2 * 16);
  CHECK(stub_sent[26] == 0 && stub_sent[27] == 2);
  CHECK(memcmp(&stub_sent[28], &s1.addr, 16) == 0);
  CHECK(memcmp(&stub_sent[44], &s2.addr, 16) == 0);

  teardown();
}

int main(void) {
  setlogmask(LOG_UPTO(LOG_CRIT));
  test_igmp_report_exclude();
  test_igmp_report_include_sources();
  test_igmp_report_truncated();
  test_igmp_v2_report_and_leave();
  test_igmp_query_updates_source_timers();
  test_igmp_query_suppress_respected();
  test_igmp_send_general_query();
  test_mld_report_exclude();
  test_mld_report_include_sources();
  test_mld_report_truncated();
  test_mld_v1_report_and_done();
  test_mld_send_source_specific_query();
  return test_result();
}
