#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "src/addr.h"
#include "src/gmp.h"
#include "src/querier.h"

#include "ev_stub.h"
#include "mrib_stub.h"
#include "test.h"

static struct querier_iface q;

static _Alignas(16) uint8_t pkt[2048];
static bool fail_calloc;

void* __real_calloc(size_t count, size_t size);

void* __wrap_calloc(size_t count, size_t size) {
  if (fail_calloc) {
    fail_calloc = false;
    errno = ENOMEM;
    return NULL;
  }
  return __real_calloc(count, size);
}

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
  stub_mrib_attach_error = 0;
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

static size_t build_mld_query(uint8_t* buf,
                              const struct in6_addr* grp,
                              const struct in6_addr* srcs,
                              size_t nsrc,
                              bool suppress) {
  memset(buf, 0, 28 + 16 * nsrc);
  buf[0] = 130;
  buf[4] = 0;
  buf[5] = 100;
  if (grp) {
    memcpy(&buf[8], grp, 16);
  }
  buf[24] = 2 | (suppress ? 0x8 : 0);
  buf[26] = (uint8_t)(nsrc >> 8);
  buf[27] = (uint8_t)nsrc;
  for (size_t i = 0; i < nsrc; ++i) {
    memcpy(&buf[28 + 16 * i], &srcs[i], 16);
  }
  return 28 + 16 * nsrc;
}

static void igmp_input(size_t len) {
  struct sockaddr_in from = from4();
  igmp_handle(&q.mrib, (const struct igmphdr*)pkt, len, &from);
}

static void mld_input(size_t len) {
  struct sockaddr_in6 from = from6();
  mld_handle(&q.mrib, (const struct mld_hdr*)pkt, len, &from);
}

static void igmp_input_from(size_t len, const char* ip) {
  struct sockaddr_in from = {.sin_family = AF_INET};
  from.sin_addr.s_addr = addr4(ip);
  igmp_handle(&q.mrib, (const struct igmphdr*)pkt, len, &from);
}

static void mld_input_from(size_t len, const char* ip) {
  struct sockaddr_in6 from = {.sin6_family = AF_INET6};
  from.sin6_addr = addr(ip);
  mld_handle(&q.mrib, (const struct mld_hdr*)pkt, len, &from);
}

static void test_igmp_report_exclude(void) {
  setup();
  struct in6_addr grp;
  struct in6_addr any;
  addr_map(&grp, addr4("239.1.2.3"));
  addr_map(&any, addr4("10.0.0.1"));

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
  addr_map(&grp, addr4("232.1.1.1"));
  addr_map(&s1, addr4("10.0.0.1"));
  addr_map(&s2, addr4("10.0.0.2"));
  addr_map(&s3, addr4("10.0.0.3"));

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
  addr_map(&grp, addr4("239.1.2.3"));

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
  addr_map(&grp, addr4("239.5.5.5"));

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
  addr_map(&grp, addr4("232.7.7.7"));
  addr_map(&s1, addr4("10.0.0.7"));

  in_addr_t srcs[1] = {addr4("10.0.0.7")};
  igmp_input(
      build_igmp_report(pkt, UPDATE_IS_INCLUDE, addr4("232.7.7.7"), srcs, 1));
  CHECK(groups_includes_group(&q.groups, &grp, &s1, stub_now));

  igmp_input(build_igmp_query(pkt, addr4("232.7.7.7"), srcs, 1, false));
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) != NULL);

  stub_advance(18 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_igmp_query_suppress_respected(void) {
  setup();
  struct in6_addr grp;
  addr_map(&grp, addr4("239.8.8.8"));

  igmp_input(
      build_igmp_report(pkt, UPDATE_IS_EXCLUDE, addr4("239.8.8.8"), NULL, 0));
  igmp_input(build_igmp_query(pkt, addr4("239.8.8.8"), NULL, 0, true));
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) != NULL);

  teardown();
}

static void test_igmp_send_general_query(void) {
  setup();
  CHECK(gmp_send_query(&q, GMP_IGMP, NULL, NULL, false) == 0);
  CHECK(stub_sent_family == 4);
  CHECK(stub_sent_len == 12);
  CHECK(stub_sent[0] == 0x11);

  teardown();
}

static void test_igmp_send_source_specific_query(void) {
  setup();
  struct in6_addr grp;
  addr_map(&grp, addr4("232.9.9.9"));

  struct group_source s1 = {.addr = {{{0}}}};
  struct group_source s2 = {.addr = {{{0}}}};
  addr_map(&s1.addr, addr4("10.0.0.1"));
  addr_map(&s2.addr, addr4("10.0.0.2"));
  struct list_head sources = LIST_HEAD_INIT(sources);
  list_add_tail(&s1.head, &sources);
  list_add_tail(&s2.head, &sources);

  CHECK(gmp_send_query(&q, GMP_IGMP, &grp, &sources, false) == 0);
  CHECK(stub_sent_family == 4);
  CHECK(stub_sent_len == 12 + 2 * 4);
  CHECK(stub_sent[10] == 0 && stub_sent[11] == 2);
  CHECK(memcmp(&stub_sent[12], &s1.addr.s6_addr32[3], 4) == 0);
  CHECK(memcmp(&stub_sent[16], &s2.addr.s6_addr32[3], 4) == 0);

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

static void test_igmp_report_aux_data_skipped(void) {
  setup();
  struct in6_addr g1;
  struct in6_addr g2;
  addr_map(&g1, addr4("239.11.11.11"));
  addr_map(&g2, addr4("239.22.22.22"));

  memset(pkt, 0, 64);
  pkt[0] = 0x22;
  pkt[7] = 2;
  pkt[8] = UPDATE_IS_EXCLUDE;
  pkt[9] = 1;
  in_addr_t a = addr4("239.11.11.11");
  memcpy(&pkt[12], &a, 4);
  pkt[20] = UPDATE_IS_EXCLUDE;
  a = addr4("239.22.22.22");
  memcpy(&pkt[24], &a, 4);
  igmp_input(8 + 12 + 8);
  CHECK(groups_get(&q.groups, &g1) != NULL);
  CHECK(groups_get(&q.groups, &g2) != NULL);

  teardown();
}

static void test_mld_report_aux_data_skipped(void) {
  setup();
  struct in6_addr g1 = addr("ff05::a1");
  struct in6_addr g2 = addr("ff05::a2");

  memset(pkt, 0, 64);
  pkt[0] = 143;
  pkt[7] = 2;
  pkt[8] = UPDATE_IS_EXCLUDE;
  pkt[9] = 1;
  memcpy(&pkt[12], &g1, 16);
  pkt[32] = UPDATE_IS_EXCLUDE;
  memcpy(&pkt[36], &g2, 16);
  mld_input(8 + 24 + 20);
  CHECK(groups_get(&q.groups, &g1) != NULL);
  CHECK(groups_get(&q.groups, &g2) != NULL);

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

static void test_mld_query_updates_source_timers(void) {
  setup();
  struct in6_addr grp = addr("ff35::8000:7");
  struct in6_addr srcs[1] = {addr("2001:db8::7")};

  mld_input(build_mld_report(pkt, UPDATE_IS_INCLUDE, &grp, srcs, 1));
  CHECK(groups_includes_group(&q.groups, &grp, &srcs[0], stub_now));

  mld_input(build_mld_query(pkt, &grp, srcs, 1, false));
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_mld_query_suppress_respected(void) {
  setup();
  struct in6_addr grp = addr("ff05::8888");

  mld_input(build_mld_report(pkt, UPDATE_IS_EXCLUDE, &grp, NULL, 0));
  mld_input(build_mld_query(pkt, &grp, NULL, 0, true));
  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) != NULL);

  teardown();
}

static void test_mld_query_respects_received_mrc(void) {
  setup();
  struct in6_addr grp = addr("ff35::8000:77");
  struct in6_addr srcs[1] = {addr("2001:db8::77")};

  mld_input(build_mld_report(pkt, UPDATE_IS_INCLUDE, &grp, srcs, 1));
  size_t len = build_mld_query(pkt, &grp, srcs, 1, false);
  pkt[4] = 0x27;
  pkt[5] = 0x10;
  mld_input(len);

  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) != NULL);

  stub_advance(18 * OMGP_TIME_PER_SECOND);
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

  CHECK(gmp_send_query(&q, GMP_MLD, &grp, &sources, false) == 0);
  CHECK(stub_sent_family == 6);
  CHECK(stub_sent_len == 28 + 2 * 16);
  CHECK(stub_sent[26] == 0 && stub_sent[27] == 2);
  CHECK(memcmp(&stub_sent[28], &s1.addr, 16) == 0);
  CHECK(memcmp(&stub_sent[44], &s2.addr, 16) == 0);

  teardown();
}

static void test_igmp_specific_query_wins_election(void) {
  setup();
  struct in6_addr grp;
  addr_map(&grp, addr4("239.30.30.30"));
  igmp_input(build_igmp_report(pkt, UPDATE_IS_EXCLUDE, addr4("239.30.30.30"),
                               NULL, 0));

  size_t len = build_igmp_query(pkt, addr4("239.30.30.30"), NULL, 0, false);
  pkt[1] = 50;
  pkt[8] = 7;
  igmp_input_from(len, "192.168.1.0");
  CHECK(q.proto[GMP_IGMP].other_querier);
  CHECK(q.groups.cfg_v4.robustness == 7);
  CHECK(q.groups.cfg_v4.query_response_interval == 10000);

  teardown();
}

static void test_mld_specific_query_wins_election(void) {
  setup();
  struct in6_addr grp = addr("ff05::3030");
  mld_input(build_mld_report(pkt, UPDATE_IS_EXCLUDE, &grp, NULL, 0));

  size_t len = build_mld_query(pkt, &grp, NULL, 0, false);
  pkt[24] = 7;
  mld_input_from(len, "fe80::");
  CHECK(q.proto[GMP_MLD].other_querier);
  CHECK(q.groups.cfg_v6.robustness == 7);
  CHECK(q.groups.cfg_v6.query_response_interval == 10000);

  teardown();
}

static void test_igmp_qrv_adopted_while_querier(void) {
  setup();
  size_t len = build_igmp_query(pkt, 0, NULL, 0, false);
  pkt[8] = 7;
  pkt[9] = 30;
  igmp_input(len);
  CHECK(!q.proto[GMP_IGMP].other_querier);
  CHECK(q.groups.cfg_v4.robustness == 7);
  CHECK(q.groups.cfg_v4.query_interval == 125 * OMGP_TIME_PER_SECOND);
  CHECK(q.groups.cfg_v4.query_response_interval == 10 * OMGP_TIME_PER_SECOND);

  teardown();
}

static void test_mld_qrv_adopted_while_querier(void) {
  setup();
  size_t len = build_mld_query(pkt, NULL, NULL, 0, false);
  pkt[24] = 7;
  pkt[25] = 30;
  mld_input(len);
  CHECK(!q.proto[GMP_MLD].other_querier);
  CHECK(q.groups.cfg_v6.robustness == 7);
  CHECK(q.groups.cfg_v6.query_interval == 125 * OMGP_TIME_PER_SECOND);
  CHECK(q.groups.cfg_v6.query_response_interval == 10 * OMGP_TIME_PER_SECOND);

  teardown();
}

static void test_igmp_nonquerier_adopts_latest_query_config(void) {
  setup();
  size_t len = build_igmp_query(pkt, 0, NULL, 0, false);
  pkt[8] = 7;
  igmp_input_from(len, "192.168.1.0");
  CHECK(q.proto[GMP_IGMP].other_querier);
  CHECK(q.groups.cfg_v4.robustness == 7);
  CHECK(q.groups.cfg_v4.query_interval == 125 * OMGP_TIME_PER_SECOND);
  omgp_time_t oqpt = q.proto[GMP_IGMP].next_query;

  len = build_igmp_query(pkt, 0, NULL, 0, false);
  pkt[8] = 3;
  pkt[9] = 30;
  igmp_input_from(len, "192.168.1.3");
  CHECK(q.proto[GMP_IGMP].other_querier);
  CHECK(q.groups.cfg_v4.robustness == 3);
  CHECK(q.groups.cfg_v4.query_interval == 30 * OMGP_TIME_PER_SECOND);
  CHECK(q.proto[GMP_IGMP].next_query == oqpt);

  teardown();
}

static void test_mld_nonquerier_adopts_latest_query_config(void) {
  setup();
  size_t len = build_mld_query(pkt, NULL, NULL, 0, false);
  pkt[24] = 7;
  mld_input_from(len, "fe80::");
  CHECK(q.proto[GMP_MLD].other_querier);
  CHECK(q.groups.cfg_v6.robustness == 7);
  CHECK(q.groups.cfg_v6.query_interval == 125 * OMGP_TIME_PER_SECOND);
  omgp_time_t oqpt = q.proto[GMP_MLD].next_query;

  len = build_mld_query(pkt, NULL, NULL, 0, false);
  pkt[24] = 3;
  pkt[25] = 30;
  mld_input_from(len, "fe80::3");
  CHECK(q.proto[GMP_MLD].other_querier);
  CHECK(q.groups.cfg_v6.robustness == 3);
  CHECK(q.groups.cfg_v6.query_interval == 30 * OMGP_TIME_PER_SECOND);
  CHECK(q.proto[GMP_MLD].next_query == oqpt);

  teardown();
}

static void test_igmp_general_query_mrc_zero(void) {
  setup();
  size_t len = build_igmp_query(pkt, 0, NULL, 0, false);
  pkt[1] = 0;
  igmp_input_from(len, "192.168.1.0");
  CHECK(q.proto[GMP_IGMP].other_querier);
  CHECK(q.groups.cfg_v4.query_response_interval == 0);
  CHECK(q.proto[GMP_IGMP].next_query == stub_now + (omgp_time_t)2 * 125000);

  teardown();
}

static void test_mld_general_query_mrc_zero(void) {
  setup();
  size_t len = build_mld_query(pkt, NULL, NULL, 0, false);
  pkt[5] = 0;
  mld_input_from(len, "fe80::");
  CHECK(q.proto[GMP_MLD].other_querier);
  CHECK(q.groups.cfg_v6.query_response_interval == 0);
  CHECK(q.proto[GMP_MLD].next_query == stub_now + (omgp_time_t)2 * 125000);

  teardown();
}

static void test_igmp_zero_group_with_sources_ignored(void) {
  setup();
  in_addr_t srcs[1] = {addr4("10.0.0.1")};
  size_t len = build_igmp_query(pkt, 0, srcs, 1, false);
  pkt[8] = 7;
  igmp_input_from(len, "192.168.1.0");
  CHECK(!q.proto[GMP_IGMP].other_querier);
  CHECK(q.groups.cfg_v4.robustness == 2);

  teardown();
}

static void test_mld_zero_group_with_sources_ignored(void) {
  setup();
  struct in6_addr srcs[1] = {addr("2001:db8::1")};
  size_t len = build_mld_query(pkt, NULL, srcs, 1, false);
  pkt[24] = 7;
  mld_input_from(len, "fe80::");
  CHECK(!q.proto[GMP_MLD].other_querier);
  CHECK(q.groups.cfg_v6.robustness == 2);

  teardown();
}

static void test_igmp_query_source_beyond_76_processed(void) {
  setup();
  struct in6_addr grp;
  struct in6_addr s1;
  addr_map(&grp, addr4("232.7.7.7"));
  addr_map(&s1, addr4("10.0.7.7"));

  in_addr_t rep_srcs[1] = {addr4("10.0.7.7")};
  igmp_input(build_igmp_report(pkt, UPDATE_IS_INCLUDE, addr4("232.7.7.7"),
                               rep_srcs, 1));
  CHECK(groups_includes_group(&q.groups, &grp, &s1, stub_now));

  in_addr_t qsrcs[77];
  for (uint32_t i = 0; i < 76; ++i) {
    qsrcs[i] = htobe32(UINT32_C(0x0a010000) + i);
  }
  qsrcs[76] = addr4("10.0.7.7");
  size_t len = build_igmp_query(pkt, addr4("232.7.7.7"), qsrcs, 77, false);
  pkt[1] = 10;
  igmp_input(len);

  stub_advance(3 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&q.groups, &grp) == NULL);

  teardown();
}

static void test_float8_codec(void) {
  CHECK(gmp_float8_decode(0) == 0);
  CHECK(gmp_float8_decode(127) == 127);
  CHECK(gmp_float8_decode(0x8f) == 248);
  CHECK(gmp_float8_decode(0xff) == 31744);
  CHECK(gmp_float8_encode(100) == 100);
  CHECK(gmp_float8_encode(127) == 127);
  CHECK(gmp_float8_encode(248) == 0x8f);
  CHECK(gmp_float8_encode(31744) == 0xff);
  CHECK(gmp_float8_encode(1000000) == 0xff);
  for (int v = 1; v < 40000; v += 7) {
    int rt = gmp_float8_decode(gmp_float8_encode(v));
    CHECK(rt <= v || v > 31744);
    CHECK(rt > v / 2);
  }
}

static void test_float16_codec(void) {
  CHECK(gmp_float16_decode(0) == 0);
  CHECK(gmp_float16_decode(32767) == 32767);
  CHECK(gmp_float16_decode(0x8fff) == 65528);
  CHECK(gmp_float16_decode(0xffff) == 8387584);
  CHECK(gmp_float16_encode(10000) == 10000);
  CHECK(gmp_float16_encode(65528) == 0x8fff);
  CHECK(gmp_float16_encode(8387584) == 0xffff);
  CHECK(gmp_float16_encode(100000000) == 0xffff);
  for (int v = 1; v < 9000000; v += 1009) {
    int rt = gmp_float16_decode(gmp_float16_encode(v));
    CHECK(rt <= v || v > 8387584);
    CHECK(rt > v / 2);
  }
}

static void test_ipv4_router_alert_walk(void) {
  uint8_t ra[] = {0x94, 0x04, 0x00, 0x00};
  CHECK(gmp_ipv4_router_alert(ra, sizeof(ra)));

  uint8_t nop_ra[] = {0x01, 0x94, 0x04, 0x00, 0x00};
  CHECK(gmp_ipv4_router_alert(nop_ra, sizeof(nop_ra)));

  uint8_t other_then_ra[] = {0x07, 0x03, 0x04, 0x94, 0x04, 0x00, 0x00, 0x00};
  CHECK(gmp_ipv4_router_alert(other_then_ra, sizeof(other_then_ra)));

  uint8_t end[] = {0x00, 0x94, 0x04, 0x00, 0x00};
  CHECK(!gmp_ipv4_router_alert(end, sizeof(end)));

  uint8_t bad_len[] = {0x07, 0x00, 0x94, 0x04, 0x00, 0x00};
  CHECK(!gmp_ipv4_router_alert(bad_len, sizeof(bad_len)));

  CHECK(!gmp_ipv4_router_alert(NULL, 0));

  uint8_t truncated[] = {0x94, 0x04, 0x00};
  CHECK(!gmp_ipv4_router_alert(truncated, sizeof(truncated)));

  uint8_t nonzero_value[] = {0x94, 0x04, 0x00, 0x01};
  CHECK(!gmp_ipv4_router_alert(nonzero_value, sizeof(nonzero_value)));
}

static void test_ipv6_router_alert_walk(void) {
  uint8_t ra[] = {0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00};
  CHECK(gmp_ipv6_router_alert(ra, sizeof(ra)));

  uint8_t pad1_ra[] = {0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00};
  CHECK(gmp_ipv6_router_alert(pad1_ra, sizeof(pad1_ra)));

  uint8_t wrong_value[] = {0x00, 0x00, 0x05, 0x02, 0x00, 0x01, 0x01, 0x00};
  CHECK(!gmp_ipv6_router_alert(wrong_value, sizeof(wrong_value)));

  uint8_t embedded[] = {0x00, 0x00, 0x1e, 0x04, 0x05, 0x02, 0x00, 0x00};
  CHECK(!gmp_ipv6_router_alert(embedded, sizeof(embedded)));

  uint8_t none[] = {0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00};
  CHECK(!gmp_ipv6_router_alert(none, sizeof(none)));

  CHECK(!gmp_ipv6_router_alert(NULL, 0));
}

static void test_mrib_filter_bits(void) {
  CHECK(mrib_filter_bit(0) == UINT32_C(1));
  CHECK(mrib_filter_bit(31) == UINT32_C(0x80000000));
  CHECK(MRIB_DEFAULT_LIFETIME * OMGP_TIME_PER_SECOND == 125000);
}

static void test_checksum_even_length_self_verifies(void) {
  uint8_t query[12] = {0x11, 0x64};
  uint16_t csum = gmp_checksum(query, sizeof(query));
  memcpy(&query[2], &csum, 2);
  CHECK(gmp_checksum(query, sizeof(query)) == 0);
}

static void test_checksum_odd_length_self_verifies(void) {
  uint8_t data[5] = {0x11, 0x64, 0, 0, 0x7f};
  uint16_t csum = gmp_checksum(data, sizeof(data));
  memcpy(&data[2], &csum, 2);
  CHECK(gmp_checksum(data, sizeof(data)) == 0);
}

static void test_checksum_carry_folding(void) {
  uint8_t data[8] = {0xff, 0xff, 0xff, 0xff, 0, 0, 0xff, 0xff};
  uint16_t csum = gmp_checksum(data, sizeof(data));
  memcpy(&data[4], &csum, 2);
  CHECK(gmp_checksum(data, sizeof(data)) == 0);
}

static void reset_attach_stubs(void) {
  stub_mrib_attach_error = 0;
  stub_mrib_attach_calls = 0;
  stub_mrib_detach_calls = 0;
  stub_timer_set_calls = 0;
}

static void test_querier_attach_allocation_failure(void) {
  struct querier querier;
  struct querier_user_iface user = {0};
  querier_init(&querier);
  reset_attach_stubs();
  fail_calloc = true;

  CHECK(querier_attach(&user, &querier, 7, NULL) == -ENOMEM);
  CHECK(user.iface == NULL);
  CHECK(list_empty(&querier.ifaces));
  CHECK(stub_mrib_attach_calls == 0);
  CHECK(stub_timer_set_calls == 0);
  querier_deinit(&querier);
}

static void test_querier_attach_mrib_failure(void) {
  struct querier querier;
  struct querier_user_iface user = {0};
  querier_init(&querier);
  reset_attach_stubs();
  stub_mrib_attach_error = -ENODEV;

  CHECK(querier_attach(&user, &querier, 7, NULL) == -ENODEV);
  CHECK(user.iface == NULL);
  CHECK(list_empty(&querier.ifaces));
  CHECK(stub_mrib_attach_calls == 1);
  CHECK(stub_mrib_detach_calls == 0);
  CHECK(stub_timer_set_calls == 0);
  querier_deinit(&querier);
}

static void test_startup_tries_kept_after_send_failure(void) {
  struct querier querier;
  struct querier_user_iface user = {.user_cb = NULL};
  stub_igmp_source.s_addr = addr4("192.168.1.1");
  stub_mld_source = addr("fe80::1");
  stub_mrib_attach_error = 0;
  stub_send_result = -1;
  stub_send_count = 0;

  CHECK(querier_init(&querier) == 0);
  CHECK(querier_attach(&user, &querier, 9, NULL) == 0);
  struct querier_iface* iface = user.iface;

  stub_advance(0);
  CHECK(stub_send_count == 2);
  CHECK(ev_timer_remaining(&iface->timeout) == 125000 / 4);

  stub_advance(125000 / 4);
  CHECK(stub_send_count == 4);
  CHECK(ev_timer_remaining(&iface->timeout) == 125000 / 4);

  stub_send_result = 0;
  stub_advance(125000 / 4);
  CHECK(stub_send_count == 6);
  CHECK(ev_timer_remaining(&iface->timeout) == 125000 / 4);

  stub_advance(125000 / 4);
  CHECK(stub_send_count == 8);
  CHECK(ev_timer_remaining(&iface->timeout) == 125000);

  querier_detach(&user);
}

static void test_igmp_report_duplicates_do_not_crowd_out_sources(void) {
  setup();
  struct in6_addr grp;
  struct in6_addr s1;
  struct in6_addr s2;
  addr_map(&grp, addr4("239.10.10.10"));
  addr_map(&s1, addr4("10.0.1.1"));
  addr_map(&s2, addr4("10.0.1.2"));

  in_addr_t srcs[QUERIER_MAX_SOURCE + 2];
  for (size_t i = 0; i < QUERIER_MAX_SOURCE + 1; ++i) {
    srcs[i] = addr4("10.0.1.1");
  }
  srcs[QUERIER_MAX_SOURCE + 1] = addr4("10.0.1.2");
  igmp_input(build_igmp_report(pkt, UPDATE_IS_INCLUDE, addr4("239.10.10.10"),
                               srcs, QUERIER_MAX_SOURCE + 2));
  CHECK(groups_includes_group(&q.groups, &grp, &s1, stub_now));
  CHECK(groups_includes_group(&q.groups, &grp, &s2, stub_now));

  teardown();
}

static void test_mld_report_duplicates_do_not_crowd_out_sources(void) {
  setup();
  struct in6_addr grp = addr("ff05::1010");
  struct in6_addr s1 = addr("2001:db8::1");
  struct in6_addr s2 = addr("2001:db8::2");

  struct in6_addr srcs[QUERIER_MAX_SOURCE + 2];
  for (size_t i = 0; i < QUERIER_MAX_SOURCE + 1; ++i) {
    srcs[i] = s1;
  }
  srcs[QUERIER_MAX_SOURCE + 1] = s2;
  mld_input(build_mld_report(pkt, UPDATE_IS_INCLUDE, &grp, srcs,
                             QUERIER_MAX_SOURCE + 2));
  CHECK(groups_includes_group(&q.groups, &grp, &s1, stub_now));
  CHECK(groups_includes_group(&q.groups, &grp, &s2, stub_now));

  teardown();
}

int main(void) {
  setlogmask(LOG_UPTO(LOG_CRIT));
  test_float8_codec();
  test_float16_codec();
  test_ipv4_router_alert_walk();
  test_ipv6_router_alert_walk();
  test_mrib_filter_bits();
  test_checksum_even_length_self_verifies();
  test_checksum_odd_length_self_verifies();
  test_checksum_carry_folding();
  test_querier_attach_allocation_failure();
  test_querier_attach_mrib_failure();
  test_startup_tries_kept_after_send_failure();
  test_igmp_report_exclude();
  test_igmp_report_include_sources();
  test_igmp_report_truncated();
  test_igmp_v2_report_and_leave();
  test_igmp_query_updates_source_timers();
  test_igmp_query_suppress_respected();
  test_igmp_send_general_query();
  test_igmp_send_source_specific_query();
  test_mld_report_exclude();
  test_mld_report_include_sources();
  test_mld_report_truncated();
  test_igmp_report_aux_data_skipped();
  test_mld_report_aux_data_skipped();
  test_mld_v1_report_and_done();
  test_mld_query_updates_source_timers();
  test_mld_query_suppress_respected();
  test_mld_query_respects_received_mrc();
  test_mld_send_source_specific_query();
  test_igmp_specific_query_wins_election();
  test_mld_specific_query_wins_election();
  test_igmp_qrv_adopted_while_querier();
  test_mld_qrv_adopted_while_querier();
  test_igmp_nonquerier_adopts_latest_query_config();
  test_mld_nonquerier_adopts_latest_query_config();
  test_igmp_general_query_mrc_zero();
  test_mld_general_query_mrc_zero();
  test_igmp_zero_group_with_sources_ignored();
  test_mld_zero_group_with_sources_ignored();
  test_igmp_query_source_beyond_76_processed();
  test_igmp_report_duplicates_do_not_crowd_out_sources();
  test_mld_report_duplicates_do_not_crowd_out_sources();
  return test_result();
}
