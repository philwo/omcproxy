#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

#include "src/groups.h"

#include "ev_stub.h"
#include "test.h"

static struct groups g;

static int update_calls;
static struct in6_addr update_addr;
static bool update_included;
static size_t update_source_count;

static int query_calls;
static struct in6_addr query_addr;
static int query_source_count;
static bool query_suppress;

static struct in6_addr addr(const char* s) {
  struct in6_addr a;
  CHECK(inet_pton(AF_INET6, s, &a) == 1);
  return a;
}

static void on_update(struct groups* groups,
                      struct group* group,
                      omgp_time_t now) {
  (void)groups;
  ++update_calls;
  update_addr = group->addr;
  update_included = group_is_included(group, now);
  update_source_count = group->source_count;
}

static void on_query(struct groups* groups,
                     const struct in6_addr* group,
                     const struct list_head* sources,
                     bool suppress) {
  (void)groups;
  ++query_calls;
  query_addr = *group;
  query_suppress = suppress;
  query_source_count = -1;
  if (sources) {
    query_source_count = 0;
    struct group_source* s;
    list_for_each_entry (s, sources, head) {
      ++query_source_count;
    }
  }
}

static void setup(void) {
  memset(&g, 0, sizeof(g));
  groups_init(&g);
  g.source_limit = 4;
  g.group_limit = 4;
  g.cb_update = on_update;
  g.cb_query = on_query;
  update_calls = 0;
  query_calls = 0;
}

static void test_asm_join_and_expiry(void) {
  setup();
  struct in6_addr grp = addr("ff05::1234");
  struct in6_addr any_src = addr("2001:db8::1");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  CHECK(update_calls == 1);
  CHECK(!update_included);
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));
  CHECK(groups_includes_group(&g, &grp, &any_src, stub_now));

  stub_advance(259 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) != NULL);
  CHECK(groups_includes_group(&g, &grp, &any_src, stub_now));

  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);
  CHECK(!groups_includes_group(&g, &grp, &any_src, stub_now));
  CHECK(update_included);

  groups_deinit(&g);
}

static void test_asm_refresh_extends_membership(void) {
  setup();
  struct in6_addr grp = addr("ff05::1234");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  stub_advance(200 * OMGP_TIME_PER_SECOND);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  stub_advance(200 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) != NULL);
  stub_advance(100 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

static void test_ssm_include_join_and_expiry(void) {
  setup();
  struct in6_addr grp = addr("ff3e::1");
  struct in6_addr s1 = addr("2001:db8::1");
  struct in6_addr s2 = addr("2001:db8::2");

  groups_update_state(&g, &grp, &s1, 1, UPDATE_IS_INCLUDE);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));
  CHECK(!groups_includes_group(&g, &grp, &s2, stub_now));
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  stub_advance(261 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);
  CHECK(!groups_includes_group(&g, &grp, &s1, stub_now));

  groups_deinit(&g);
}

static void test_leave_triggers_group_queries(void) {
  setup();
  struct in6_addr grp = addr("::ffff:239.1.2.3");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);

  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(query_source_count == -1);
  CHECK(!query_suppress);
  CHECK(IN6_ARE_ADDR_EQUAL(&query_addr, &grp));

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

static void test_block_triggers_source_queries(void) {
  setup();
  struct in6_addr grp = addr("ff05::42");
  struct in6_addr s1 = addr("2001:db8::7");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);

  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(query_source_count == 1);
  CHECK(IN6_ARE_ADDR_EQUAL(&query_addr, &grp));

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);

  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(!groups_includes_group(&g, &grp, &s1, stub_now));
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  groups_deinit(&g);
}

static void test_compat_mode_ignores_block(void) {
  setup();
  struct in6_addr grp = addr("ff05::99");
  struct in6_addr s1 = addr("2001:db8::5");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_REPORT);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  query_calls = 0;
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  stub_advance(0);
  CHECK(query_calls == 0);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  groups_deinit(&g);
}

static void test_other_querier_timer_update(void) {
  setup();
  struct in6_addr grp = addr("ff05::77");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_timers(&g, &grp, NULL, 0);

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) != NULL);
  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

int main(void) {
  setlogmask(LOG_UPTO(LOG_CRIT));
  test_asm_join_and_expiry();
  test_asm_refresh_extends_membership();
  test_ssm_include_join_and_expiry();
  test_leave_triggers_group_queries();
  test_block_triggers_source_queries();
  test_compat_mode_ignores_block();
  test_other_querier_timer_update();
  return test_result();
}
