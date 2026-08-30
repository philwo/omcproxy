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
static enum groups_query_result query_result;

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

static enum groups_query_result on_query(struct groups* groups,
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
  return query_result;
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
  query_result = GROUPS_QUERY_SENT;
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

static void test_source_overflow_falls_back_to_asm(void) {
  setup();
  g.source_limit = 2;
  struct in6_addr group = addr("ff05::abcd");
  struct in6_addr sources[2] = {addr("2001:db8::1"), addr("2001:db8::2")};
  struct in6_addr third = addr("2001:db8::3");
  struct in6_addr unrelated = addr("2001:db8::ee");

  groups_update_state(&g, &group, sources, 2, UPDATE_IS_INCLUDE);
  CHECK(!groups_includes_group(&g, &group, &unrelated, stub_now));

  groups_update_state(&g, &group, &third, 1, UPDATE_IS_INCLUDE);
  CHECK(groups_includes_group(&g, &group, &unrelated, stub_now));
  CHECK(groups_includes_group(&g, &group, &third, stub_now));

  groups_deinit(&g);
}

static void test_source_overflow_mid_update_falls_back_to_asm(void) {
  setup();
  g.source_limit = 2;
  struct in6_addr group = addr("ff05::dcba");
  struct in6_addr sources[2] = {addr("2001:db8::1"), addr("2001:db8::2")};
  struct in6_addr mixed[2] = {addr("2001:db8::1"), addr("2001:db8::3")};
  struct in6_addr unrelated = addr("2001:db8::ee");

  groups_update_state(&g, &group, sources, 2, UPDATE_IS_INCLUDE);
  groups_update_state(&g, &group, mixed, 2, UPDATE_TO_EX);
  CHECK(groups_includes_group(&g, &group, &unrelated, stub_now));
  CHECK(update_source_count == 0);

  groups_deinit(&g);
}

static void test_overdue_timer_not_postponed(void) {
  setup();
  struct in6_addr g1 = addr("ff05::aa");
  struct in6_addr g2 = addr("ff05::bb");

  groups_update_state(&g, &g1, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &g1, NULL, 0, UPDATE_TO_IN);
  stub_advance(0);
  stub_advance(OMGP_TIME_PER_SECOND);

  stub_now += 2 * OMGP_TIME_PER_SECOND;
  groups_update_state(&g, &g2, NULL, 0, UPDATE_IS_EXCLUDE);
  stub_advance(0);
  CHECK(groups_get(&g, &g1) == NULL);
  CHECK(groups_get(&g, &g2) != NULL);

  groups_deinit(&g);
}

static void test_repeated_block_sends_immediate_query_keeps_counter(void) {
  setup();
  struct in6_addr grp = addr("ff05::66");
  struct in6_addr s1 = addr("2001:db8::6");

  groups_update_state(&g, &grp, &s1, 1, UPDATE_IS_INCLUDE);
  query_calls = 0;
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  stub_advance(0);
  CHECK(query_calls == 1);

  stub_advance(OMGP_TIME_PER_SECOND / 2);
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  stub_advance(0);
  CHECK(query_calls == 2);

  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);

  groups_deinit(&g);
}

static void test_repeated_to_in_restarts_group_query_sequence(void) {
  setup();
  struct in6_addr grp = addr("ff05::cc");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
  stub_advance(0);
  CHECK(query_calls == 1);

  stub_advance(OMGP_TIME_PER_SECOND / 2);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
  stub_advance(0);
  CHECK(query_calls == 2);

  stub_advance(OMGP_TIME_PER_SECOND / 2);
  CHECK(query_calls == 2);

  stub_advance(OMGP_TIME_PER_SECOND / 2);
  CHECK(query_calls == 3);

  stub_advance(5 * OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 3);

  groups_deinit(&g);
}

static void test_group_limit_enforced(void) {
  setup();
  g.group_limit = 2;
  struct in6_addr first = addr("ff05::1");
  struct in6_addr second = addr("ff05::2");
  struct in6_addr third = addr("ff05::3");

  groups_update_state(&g, &first, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &second, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &third, NULL, 0, UPDATE_IS_EXCLUDE);
  CHECK(groups_get(&g, &first) != NULL);
  CHECK(groups_get(&g, &second) != NULL);
  CHECK(groups_get(&g, &third) == NULL);

  stub_advance(261 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &first) == NULL);
  groups_update_state(&g, &third, NULL, 0, UPDATE_IS_EXCLUDE);
  CHECK(groups_get(&g, &third) != NULL);

  groups_deinit(&g);
}

static void test_other_querier_timer_update(void) {
  setup();
  struct in6_addr grp = addr("ff05::77");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_timers(&g, &grp, NULL, 0, OMGP_TIME_PER_SECOND, 2);

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) != NULL);
  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

static void test_group_query_attempt_kept_after_failure(void) {
  setup();
  struct in6_addr grp = addr("ff05::f2");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  query_result = GROUPS_QUERY_FAILED;
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);

  stub_advance(0);
  CHECK(query_calls == 1);
  query_result = GROUPS_QUERY_SENT;
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 3);
  CHECK(groups_get(&g, &grp) != NULL);
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

static void test_failed_group_queries_stop_at_natural_expiry(void) {
  setup();
  struct in6_addr grp = addr("ff05::f1");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  query_result = GROUPS_QUERY_FAILED;
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);

  stub_advance(258 * OMGP_TIME_PER_SECOND);
  CHECK(query_calls > 3);
  CHECK(groups_get(&g, &grp) != NULL);
  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

static void test_source_query_attempt_kept_after_failure(void) {
  setup();
  struct in6_addr grp = addr("ff05::f3");
  struct in6_addr s1 = addr("2001:db8::f3");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  query_result = GROUPS_QUERY_FAILED;
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);

  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(query_source_count == 1);
  query_result = GROUPS_QUERY_SENT;
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 3);

  groups_deinit(&g);
}

static void test_failed_source_queries_stop_at_natural_expiry(void) {
  setup();
  struct in6_addr grp = addr("ff05::f5");
  struct in6_addr s1 = addr("2001:db8::f5");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  query_calls = 0;
  query_result = GROUPS_QUERY_FAILED;
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);

  stub_advance(100 * OMGP_TIME_PER_SECOND);
  CHECK(query_calls > 3);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  stub_advance(160 * OMGP_TIME_PER_SECOND);
  CHECK(!groups_includes_group(&g, &grp, &s1, stub_now));

  groups_deinit(&g);
}

static void test_skipped_group_query_cancels_schedule(void) {
  setup();
  struct in6_addr grp = addr("ff05::b3");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
  query_calls = 0;
  query_result = GROUPS_QUERY_SKIPPED;

  stub_advance(0);
  CHECK(query_calls == 1);
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 1);

  groups_deinit(&g);
}

static void test_skipped_source_query_cancels_schedule(void) {
  setup();
  struct in6_addr grp = addr("ff05::b4");
  struct in6_addr s1 = addr("2001:db8::b4");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  query_calls = 0;
  query_result = GROUPS_QUERY_SKIPPED;

  stub_advance(0);
  CHECK(query_calls == 1);
  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 1);

  groups_deinit(&g);
}

static void test_overdue_group_membership_stays_active(void) {
  setup();
  struct in6_addr grp = addr("ff05::b1");
  struct in6_addr any_src = addr("2001:db8::b1");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
  query_calls = 0;

  stub_now += 3 * OMGP_TIME_PER_SECOND;
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));
  CHECK(groups_includes_group(&g, &grp, &any_src, stub_now));

  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(groups_get(&g, &grp) == NULL);
  CHECK(update_included);

  groups_deinit(&g);
}

static void test_overdue_source_membership_stays_active(void) {
  setup();
  struct in6_addr grp = addr("ff05::b2");
  struct in6_addr s1 = addr("2001:db8::b2");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  query_calls = 0;

  stub_now += 3 * OMGP_TIME_PER_SECOND;
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(query_calls == 2);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  stub_advance(OMGP_TIME_PER_SECOND);
  CHECK(!groups_includes_group(&g, &grp, &s1, stub_now));
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  groups_deinit(&g);
}

static void test_failed_suppressed_group_query_keeps_deadline(void) {
  setup();
  struct in6_addr grp = addr("ff05::f8");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_timers(&g, &grp, NULL, 0, 10 * OMGP_TIME_PER_SECOND, 2);
  omgp_time_t lowered = stub_now + 20 * OMGP_TIME_PER_SECOND;

  query_calls = 0;
  query_result = GROUPS_QUERY_FAILED;
  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(query_suppress);
  const struct group* group = groups_get(&g, &grp);
  CHECK(group != NULL && group->exclude_until == lowered);

  groups_deinit(&g);
}

static void test_failed_suppressed_source_query_keeps_deadline(void) {
  setup();
  struct in6_addr grp = addr("ff05::f9");
  struct in6_addr s1 = addr("2001:db8::f9");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  groups_update_state(&g, &grp, &s1, 1, UPDATE_ALLOW);
  groups_update_timers(&g, &grp, &s1, 1, 10 * OMGP_TIME_PER_SECOND, 2);
  omgp_time_t lowered = stub_now + 20 * OMGP_TIME_PER_SECOND;

  query_calls = 0;
  query_result = GROUPS_QUERY_FAILED;
  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(query_suppress);
  const struct group* group = groups_get(&g, &grp);
  CHECK(group != NULL);
  if (group) {
    const struct group_source* source;
    group_for_each_source (source, group) {
      CHECK(source->include_until == lowered);
    }
  }

  groups_deinit(&g);
}

static void test_received_query_deadline_overrides_group_protection(void) {
  setup();
  struct in6_addr grp = addr("ff05::c1");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
  stub_advance(0);
  CHECK(query_calls >= 1);

  stub_advance(100);
  groups_update_timers(&g, &grp, NULL, 0, 100, 2);

  stub_advance(100);
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  stub_advance(150);
  CHECK(groups_get(&g, &grp) == NULL);

  groups_deinit(&g);
}

static void test_received_query_deadline_overrides_source_protection(void) {
  setup();
  struct in6_addr grp = addr("ff05::c2");
  struct in6_addr s1 = addr("2001:db8::c2");

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, &s1, 1, UPDATE_BLOCK);
  stub_advance(0);
  CHECK(query_calls >= 1);

  stub_advance(100);
  groups_update_timers(&g, &grp, &s1, 1, 100, 2);

  stub_advance(100);
  CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

  stub_advance(150);
  CHECK(!groups_includes_group(&g, &grp, &s1, stub_now));
  CHECK(groups_includes_group(&g, &grp, NULL, stub_now));

  groups_deinit(&g);
}

static void test_pending_exclude_records_use_effective_group_timer(void) {
  const struct {
    enum groups_update update;
    const char* group;
    const char* source;
  } cases[] = {
      {UPDATE_BLOCK, "::ffff:239.1.2.8", "::ffff:192.0.2.8"},
      {UPDATE_TO_EX, "ff05::c8", "2001:db8::c8"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    setup();
    struct in6_addr grp = addr(cases[i].group);
    struct in6_addr s1 = addr(cases[i].source);

    groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
    groups_update_state(&g, &grp, NULL, 0, UPDATE_TO_IN);
    stub_advance(0);
    CHECK(query_calls == 1);

    const struct group* group = groups_get(&g, &grp);
    omgp_time_t filter_cap = group ? group->expire_cap : 0;
    CHECK(filter_cap > stub_now);

    stub_now += 3 * OMGP_TIME_PER_SECOND;
    query_calls = 0;
    groups_update_state(&g, &grp, &s1, 1, cases[i].update);
    CHECK(groups_includes_group(&g, &grp, &s1, stub_now));

    group = groups_get(&g, &grp);
    CHECK(group != NULL && group->source_count == 1);
    if (group) {
      const struct group_source* source;
      group_for_each_source (source, group) {
        CHECK(source->include_until == stub_now + 2 * OMGP_TIME_PER_SECOND);
        CHECK(source->expire_cap == filter_cap);
        CHECK(source->retransmit == 2);
      }
    }

    stub_advance(0);
    CHECK(query_calls == 2);
    CHECK(query_source_count == 1);

    groups_deinit(&g);
  }
}

static void test_source_cap_preserves_other_query_schedule(void) {
  setup();
  struct in6_addr grp = addr("ff05::cb");
  struct in6_addr srcs[2] = {addr("2001:db8::cb"), addr("2001:db8::cc")};

  groups_update_state(&g, &grp, NULL, 0, UPDATE_IS_EXCLUDE);
  groups_update_state(&g, &grp, &srcs[0], 1, UPDATE_BLOCK);
  stub_advance(0);
  CHECK(query_calls == 1);

  const struct group* group = groups_get(&g, &grp);
  omgp_time_t first_cap = 0;
  if (group) {
    const struct group_source* source;
    group_for_each_source (source, group) {
      first_cap = source->expire_cap;
    }
  }
  CHECK(first_cap > stub_now);

  query_result = GROUPS_QUERY_FAILED;
  stub_now += 100 * OMGP_TIME_PER_SECOND;
  groups_update_state(&g, &grp, &srcs[0], 1, UPDATE_TO_EX);
  groups_update_state(&g, &grp, &srcs[0], 1, UPDATE_TO_EX);
  groups_update_state(&g, &grp, &srcs[1], 1, UPDATE_BLOCK);
  stub_advance(0);
  CHECK(query_source_count == 2);

  query_calls = 0;
  stub_now = first_cap;
  stub_advance(0);
  CHECK(query_calls == 1);
  CHECK(query_source_count == 1);

  group = groups_get(&g, &grp);
  CHECK(group != NULL &&
        group->next_source_transmit == stub_now + OMGP_TIME_PER_SECOND);
  int expired = 0;
  int pending = 0;
  if (group) {
    const struct group_source* source;
    group_for_each_source (source, group) {
      expired += source->retransmit == 0;
      pending += source->retransmit > 0;
    }
  }
  CHECK(expired == 1);
  CHECK(pending == 1);

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
  test_source_overflow_falls_back_to_asm();
  test_source_overflow_mid_update_falls_back_to_asm();
  test_overdue_timer_not_postponed();
  test_repeated_block_sends_immediate_query_keeps_counter();
  test_repeated_to_in_restarts_group_query_sequence();
  test_group_limit_enforced();
  test_other_querier_timer_update();
  test_group_query_attempt_kept_after_failure();
  test_failed_group_queries_stop_at_natural_expiry();
  test_source_query_attempt_kept_after_failure();
  test_failed_source_queries_stop_at_natural_expiry();
  test_skipped_group_query_cancels_schedule();
  test_skipped_source_query_cancels_schedule();
  test_overdue_group_membership_stays_active();
  test_overdue_source_membership_stays_active();
  test_failed_suppressed_group_query_keeps_deadline();
  test_failed_suppressed_source_query_keeps_deadline();
  test_received_query_deadline_overrides_group_protection();
  test_received_query_deadline_overrides_source_protection();
  test_pending_exclude_records_use_effective_group_timer();
  test_source_cap_preserves_other_query_schedule();
  return test_result();
}
