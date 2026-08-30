#include <string.h>

#include "src/config.h"

#include "test.h"

static void test_uplink_and_downlinks(void) {
  char spec[] = "eth1,eth2,eth3";
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) == 0);
  CHECK(strcmp(cfg.uplink, "eth1") == 0);
  CHECK(cfg.downlink_count == 2);
  CHECK(strcmp(cfg.downlinks[0], "eth2") == 0);
  CHECK(strcmp(cfg.downlinks[1], "eth3") == 0);
  CHECK(cfg.flags == 0);
}

static void test_scope_option(void) {
  char spec[] = "eth1,eth2,scope=organization";
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) == 0);
  CHECK(strcmp(cfg.uplink, "eth1") == 0);
  CHECK(cfg.downlink_count == 1);
  CHECK(cfg.flags == PROXY_ORGLOCAL);
}

static void test_scope_before_interfaces(void) {
  char spec[] = "scope=site,eth1,eth2";
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) == 0);
  CHECK(strcmp(cfg.uplink, "eth1") == 0);
  CHECK(cfg.flags == PROXY_SITELOCAL);
}

static void test_uplink_only(void) {
  char spec[] = "eth1";
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) == 0);
  CHECK(strcmp(cfg.uplink, "eth1") == 0);
  CHECK(cfg.downlink_count == 0);
}

static void test_invalid_scope(void) {
  char spec[] = "eth1,eth2,scope=bogus";
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) < 0);
}

static void test_missing_uplink(void) {
  char spec[] = "scope=site";
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) < 0);

  char empty[] = "";
  CHECK(config_parse_proxy(empty, &cfg) < 0);
}

static void test_too_many_downlinks(void) {
  char spec[512] = "up0";
  size_t offset = strlen(spec);
  for (int i = 0; i <= CONFIG_MAX_DOWNLINKS; ++i) {
    size_t remaining = sizeof(spec) - offset;
    int written = snprintf(&spec[offset], remaining, ",d%d", i);
    if (written <= 0 || (size_t)written >= remaining) {
      CHECK(false);
      return;
    }
    offset += (size_t)written;
  }
  struct proxy_config cfg;
  CHECK(config_parse_proxy(spec, &cfg) < 0);
}

int main(void) {
  test_uplink_and_downlinks();
  test_scope_option();
  test_scope_before_interfaces();
  test_uplink_only();
  test_invalid_scope();
  test_missing_uplink();
  test_too_many_downlinks();
  return test_result();
}
