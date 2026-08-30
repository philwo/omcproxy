#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#include "src/querier.h"

#include "ev_stub.h"
#include "mrib_stub.h"

static struct querier_iface q;
static bool initialized;

static void noop_timer(struct ev_timer* t) {
  (void)t;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!initialized) {
    setlogmask(LOG_UPTO(LOG_EMERG));
    INIT_LIST_HEAD(&q.users);
    q.timeout.cb = noop_timer;
    q.ifindex = 7;
    groups_init(&q.groups);
    q.groups.source_limit = QUERIER_MAX_SOURCE;
    q.groups.group_limit = QUERIER_MAX_GROUPS;
    q.cfg = q.groups.cfg_v6;
    stub_igmp_source.s_addr = htobe32(0xc0a80101);
    inet_pton(AF_INET6, "fe80::1", &stub_mld_source);
    initialized = true;
  }

  if (size < 1) {
    return 0;
  }

  uint8_t control = data[0];
  const uint8_t* pkt = data + 1;
  size_t len = size - 1;

  _Alignas(16) uint8_t buf[9216];
  if (len > sizeof(buf)) {
    len = sizeof(buf);
  }
  memcpy(buf, pkt, len);

  if (control & 1) {
    if (len < sizeof(struct mld_hdr)) {
      return 0;
    }
    struct sockaddr_in6 from = {.sin6_family = AF_INET6};
    inet_pton(AF_INET6, "fe80::2", &from.sin6_addr);
    mld_handle(&q.mrib, (const struct mld_hdr*)buf, len, &from);
  } else {
    if (len < sizeof(struct igmphdr)) {
      return 0;
    }
    struct sockaddr_in from = {
        .sin_family = AF_INET,
        .sin_addr = {htobe32(0xc0a80102)},
    };
    igmp_handle(&q.mrib, (const struct igmphdr*)buf, len, &from);
  }

  stub_advance((omgp_time_t)(control >> 1) * 100);
  return 0;
}
