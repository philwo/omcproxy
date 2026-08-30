#include <string.h>

#include "mrib_stub.h"

struct in_addr stub_igmp_source;
struct in6_addr stub_mld_source;

uint8_t stub_sent[2048];
size_t stub_sent_len;
int stub_sent_family;
int stub_send_result;
int stub_send_count;

int mrib_attach_querier(struct mrib_querier* querier,
                        int ifindex,
                        mrib_igmp_cb* cb_igmp,
                        mrib_mld_cb* cb_mld) {
  (void)ifindex;
  querier->iface = NULL;
  querier->cb_igmp = cb_igmp;
  querier->cb_mld = cb_mld;
  return 0;
}

void mrib_detach_querier(struct mrib_querier* querier) {
  (void)querier;
}

int mrib_igmp_source(struct mrib_querier* q, struct in_addr* source) {
  (void)q;
  *source = stub_igmp_source;
  return 0;
}

int mrib_mld_source(struct mrib_querier* q, struct in6_addr* source) {
  (void)q;
  *source = stub_mld_source;
  return 0;
}

int mrib_send_igmp(struct mrib_querier* querier,
                   struct igmpv3_query* igmp,
                   size_t len,
                   const struct sockaddr_in* dest) {
  (void)querier;
  (void)dest;
  ++stub_send_count;
  if (len > sizeof(stub_sent)) {
    return -1;
  }
  memcpy(stub_sent, igmp, len);
  stub_sent_len = len;
  stub_sent_family = 4;
  return stub_send_result;
}

int mrib_send_mld(struct mrib_querier* querier,
                  struct mld_hdr* mld,
                  size_t len,
                  const struct sockaddr_in6* dest) {
  (void)querier;
  (void)dest;
  ++stub_send_count;
  if (len > sizeof(stub_sent)) {
    return -1;
  }
  memcpy(stub_sent, mld, len);
  stub_sent_len = len;
  stub_sent_family = 6;
  return stub_send_result;
}
