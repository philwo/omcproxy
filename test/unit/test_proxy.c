#include <errno.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "src/client.h"
#include "src/groups.h"
#include "src/mrib.h"
#include "src/proxy.h"
#include "src/querier.h"

#include "test.h"

static int detached_ifindices[16];
static size_t detached_count;
static struct querier_user_iface* last_attached_user;
static struct mrib_user* uplink_user;
static struct mrib_user* refreshed_user;
static struct in6_addr refreshed_group;
static int refresh_count;

omgp_time_t omgp_time(void) {
  return 0;
}

bool groups_includes_group(struct groups* groups,
                           const struct in6_addr* group,
                           const struct in6_addr* source,
                           omgp_time_t now) {
  (void)groups;
  (void)group;
  (void)source;
  (void)now;
  return false;
}

int client_init(struct client* client, int ifindex) {
  client->ifindex = ifindex;
  return 0;
}

void client_deinit(struct client* client) {
  client->ifindex = 0;
}

int client_set(struct client* client,
               const struct in6_addr* group,
               bool include,
               const struct in6_addr sources[],
               size_t count) {
  (void)client;
  (void)group;
  (void)include;
  (void)sources;
  (void)count;
  return 0;
}

int mrib_attach_user(struct mrib_user* user, int ifindex, mrib_cb* callback) {
  (void)ifindex;
  user->cb_newsource = callback;
  if (callback) {
    uplink_user = user;
  }
  return 0;
}

void mrib_detach_user(struct mrib_user* user) {
  user->iface = NULL;
}

void mrib_refresh(struct mrib_user* user, const struct in6_addr* group) {
  refreshed_user = user;
  refreshed_group = *group;
  ++refresh_count;
}

int mrib_filter_add(mrib_filter* filter, struct mrib_user* user) {
  (void)filter;
  (void)user;
  return 0;
}

int querier_init(struct querier* querier) {
  INIT_LIST_HEAD(&querier->ifaces);
  return 0;
}

void querier_deinit(struct querier* querier) {
  CHECK(list_empty(&querier->ifaces));
}

int querier_attach(struct querier_user_iface* user,
                   struct querier* querier,
                   int ifindex,
                   querier_iface_cb* callback) {
  struct querier_iface* iface = calloc(1, sizeof(*iface));
  if (!iface) {
    return -ENOMEM;
  }
  iface->ifindex = ifindex;
  user->iface = iface;
  user->user.groups = &iface->groups;
  user->user.querier = querier;
  user->user_cb = callback;
  list_add_tail(&user->user.head, &querier->ifaces);
  last_attached_user = user;
  return 0;
}

void querier_detach(struct querier_user_iface* user) {
  CHECK(detached_count <
        sizeof(detached_ifindices) / sizeof(detached_ifindices[0]));
  if (detached_count >=
      sizeof(detached_ifindices) / sizeof(detached_ifindices[0])) {
    return;
  }
  detached_ifindices[detached_count++] = user->iface->ifindex;
  list_del(&user->user.head);
  free(user->iface);
  user->iface = NULL;
}

static void test_stale_downlink_scan(void) {
  detached_count = 0;
  int initial[] = {20, 30};
  CHECK(proxy_set(10, initial, 2, PROXY_GLOBAL) == 0);
  CHECK(detached_count == 0);

  int updated[] = {30};
  CHECK(proxy_set(10, updated, 1, PROXY_GLOBAL) == 0);
  CHECK(detached_count == 1);
  CHECK(detached_ifindices[0] == 20);

  proxy_flush();
}

static struct in6_addr addr6(const char* text) {
  struct in6_addr address;
  CHECK(inet_pton(AF_INET6, text, &address) == 1);
  return address;
}

static void test_membership_callback_refreshes_matching_group(void) {
  refresh_count = 0;
  refreshed_user = NULL;
  uplink_user = NULL;
  int downlink = 20;
  CHECK(proxy_set(10, &downlink, 1, PROXY_GLOBAL) == 0);
  CHECK(last_attached_user != NULL);

  struct in6_addr group = addr6("ff3e::1234");
  last_attached_user->user_cb(last_attached_user, &group, false, NULL, 0);
  CHECK(refresh_count == 1);
  CHECK(refreshed_user == uplink_user);
  CHECK(IN6_ARE_ADDR_EQUAL(&refreshed_group, &group));

  proxy_flush();
}

int main(void) {
  test_stale_downlink_scan();
  test_membership_callback_refreshes_matching_group();
  return test_result();
}
