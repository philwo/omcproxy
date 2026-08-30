#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "src/client.h"

#include "ev_stub.h"
#include "test.h"

#define BASE_FD 1000
#define MAX_FDS 64

static int sock_capacity;
static int fd_joins[MAX_FDS];
static int socket_calls;
static int socket_fail_call;
static int close_calls;
static int last_closed_fd;
static int join_calls;
static int leave_calls;
static int msfilter_calls;
static int msfilter_fail_count;
static int msfilter_fail_errno;
static int next_fd = BASE_FD;

int __wrap_socket(int domain, int type, int protocol);
int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void* optval,
                      socklen_t optlen);
int __wrap_close(int fd);

int __wrap_socket(int domain, int type, int protocol) {
  (void)domain;
  (void)type;
  (void)protocol;
  ++socket_calls;
  if (socket_calls == socket_fail_call) {
    errno = EMFILE;
    return -1;
  }
  return next_fd++;
}

int __wrap_close(int fd) {
  ++close_calls;
  last_closed_fd = fd;
  return 0;
}

int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void* optval,
                      socklen_t optlen) {
  (void)level;
  (void)optval;
  (void)optlen;
  int idx = fd - BASE_FD;
  if (idx < 0 || idx >= MAX_FDS) {
    CHECK(false);
    errno = EBADF;
    return -1;
  }

  if (optname == MCAST_JOIN_GROUP) {
    ++join_calls;
    if (fd_joins[idx] >= sock_capacity) {
      errno = ENOBUFS;
      return -1;
    }
    ++fd_joins[idx];
    return 0;
  }
  if (optname == MCAST_LEAVE_GROUP) {
    ++leave_calls;
    if (fd_joins[idx] > 0) {
      --fd_joins[idx];
    }
    return 0;
  }
  if (optname == MCAST_MSFILTER) {
    ++msfilter_calls;
    if (msfilter_fail_count != 0) {
      --msfilter_fail_count;
      errno = msfilter_fail_errno;
      return -1;
    }
    return 0;
  }
  return 0;
}

static struct client c;

static struct in6_addr addr6(const char* s) {
  struct in6_addr a;
  CHECK(inet_pton(AF_INET6, s, &a) == 1);
  return a;
}

static int total_joins(void) {
  int total = 0;
  for (int i = 0; i < MAX_FDS; ++i) {
    total += fd_joins[i];
  }
  return total;
}

static void setup(void) {
  memset(fd_joins, 0, sizeof(fd_joins));
  sock_capacity = 1000;
  socket_calls = 0;
  socket_fail_call = 0;
  close_calls = 0;
  last_closed_fd = -1;
  join_calls = 0;
  leave_calls = 0;
  msfilter_calls = 0;
  msfilter_fail_count = 0;
  msfilter_fail_errno = EINVAL;
  CHECK(client_init(&c, 7) == 0);
}

static void test_second_socket_failure_closes_first_socket(void) {
  memset(fd_joins, 0, sizeof(fd_joins));
  socket_calls = 0;
  socket_fail_call = 2;
  close_calls = 0;
  last_closed_fd = -1;
  int first_fd = next_fd;
  struct client client;

  CHECK(client_init(&client, 7) == -EMFILE);
  CHECK(close_calls == 1);
  CHECK(last_closed_fd == first_fd);

  socket_fail_call = 0;
}

static void teardown(void) {
  client_deinit(&c);
  stub_advance(120 * OMGP_TIME_PER_SECOND);
}

static void test_idempotent_set_makes_no_syscalls(void) {
  setup();
  struct in6_addr grp = addr6("ff0e::1");

  client_set(&c, &grp, false, NULL, 0);
  CHECK(total_joins() == 1);
  int joins = join_calls;
  int leaves = leave_calls;
  int filters = msfilter_calls;

  client_set(&c, &grp, false, NULL, 0);
  CHECK(join_calls == joins);
  CHECK(leave_calls == leaves);
  CHECK(msfilter_calls == filters);

  teardown();
}

static void test_filter_change_keeps_membership(void) {
  setup();
  struct in6_addr grp = addr6("ff3e::1");
  struct in6_addr s1 = addr6("2001:db8::1");
  struct in6_addr s2 = addr6("2001:db8::2");

  client_set(&c, &grp, true, &s1, 1);
  CHECK(total_joins() == 1);
  int joins = join_calls;
  int leaves = leave_calls;

  client_set(&c, &grp, true, &s2, 1);
  CHECK(join_calls == joins);
  CHECK(leave_calls == leaves);
  CHECK(total_joins() == 1);

  teardown();
}

static void test_leave_on_empty_include(void) {
  setup();
  struct in6_addr grp = addr6("ff0e::2");

  client_set(&c, &grp, false, NULL, 0);
  CHECK(total_joins() == 1);
  client_set(&c, &grp, true, NULL, 0);
  CHECK(total_joins() == 0);
  CHECK(leave_calls == 1);

  teardown();
}

static void test_socket_pool_grows_on_enobufs(void) {
  setup();
  sock_capacity = 2;
  struct in6_addr g1 = addr6("ff0e::11");
  struct in6_addr g2 = addr6("ff0e::12");
  struct in6_addr g3 = addr6("ff0e::13");

  int sockets = socket_calls;
  client_set(&c, &g1, false, NULL, 0);
  client_set(&c, &g2, false, NULL, 0);
  client_set(&c, &g3, false, NULL, 0);
  CHECK(total_joins() == 3);
  CHECK(socket_calls == sockets + 1);

  client_set(&c, &g1, true, NULL, 0);
  client_set(&c, &g2, true, NULL, 0);
  client_set(&c, &g3, true, NULL, 0);
  CHECK(total_joins() == 0);

  teardown();
}

static void test_msfilter_failure_keeps_join_and_retries(void) {
  setup();
  struct in6_addr grp = addr6("ff3e::99");
  struct in6_addr s1 = addr6("2001:db8::9");

  msfilter_fail_count = 1;
  msfilter_fail_errno = ENOBUFS;
  client_set(&c, &grp, true, &s1, 1);
  CHECK(total_joins() == 1);
  CHECK(leave_calls == 0);

  int filters = msfilter_calls;
  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(msfilter_calls == filters + 1);
  CHECK(total_joins() == 1);

  stub_advance(120 * OMGP_TIME_PER_SECOND);
  CHECK(msfilter_calls == filters + 1);

  teardown();
}

static void test_join_failure_retries(void) {
  setup();
  sock_capacity = 0;
  struct in6_addr grp = addr6("ff0e::42");

  client_set(&c, &grp, false, NULL, 0);
  CHECK(total_joins() == 0);

  sock_capacity = 1000;
  stub_advance(2 * OMGP_TIME_PER_SECOND);
  CHECK(total_joins() == 1);

  teardown();
}

int main(void) {
  setlogmask(LOG_UPTO(LOG_CRIT));
  test_idempotent_set_makes_no_syscalls();
  test_filter_change_keeps_membership();
  test_leave_on_empty_include();
  test_socket_pool_grows_on_enobufs();
  test_msfilter_failure_keeps_join_and_retries();
  test_join_failure_retries();
  test_second_socket_failure_closes_first_socket();
  return test_result();
}
