#include <errno.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "src/client.h"

#include "test.h"

static socklen_t msfilter_optlen;
static uint32_t msfilter_numsrc;
static int next_fd = 1000;
static int socket_calls;
static int socket_fail_call;
static int close_calls;
static int last_closed_fd;

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

int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void* optval,
                      socklen_t optlen) {
  (void)fd;
  (void)level;
  if (optname == MCAST_MSFILTER) {
    msfilter_optlen = optlen;
    msfilter_numsrc = ((const struct group_filter*)optval)->gf_numsrc;
  }
  return 0;
}

int __wrap_close(int fd) {
  ++close_calls;
  last_closed_fd = fd;
  return 0;
}

static void reset_calls(void) {
  msfilter_optlen = 0;
  msfilter_numsrc = 0;
  socket_calls = 0;
  socket_fail_call = 0;
  close_calls = 0;
  last_closed_fd = -1;
}

static struct in6_addr addr6(const char* text) {
  struct in6_addr addr;
  CHECK(inet_pton(AF_INET6, text, &addr) == 1);
  return addr;
}

static void test_source_storage_is_bounded(void) {
  reset_calls();
  struct client client;
  CHECK(client_init(&client, 7) == 0);
  struct in6_addr group = addr6("ff3e::1");
  struct in6_addr sources[CLIENT_MAX_SOURCES + 3] = {};

  CHECK(client_set(&client, &group, true, sources, CLIENT_MAX_SOURCES + 3) ==
        0);
  CHECK(msfilter_numsrc == CLIENT_MAX_SOURCES);
  CHECK(msfilter_optlen ==
        sizeof(struct group_filter) +
            CLIENT_MAX_SOURCES * sizeof(struct sockaddr_storage));
  client_deinit(&client);
}

static void test_second_socket_failure_closes_first_socket(void) {
  reset_calls();
  socket_fail_call = 2;
  int first_fd = next_fd;
  struct client client;

  CHECK(client_init(&client, 7) == -EMFILE);
  CHECK(close_calls == 1);
  CHECK(last_closed_fd == first_fd);
}

int main(void) {
  test_source_storage_is_bounded();
  test_second_socket_failure_closes_first_socket();
  return test_result();
}
