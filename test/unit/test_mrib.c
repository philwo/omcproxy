#include <errno.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "src/mrib.h"

#include "ev_stub.h"
#include "test.h"

static struct mrib_user uplink;
static struct mrib_user downlink;
static bool membership_active;
static uint32_t programmed_oifs;
static struct igmpmsg pending_msg;
static bool message_pending;
static int next_fd = 500;
static int socket_calls;
static int socket_fail_call;
static int open_sockets;
static int fail_optname;
static int fail_level;
static int del_vif_calls;

int __wrap_socket(int domain, int type, int protocol);
int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void* optval,
                      socklen_t optlen);
int __wrap_close(int fd);
ssize_t __wrap_recvmsg(int fd, struct msghdr* message, int flags);

int __wrap_socket(int domain, int type, int protocol) {
  (void)domain;
  (void)type;
  (void)protocol;
  ++socket_calls;
  if (socket_calls == socket_fail_call) {
    errno = EMFILE;
    return -1;
  }
  ++open_sockets;
  return next_fd++;
}

int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void* optval,
                      socklen_t optlen) {
  (void)fd;
  if (level == fail_level && optname == fail_optname) {
    errno = EIO;
    return -1;
  }
  if (level == IPPROTO_IP && optname == MRT_DEL_VIF) {
    ++del_vif_calls;
  }
  if (level == IPPROTO_IP && optname == MRT_ADD_MFC) {
    CHECK(optlen == sizeof(struct mfcctl));
    const struct mfcctl* control = optval;
    programmed_oifs = 0;
    for (size_t i = 0; i < MAXVIFS; ++i) {
      if (control->mfcc_ttls[i]) {
        programmed_oifs |= mrib_filter_bit(i);
      }
    }
  }
  return 0;
}

int __wrap_close(int fd) {
  (void)fd;
  --open_sockets;
  return 0;
}

ssize_t __wrap_recvmsg(int fd, struct msghdr* message, int flags) {
  (void)fd;
  (void)flags;
  if (!message_pending) {
    errno = EAGAIN;
    return -1;
  }
  CHECK(message->msg_iov[0].iov_len >= sizeof(pending_msg));
  memcpy(message->msg_iov[0].iov_base, &pending_msg, sizeof(pending_msg));
  message->msg_controllen = 0;
  message_pending = false;
  return sizeof(pending_msg);
}

static void update_filter(struct mrib_user* user,
                          const struct in6_addr* group,
                          const struct in6_addr* source,
                          mrib_filter* filter) {
  (void)user;
  (void)group;
  (void)source;
  if (membership_active) {
    CHECK(mrib_filter_add(filter, &downlink) == 0);
  }
}

static void test_refresh_reconciles_output_interfaces(void) {
  CHECK(mrib_attach_user(&uplink, 101, update_filter) == 0);
  CHECK(mrib_attach_user(&downlink, 201, NULL) == 0);
  CHECK(stub_fd_count == 2);

  pending_msg = (struct igmpmsg){.im_msgtype = IGMPMSG_NOCACHE, .im_vif = 0};
  CHECK(inet_pton(AF_INET, "10.0.0.2", &pending_msg.im_src) == 1);
  CHECK(inet_pton(AF_INET, "239.1.2.3", &pending_msg.im_dst) == 1);
  message_pending = true;
  stub_fds[0]->cb(stub_fds[0], EV_READ);
  CHECK(!message_pending);
  CHECK(programmed_oifs == 0);

  struct in6_addr group = IN6ADDR_ANY_INIT;
  group.s6_addr32[2] = htobe32(0xffff);
  group.s6_addr32[3] = pending_msg.im_dst.s_addr;
  membership_active = true;
  mrib_refresh(&uplink, &group);
  CHECK(programmed_oifs == mrib_filter_bit(1));

  mrib_detach_user(&downlink);
  mrib_detach_user(&uplink);
}

static void test_startup_failure_closes_partial_sockets(void) {
  struct mrib_user user = {0};
  socket_calls = 0;
  socket_fail_call = 2;

  CHECK(mrib_attach_user(&user, 100, NULL) == -EMFILE);
  CHECK(user.iface == NULL);
  CHECK(open_sockets == 0);
  CHECK(stub_fd_count == 0);

  socket_fail_call = 0;
}

static void test_interface_setup_rolls_back_ipv4(void) {
  struct mrib_user user = {0};
  fail_optname = MRT6_ADD_MIF;
  fail_level = IPPROTO_IPV6;
  del_vif_calls = 0;

  CHECK(mrib_attach_user(&user, 102, NULL) == -EIO);
  CHECK(user.iface == NULL);
  CHECK(del_vif_calls == 1);

  fail_optname = 0;
  fail_level = 0;
  CHECK(mrib_attach_user(&user, 102, NULL) == 0);
  mrib_detach_user(&user);
}

int main(void) {
  test_startup_failure_closes_partial_sockets();
  test_interface_setup_rolls_back_ipv4();
  test_refresh_reconciles_output_interfaces();
  return test_result();
}
