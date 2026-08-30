#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <linux/mroute.h>
#include <linux/mroute6.h>

#include "src/mrib.h"

#include "ev_stub.h"
#include "test.h"

#define BASE_FD 500
#define MAX_MFC 16
#define MAX_MSGS 8

struct mfc_entry {
  bool used;
  struct in6_addr group;
  struct in6_addr source;
  uint16_t parent;
  uint32_t oifs;
};

struct stub_msg {
  int fd;
  size_t len;
  uint8_t data[128];
};

static struct mfc_entry mfc_table[MAX_MFC];
static int mfc_ops;
static int add_mfc_fail_count;
static int add_mfc_fail_errno;
static int mrt_assert_val;
static int mrt6_assert_val;
static int mrt_pim_val;
static int mrt6_pim_val;
static struct stub_msg msgq[MAX_MSGS];
static size_t msgq_len;
static size_t msgq_pos;
static int next_fd = BASE_FD;
static int socket_calls;
static int socket_fail_call;
static int open_sockets;
static int fail_optname;
static int fail_level;
static int del_vif_calls;

static struct mrib_user uplink;
static struct mrib_user uplink2;
static struct mrib_user downlink;
static bool membership_active;

int __wrap_socket(int domain, int type, int protocol);
int __wrap_setsockopt(int fd,
                      int level,
                      int optname,
                      const void* optval,
                      socklen_t optlen);
int __wrap_ioctl(int fd, unsigned long request, void* arg);
int __wrap_close(int fd);
ssize_t __wrap_recvmsg(int fd, struct msghdr* hdr, int flags);

static struct in6_addr addr6(const char* s) {
  struct in6_addr a;
  CHECK(inet_pton(AF_INET6, s, &a) == 1);
  return a;
}

static struct in6_addr map4(struct in_addr a) {
  struct in6_addr r = IN6ADDR_ANY_INIT;
  r.s6_addr32[2] = htobe32(0xffff);
  r.s6_addr32[3] = a.s_addr;
  return r;
}

static struct mfc_entry* mfc_find(const struct in6_addr* group,
                                  const struct in6_addr* source) {
  for (size_t i = 0; i < MAX_MFC; ++i) {
    if (mfc_table[i].used && IN6_ARE_ADDR_EQUAL(&mfc_table[i].group, group) &&
        IN6_ARE_ADDR_EQUAL(&mfc_table[i].source, source)) {
      return &mfc_table[i];
    }
  }
  return NULL;
}

static void mfc_upsert(const struct in6_addr* group,
                       const struct in6_addr* source,
                       uint16_t parent,
                       uint32_t oifs) {
  struct mfc_entry* e = mfc_find(group, source);
  if (!e) {
    for (size_t i = 0; i < MAX_MFC && !e; ++i) {
      if (!mfc_table[i].used) {
        e = &mfc_table[i];
      }
    }
    CHECK(e != NULL);
    if (!e) {
      return;
    }
    e->used = true;
    e->group = *group;
    e->source = *source;
  }
  e->parent = parent;
  e->oifs = oifs;
}

static void mfc_del(const struct in6_addr* group,
                    const struct in6_addr* source) {
  struct mfc_entry* e = mfc_find(group, source);
  if (e) {
    e->used = false;
  }
}

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

int __wrap_ioctl(int fd, unsigned long request, void* arg) {
  (void)fd;
  (void)request;
  (void)arg;
  return 0;
}

int __wrap_close(int fd) {
  (void)fd;
  --open_sockets;
  return 0;
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
  if (level == IPPROTO_IP && optname == MRT_ASSERT && optlen == sizeof(int)) {
    memcpy(&mrt_assert_val, optval, sizeof(mrt_assert_val));
  } else if (level == IPPROTO_IPV6 && optname == MRT6_ASSERT &&
             optlen == sizeof(int)) {
    memcpy(&mrt6_assert_val, optval, sizeof(mrt6_assert_val));
  } else if (level == IPPROTO_IP && optname == MRT_PIM &&
             optlen == sizeof(int)) {
    memcpy(&mrt_pim_val, optval, sizeof(mrt_pim_val));
  } else if (level == IPPROTO_IPV6 && optname == MRT6_PIM &&
             optlen == sizeof(int)) {
    memcpy(&mrt6_pim_val, optval, sizeof(mrt6_pim_val));
  } else if (level == IPPROTO_IP &&
             (optname == MRT_ADD_MFC || optname == MRT_DEL_MFC)) {
    CHECK(optlen == sizeof(struct mfcctl));
    const struct mfcctl* ctl = optval;
    struct in6_addr group = map4(ctl->mfcc_mcastgrp);
    struct in6_addr source = map4(ctl->mfcc_origin);
    if (optname == MRT_ADD_MFC && add_mfc_fail_count != 0) {
      --add_mfc_fail_count;
      errno = add_mfc_fail_errno;
      return -1;
    }
    ++mfc_ops;
    if (optname == MRT_DEL_MFC) {
      mfc_del(&group, &source);
    } else {
      uint32_t oifs = 0;
      for (size_t i = 0; i < MAXVIFS; ++i) {
        if (ctl->mfcc_ttls[i]) {
          oifs |= mrib_filter_bit(i);
        }
      }
      mfc_upsert(&group, &source, ctl->mfcc_parent, oifs);
    }
  } else if (level == IPPROTO_IPV6 &&
             (optname == MRT6_ADD_MFC || optname == MRT6_DEL_MFC)) {
    CHECK(optlen == sizeof(struct mf6cctl));
    const struct mf6cctl* ctl = optval;
    if (optname == MRT6_ADD_MFC && add_mfc_fail_count != 0) {
      --add_mfc_fail_count;
      errno = add_mfc_fail_errno;
      return -1;
    }
    ++mfc_ops;
    if (optname == MRT6_DEL_MFC) {
      mfc_del(&ctl->mf6cc_mcastgrp.sin6_addr, &ctl->mf6cc_origin.sin6_addr);
    } else {
      uint32_t oifs = 0;
      for (size_t i = 0; i < MAXMIFS; ++i) {
        if (ctl->mf6cc_ifset.ifs_bits[i / NIFBITS] &
            (UINT32_C(1) << (i % NIFBITS))) {
          oifs |= mrib_filter_bit(i);
        }
      }
      mfc_upsert(&ctl->mf6cc_mcastgrp.sin6_addr, &ctl->mf6cc_origin.sin6_addr,
                 ctl->mf6cc_parent, oifs);
    }
  }
  return 0;
}

ssize_t __wrap_recvmsg(int fd, struct msghdr* hdr, int flags) {
  (void)flags;
  if (msgq_pos < msgq_len && msgq[msgq_pos].fd == fd) {
    struct stub_msg* m = &msgq[msgq_pos++];
    CHECK(hdr->msg_iov[0].iov_len >= m->len);
    memcpy(hdr->msg_iov[0].iov_base, m->data, m->len);
    hdr->msg_controllen = 0;
    return (ssize_t)m->len;
  }
  errno = EAGAIN;
  return -1;
}

static void inject(struct ev_fd* efd, const void* data, size_t len) {
  CHECK(len <= sizeof(msgq[0].data));
  msgq_pos = 0;
  msgq_len = 1;
  msgq[0].fd = efd->fd;
  msgq[0].len = len;
  memcpy(msgq[0].data, data, len);
  efd->cb(efd, EV_READ);
  CHECK(msgq_pos == msgq_len);
}

static void inject_mrt(unsigned char msgtype,
                       unsigned char vif,
                       const char* source,
                       const char* group) {
  struct igmpmsg msg = {0};
  msg.im_msgtype = msgtype;
  msg.im_mbz = 0;
  msg.im_vif = vif;
  CHECK(inet_pton(AF_INET, source, &msg.im_src) == 1);
  CHECK(inet_pton(AF_INET, group, &msg.im_dst) == 1);
  inject(stub_fds[0], &msg, sizeof(msg));
}

static void inject_mrt6(unsigned char msgtype,
                        uint16_t mif,
                        const char* source,
                        const char* group) {
  struct mrt6msg msg = {0};
  msg.im6_mbz = 0;
  msg.im6_msgtype = msgtype;
  msg.im6_mif = mif;
  CHECK(inet_pton(AF_INET6, source, &msg.im6_src) == 1);
  CHECK(inet_pton(AF_INET6, group, &msg.im6_dst) == 1);
  inject(stub_fds[1], &msg, sizeof(msg));
}

static void uplink_newsource(struct mrib_user* user,
                             const struct in6_addr* group,
                             const struct in6_addr* source,
                             mrib_filter* filter) {
  (void)user;
  (void)group;
  (void)source;
  if (membership_active && downlink.iface) {
    CHECK(mrib_filter_add(filter, &downlink) == 0);
  }
}

static void setup(void) {
  membership_active = true;
  CHECK(mrib_attach_user(&uplink, 101, uplink_newsource) == 0);
  CHECK(mrib_attach_user(&downlink, 201, NULL) == 0);
  CHECK(stub_fd_count == 2);
  mfc_ops = 0;
  add_mfc_fail_count = 0;
  add_mfc_fail_errno = ENOBUFS;
}

static void teardown(void) {
  if (uplink.iface) {
    mrib_detach_user(&uplink);
  }
  if (uplink2.iface) {
    mrib_detach_user(&uplink2);
  }
  if (downlink.iface) {
    mrib_detach_user(&downlink);
  }
  for (size_t i = 0; i < MAX_MFC; ++i) {
    CHECK(!mfc_table[i].used);
  }
  msgq_pos = 0;
  msgq_len = 0;
}

static void test_wrongvif_from_uplink_reparents(void) {
  setup();
  CHECK(mrt_assert_val == 1);
  CHECK(mrt6_assert_val == 1);
  CHECK(mrt_pim_val == 1);
  CHECK(mrt6_pim_val == 1);

  struct in6_addr group = addr6("::ffff:239.1.1.1");
  struct in6_addr source = addr6("::ffff:10.0.1.2");

  inject_mrt(IGMPMSG_NOCACHE, 1, "10.0.1.2", "239.1.1.1");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 1);
    CHECK(e->oifs == 0);
  }

  inject_mrt(IGMPMSG_WRONGVIF, 0, "10.0.1.2", "239.1.1.1");
  e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
    CHECK(e->oifs == mrib_filter_bit(1));
  }

  teardown();
}

static void test_wrongvif_from_downlink_keeps_parent(void) {
  setup();
  struct in6_addr group = addr6("::ffff:239.1.1.2");
  struct in6_addr source = addr6("::ffff:10.0.1.2");

  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.1.2", "239.1.1.2");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
    CHECK(e->oifs == mrib_filter_bit(1));
  }

  int ops = mfc_ops;
  inject_mrt(IGMPMSG_WRONGVIF, 1, "10.0.1.2", "239.1.1.2");
  CHECK(mfc_ops == ops);
  e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
  }

  teardown();
}

static void test_wrongvif_reparent_failure_keeps_owner(void) {
  setup();
  struct in6_addr group = addr6("::ffff:239.4.4.4");
  struct in6_addr source = addr6("::ffff:10.0.4.2");

  inject_mrt(IGMPMSG_NOCACHE, 1, "10.0.4.2", "239.4.4.4");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 1);
  }

  add_mfc_fail_count = 1;
  inject_mrt(IGMPMSG_WRONGVIF, 0, "10.0.4.2", "239.4.4.4");
  e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 1);
  }

  inject_mrt(IGMPMSG_WRONGVIF, 0, "10.0.4.2", "239.4.4.4");
  e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
    CHECK(e->oifs == mrib_filter_bit(1));
  }

  teardown();
}

static void test_nocache_program_failure_leaves_no_state(void) {
  setup();
  struct in6_addr group = addr6("::ffff:239.5.5.5");
  struct in6_addr source = addr6("::ffff:10.0.5.2");

  add_mfc_fail_count = 1;
  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.5.2", "239.5.5.5");
  CHECK(mfc_find(&group, &source) == NULL);
  int ops = mfc_ops;
  stub_advance((MRIB_DEFAULT_LIFETIME + 1) * OMGP_TIME_PER_SECOND);
  CHECK(mfc_ops == ops);

  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.5.2", "239.5.5.5");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
  }

  teardown();
}

static void test_repeated_nocache_keeps_single_route(void) {
  setup();
  struct in6_addr group = addr6("::ffff:239.6.6.6");
  struct in6_addr source = addr6("::ffff:10.0.6.2");

  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.6.2", "239.6.6.6");
  int ops = mfc_ops;
  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.6.2", "239.6.6.6");
  CHECK(mfc_ops == ops + 1);

  stub_advance((MRIB_DEFAULT_LIFETIME + 1) * OMGP_TIME_PER_SECOND);
  CHECK(mfc_ops == ops + 2);
  CHECK(mfc_find(&group, &source) == NULL);

  teardown();
}

static void test_wrongvif_for_untracked_route_is_ignored(void) {
  setup();
  struct in6_addr group = addr6("::ffff:239.9.9.9");
  struct in6_addr source = addr6("::ffff:10.0.1.9");

  int ops = mfc_ops;
  inject_mrt(IGMPMSG_WRONGVIF, 0, "10.0.1.9", "239.9.9.9");
  CHECK(mfc_ops == ops);
  CHECK(mfc_find(&group, &source) == NULL);

  teardown();
}

static void test_wrongvif_between_uplinks_keeps_parent(void) {
  setup();
  CHECK(mrib_attach_user(&uplink2, 102, uplink_newsource) == 0);

  struct in6_addr group = addr6("::ffff:239.1.1.3");
  struct in6_addr source = addr6("::ffff:10.0.1.2");

  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.1.2", "239.1.1.3");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
  }

  int ops = mfc_ops;
  inject_mrt(IGMPMSG_WRONGVIF, 2, "10.0.1.2", "239.1.1.3");
  CHECK(mfc_ops == ops);
  e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
  }

  teardown();
}

static void test_reparented_route_expires_from_new_parent(void) {
  setup();
  struct in6_addr group = addr6("::ffff:239.1.1.4");
  struct in6_addr source = addr6("::ffff:10.0.1.2");

  inject_mrt(IGMPMSG_NOCACHE, 1, "10.0.1.2", "239.1.1.4");
  inject_mrt(IGMPMSG_WRONGVIF, 0, "10.0.1.2", "239.1.1.4");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
  }

  stub_advance((MRIB_DEFAULT_LIFETIME + 1) * OMGP_TIME_PER_SECOND);
  CHECK(mfc_find(&group, &source) == NULL);

  teardown();
}

static void test_wrongmif_from_uplink_reparents_ipv6(void) {
  setup();
  struct in6_addr group = addr6("ff35::1");
  struct in6_addr source = addr6("fd00::2");

  inject_mrt6(MRT6MSG_NOCACHE, 1, "fd00::2", "ff35::1");
  struct mfc_entry* e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 1);
    CHECK(e->oifs == 0);
  }

  inject_mrt6(MRT6MSG_WRONGMIF, 0, "fd00::2", "ff35::1");
  e = mfc_find(&group, &source);
  CHECK(e != NULL);
  if (e) {
    CHECK(e->parent == 0);
    CHECK(e->oifs == mrib_filter_bit(1));
  }

  teardown();
}

static void test_refresh_reconciles_output_interfaces(void) {
  setup();
  membership_active = false;
  inject_mrt(IGMPMSG_NOCACHE, 0, "10.0.0.2", "239.1.2.3");

  struct in_addr group4;
  struct in_addr source4;
  CHECK(inet_pton(AF_INET, "239.1.2.3", &group4) == 1);
  CHECK(inet_pton(AF_INET, "10.0.0.2", &source4) == 1);
  struct in6_addr group = map4(group4);
  struct in6_addr source = map4(source4);
  struct mfc_entry* entry = mfc_find(&group, &source);
  CHECK(entry != NULL && entry->oifs == 0);

  membership_active = true;
  mrib_refresh(&uplink, &group);
  entry = mfc_find(&group, &source);
  CHECK(entry != NULL && entry->oifs == mrib_filter_bit(1));

  teardown();
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
  setlogmask(LOG_UPTO(LOG_CRIT));
  test_startup_failure_closes_partial_sockets();
  test_interface_setup_rolls_back_ipv4();
  test_wrongvif_from_uplink_reparents();
  test_wrongvif_from_downlink_keeps_parent();
  test_wrongvif_reparent_failure_keeps_owner();
  test_nocache_program_failure_leaves_no_state();
  test_repeated_nocache_keeps_single_route();
  test_wrongvif_for_untracked_route_is_ignored();
  test_wrongvif_between_uplinks_keeps_parent();
  test_reparented_route_expires_from_new_parent();
  test_wrongmif_from_uplink_reparents_ipv6();
  test_refresh_reconciles_output_interfaces();
  return test_result();
}
