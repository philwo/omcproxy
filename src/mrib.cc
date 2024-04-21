/*
 * Author: Steven Barth <steven at midlink.org>
 *
 * Copyright 2015 Deutsche Telekom AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <libubox/uloop.h>

#include "mrib.h"
#include "omcproxy.h"

struct MribRoute {
  struct ListHead head;
  struct in6_addr group;
  struct in6_addr source;
  omcp_time_t valid_until;
};

struct MribIface {
  int ifindex;
  std::vector<MribUser*> users;
  std::vector<MribRoute*> routes;
  struct ListHead queriers;
  struct UloopTimeout timer;
};

/* we can't use cpu_to_be32 outside a function */
static uint32_t ipv4_rtr_alert = 0x00000494;

static struct {
  struct ip6_hbh hdr;
  struct ip6_opt_router rt;
  uint8_t pad[2];
} ipv6_rtr_alert = {.hdr = {0, 0},
                    .rt = {IP6OPT_ROUTER_ALERT, 2, {0, IP6_ALERT_MLD}},
                    .pad = {0, 0}};

static struct MribIface mifs[MAXMIFS] = {};
static struct UloopFD mrt_fd = {.fd = -1};
static struct UloopFD mrt6_fd = {.fd = -1};

// Unmap IPv4 address from IPv6
static void mrib_unmap(struct in_addr* addr4, const struct in6_addr* addr6) {
  addr4->s_addr = addr6->s6_addr32[3];
}

// Add / delete multicast route
static int mrib_set(const struct in6_addr* group,
                    const struct in6_addr* source,
                    struct MribIface* iface,
                    MribFilter dest,
                    bool del) {
  int status = 0;
  size_t mifid = iface - mifs;
  if (IN6_IS_ADDR_V4MAPPED(group)) {
    struct mfcctl ctl = {.mfcc_parent = static_cast<vifi_t>(mifid)};
    mrib_unmap(&ctl.mfcc_origin, source);
    mrib_unmap(&ctl.mfcc_mcastgrp, group);

    if (!del) {
      for (size_t i = 0; i < MAXMIFS; ++i) {
        if (dest & (1 << i)) {
          ctl.mfcc_ttls[i] = 1;
        }
      }
    }

    if (setsockopt(mrt_fd.fd, IPPROTO_IP, (del) ? MRT_DEL_MFC : MRT_ADD_MFC,
                   &ctl, sizeof(ctl))) {
      status = -errno;
    }
  } else {
    struct mf6cctl ctl = {
        .mf6cc_origin = {AF_INET6, 0, 0, *source, 0},
        .mf6cc_mcastgrp = {AF_INET6, 0, 0, *group, 0},
        .mf6cc_parent = static_cast<mifi_t>(mifid),
    };

    if (!del) {
      for (size_t i = 0; i < MAXMIFS; ++i) {
        if (dest & (1 << i)) {
          IF_SET(i, &ctl.mf6cc_ifset);
        }
      }
    }

    if (setsockopt(mrt6_fd.fd, IPPROTO_IPV6,
                   (del) ? MRT6_DEL_MFC : MRT6_ADD_MFC, &ctl, sizeof(ctl))) {
      status = -errno;
    }
  }

  char groupbuf[INET6_ADDRSTRLEN], sourcebuf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, group, groupbuf, sizeof(groupbuf));
  inet_ntop(AF_INET6, source, sourcebuf, sizeof(sourcebuf));
  if (del) {
    L_DEBUG("%s: deleting MFC-entry for %s from %s%%%d: %s", __FUNCTION__,
            groupbuf, sourcebuf, iface->ifindex, strerror(-status));
  } else {
    int ifbuf_len = 0;
    char ifbuf[256] = {0};
    for (size_t i = 0; i < MAXMIFS; ++i) {
      if (dest & (1 << i)) {
        ifbuf_len += snprintf(&ifbuf[ifbuf_len], sizeof(ifbuf) - ifbuf_len,
                              " %d", mifs[i].ifindex);
      }
    }

    L_DEBUG("%s: setting MFC-entry for %s from %s%%%d to%s: %s", __FUNCTION__,
            groupbuf, sourcebuf, iface->ifindex, ifbuf, strerror(-status));
  }

  return status;
}

// We have no way of knowing when a source disappears, so we delete multicast
// routes from time to time
static void mrib_clean(struct UloopTimeout* t) {
  struct MribIface* iface = container_of(t, struct MribIface, timer);
  omcp_time_t now = omcp_time();
  uloop_timeout_cancel(t);

  struct MribRoute *c, *n;
  for (MribRoute* )
  list_for_each_entry_safe(c, n, &iface->routes, head) {
    if (c->valid_until <= now ||
        (iface->users.empty() && list_empty(&iface->queriers))) {
      mrib_set(&c->group, &c->source, iface, 0, true);
      list_del(&c->head);
      free(c);
    } else {
      uloop_timeout_set(t, c->valid_until - now);
      break;
    }
  }
}

// Find MIFID by ifindex
static size_t mrib_find(int ifindex) {
  size_t i = 0;
  while (i < MAXMIFS && mifs[i].ifindex != ifindex) {
    ++i;
  }
  return i;
}

// Notify all users of a new multicast source
static void mrib_notify_newsource(struct MribIface* iface,
                                  const struct in6_addr* group,
                                  const struct in6_addr* source) {
  MribFilter filter = 0;
  struct MribUser* user;
  for (MribUser* user : iface->users) {
    if (user->cb_newsource) {
      user->cb_newsource(user, group, source, &filter);
    }
  }

  char groupbuf[INET6_ADDRSTRLEN], sourcebuf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, group, groupbuf, sizeof(groupbuf));
  inet_ntop(AF_INET6, source, sourcebuf, sizeof(sourcebuf));
  L_DEBUG("%s: detected new multicast source %s for %s on %d", __FUNCTION__,
          sourcebuf, groupbuf, iface->ifindex);

  auto* route = new struct MribRoute();
  route->group = *group;
  route->source = *source;
  route->valid_until =
      omcp_time() + MRIB_DEFAULT_LIFETIME * OMCP_TIME_PER_SECOND;

  if (list_empty(&iface->routes)) {
    uloop_timeout_set(&iface->timer,
                      MRIB_DEFAULT_LIFETIME * OMCP_TIME_PER_SECOND);
  }

  list_add_tail(&route->head, &iface->routes);
  mrib_set(group, source, iface, filter, false);
}

// Calculate IGMP-checksum
static uint16_t igmp_checksum(const uint16_t* buf, size_t len) {
  int32_t sum = 0;

  while (len > 1) {
    sum += *buf++;
    sum = (sum + (sum >> 16)) & 0xffff;
    len -= 2;
  }

  if (len == 1) {
    sum += *((uint8_t*)buf);
    sum += (sum + (sum >> 16)) & 0xffff;
  }

  return ~sum;
}

// Receive and handle MRT event
static void mrib_receive_mrt(struct UloopFD* fd, unsigned flags) {
  uint8_t buf[9216], cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
  char addrbuf[INET_ADDRSTRLEN];
  struct sockaddr_in from{};

  while (true) {
    struct iovec iov = {buf, sizeof(buf)};
    struct msghdr hdr = {.msg_name = (void*)&from,
                         .msg_namelen = sizeof(from),
                         .msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = cbuf,
                         .msg_controllen = sizeof(cbuf)};

    ssize_t len = recvmsg(fd->fd, &hdr, MSG_DONTWAIT);
    if (len < 0 && errno == EAGAIN) {
      break;
    }

    auto* iph = static_cast<iphdr*>(iov.iov_base);
    if (len < (ssize_t)sizeof(*iph)) {
      continue;
    }

    if (iph->protocol == 0) {
      // Pseudo IP/IGMP-packet from kernel MC-API
      auto* msg = static_cast<igmpmsg*>(iov.iov_base);
      struct MribIface* iface = nullptr;
      if (msg->im_vif < MAXMIFS) {
        iface = &mifs[msg->im_vif];
      }

      if (!iface) {
        L_WARN("MRT kernel-message for unknown MIF %i", msg->im_vif);
        continue;
      }

      if (msg->im_msgtype != IGMPMSG_NOCACHE) {
        L_WARN("Unknown MRT kernel-message %i on interface %d", msg->im_msgtype,
               iface->ifindex);
        continue;
      }

      struct in6_addr dst = IN6ADDR_ANY_INIT;
      struct in6_addr src = IN6ADDR_ANY_INIT;
      dst.s6_addr32[2] = cpu_to_be32(0xffff);
      dst.s6_addr32[3] = msg->im_dst.s_addr;
      src.s6_addr32[2] = cpu_to_be32(0xffff);
      src.s6_addr32[3] = msg->im_src.s_addr;

      mrib_notify_newsource(iface, &dst, &src);
    } else {
      // IGMP packet
      if ((len -= iph->ihl * 4) < 0) {
        continue;
      }

      int ifindex = 0;
      for (struct cmsghdr* ch = CMSG_FIRSTHDR(&hdr); ch != nullptr;
           ch = CMSG_NXTHDR(&hdr, ch)) {
        if (ch->cmsg_level == IPPROTO_IP && ch->cmsg_type == IP_PKTINFO) {
          auto* info = (struct in_pktinfo*)CMSG_DATA(ch);
          ifindex = info->ipi_ifindex;
        }
      }

      if (ifindex == 0) {
        continue;
      }

      inet_ntop(AF_INET, &from.sin_addr, addrbuf, sizeof(addrbuf));
      auto* igmp = (struct igmphdr*)&buf[iph->ihl * 4];

      uint16_t checksum = igmp->csum;
      igmp->csum = 0;

      if (iph->ttl != 1 || len < (ssize_t)sizeof(*igmp) ||
          checksum != igmp_checksum((uint16_t*)igmp, len)) {
        L_WARN("%s: ignoring invalid IGMP-message of type %x from %s on %d",
               __FUNCTION__, igmp->type, addrbuf, ifindex);
        continue;
      }

      auto* opts = (uint32_t*)&iph[1];
      bool alert = (void*)&opts[1] <= (void*)igmp && *opts == ipv4_rtr_alert;
      if (!alert && (igmp->type != IGMP_HOST_MEMBERSHIP_QUERY ||
                     (size_t)len > sizeof(*igmp) || igmp->code > 0)) {
        L_WARN("%s: ignoring invalid IGMP-message of type %x from %s on %d",
               __FUNCTION__, igmp->type, addrbuf, ifindex);
        continue;
      }

      ssize_t mifid = mrib_find(ifindex);
      if (mifid < MAXMIFS) {
        struct MribQuerier* q;
        list_for_each_entry(q, &mifs[mifid].queriers, head) if (q->cb_igmp)
            q->cb_igmp(q, igmp, len, &from);
      }
    }
  }
}

// Receive and handle MRT6 event
static void mrib_receive_mrt6(struct UloopFD* fd, unsigned flags) {
  uint8_t buf[9216], cbuf[128];
  char addrbuf[INET6_ADDRSTRLEN];
  struct sockaddr_in6 from{};

  while (true) {
    struct iovec iov = {buf, sizeof(buf)};
    struct msghdr hdr = {.msg_name = (void*)&from,
                         .msg_namelen = sizeof(from),
                         .msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = cbuf,
                         .msg_controllen = sizeof(cbuf)};

    ssize_t len = recvmsg(fd->fd, &hdr, MSG_DONTWAIT);
    if (len < 0 && errno == EAGAIN) {
      break;
    }

    auto* mld = static_cast<mld_hdr*>(iov.iov_base);
    if (len < (ssize_t)sizeof(*mld)) {
      continue;
    }

    if (mld->mld_icmp6_hdr.icmp6_type == 0) {
      // Pseudo ICMPv6/MLD-packet from kernel MC-API
      auto* msg = static_cast<mrt6msg*>(iov.iov_base);
      struct MribIface* iface = nullptr;
      if (msg->im6_mif < MAXMIFS) {
        iface = &mifs[msg->im6_mif];
      }

      if (!iface) {
        L_WARN("MRT6 kernel-message for unknown MIF %i", msg->im6_mif);
        continue;
      }

      if (msg->im6_msgtype != MRT6MSG_NOCACHE) {
        L_WARN("Unknown MRT6 kernel-message %i on interface %d",
               msg->im6_msgtype, iface->ifindex);
        continue;
      }

      mrib_notify_newsource(iface, &msg->im6_dst, &msg->im6_src);
    } else {
      int hlim = 0, ifindex = from.sin6_scope_id;
      bool alert = false;
      for (struct cmsghdr* ch = CMSG_FIRSTHDR(&hdr); ch != nullptr;
           ch = CMSG_NXTHDR(&hdr, ch)) {
        if (ch->cmsg_level == IPPROTO_IPV6 && ch->cmsg_type == IPV6_HOPLIMIT) {
          memcpy(&hlim, CMSG_DATA(ch), sizeof(hlim));
        } else if (ch->cmsg_level == IPPROTO_IPV6 &&
                   ch->cmsg_type == IPV6_HOPOPTS &&
                   ch->cmsg_len >= CMSG_LEN(sizeof(ipv6_rtr_alert)) &&
                   memmem(CMSG_DATA(ch), ch->cmsg_len - CMSG_LEN(0),
                          &ipv6_rtr_alert.rt, sizeof(ipv6_rtr_alert.rt))) {
          alert = true;  // FIXME: memmem is wrong
        }
      }
      inet_ntop(AF_INET6, &from.sin6_addr, addrbuf, sizeof(addrbuf));

      if (!IN6_IS_ADDR_LINKLOCAL(&from.sin6_addr) || hlim != 1 || len < 24 ||
          !alert) {
        L_WARN("mld: ignoring invalid MLD-message of type %d from %s on %d",
               mld->mld_icmp6_hdr.icmp6_type, addrbuf, ifindex);
        continue;
      }

      ssize_t mifid = mrib_find(from.sin6_scope_id);
      if (mifid < MAXMIFS) {
        struct MribQuerier* q;
        list_for_each_entry(q, &mifs[mifid].queriers, head) if (q->cb_mld)
            q->cb_mld(q, mld, len, &from);
      }
    }
  }
}

// Send an IGMP-packet
int mrib_send_igmp(struct MribQuerier* q,
                   struct igmpv3_query* igmp,
                   size_t len,
                   const struct sockaddr_in* dest) {
  uint8_t cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0};
  struct iovec iov = {igmp, len};
  struct msghdr msg = {.msg_name = (void*)dest,
                       .msg_namelen = sizeof(*dest),
                       .msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_control = cbuf,
                       .msg_controllen = sizeof(cbuf)};

  igmp->csum = 0;
  igmp->csum = igmp_checksum((uint16_t*)igmp, len);

  // Set control data (define destination interface)
  struct cmsghdr* chdr = CMSG_FIRSTHDR(&msg);
  chdr->cmsg_level = IPPROTO_IP;
  chdr->cmsg_type = IP_PKTINFO;
  chdr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

  auto* pktinfo = (struct in_pktinfo*)CMSG_DATA(chdr);
  pktinfo->ipi_addr.s_addr = 0;
  pktinfo->ipi_ifindex = q->iface->ifindex;
  if (mrib_igmp_source(q, &pktinfo->ipi_spec_dst)) {
    return -errno;
  }

  ssize_t s = sendmsg(mrt_fd.fd, &msg, MSG_DONTWAIT);
  return (s < 0) ? -errno : (s < (ssize_t)len) ? -EMSGSIZE : 0;
}

// Send an IGMP-packet
int mrib_send_mld(struct MribQuerier* q,
                  struct mld_hdr* mld,
                  size_t len,
                  const struct sockaddr_in6* dest) {
  uint8_t cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
  struct iovec iov = {mld, len};
  struct msghdr msg = {.msg_name = (void*)dest,
                       .msg_namelen = sizeof(*dest),
                       .msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_control = cbuf,
                       .msg_controllen = sizeof(cbuf)};

  // Set control data (define destination interface)
  struct cmsghdr* chdr = CMSG_FIRSTHDR(&msg);
  chdr->cmsg_level = IPPROTO_IPV6;
  chdr->cmsg_type = IPV6_PKTINFO;
  chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

  auto* pktinfo = (struct in6_pktinfo*)CMSG_DATA(chdr);
  pktinfo->ipi6_ifindex = q->iface->ifindex;
  if (mrib_mld_source(q, &pktinfo->ipi6_addr)) {
    return -errno;
  }

  ssize_t s = sendmsg(mrt6_fd.fd, &msg, MSG_DONTWAIT);
  return (s < 0) ? -errno : (s < (ssize_t)len) ? -EMSGSIZE : 0;
}

// Initialize MRIB
static int mrib_init() {
  int fd;
  int val;

  if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0) {
    goto err;
  }

  val = 1;
  if (setsockopt(fd, IPPROTO_IP, MRT_INIT, &val, sizeof(val))) {
    goto err;
  }

  if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val))) {
    goto err;
  }

  // Configure IP header fields
  if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val))) {
    goto err;
  }

  val = 0xc0;
  if (setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val))) {
    goto err;
  }

  val = 0;
  if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val))) {
    goto err;
  }

  // Set router-alert option
  if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, &ipv4_rtr_alert,
                 sizeof(ipv4_rtr_alert))) {
    goto err;
  }

  mrt_fd.fd = fd;

  if ((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    goto err;
  }

  // We need to know the source interface and hop-opts
  val = 1;
  if (setsockopt(fd, IPPROTO_IPV6, MRT6_INIT, &val, sizeof(val))) {
    goto err;
  }

  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &val, sizeof(val))) {
    goto err;
  }

  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val))) {
    goto err;
  }

  // MLD has hoplimit 1
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val))) {
    goto err;
  }

  val = 0;
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val))) {
    goto err;
  }

  // Let the kernel compute our checksums
  val = 2;
  if (setsockopt(fd, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val))) {
    goto err;
  }

  // Set hop-by-hop router alert on outgoing
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_HOPOPTS, &ipv6_rtr_alert,
                 sizeof(ipv6_rtr_alert))) {
    goto err;
  }

  // Set ICMP6 filter
  struct icmp6_filter flt;
  ICMP6_FILTER_SETBLOCKALL(&flt);
  ICMP6_FILTER_SETPASS(ICMPV6_MGM_QUERY, &flt);
  ICMP6_FILTER_SETPASS(ICMPV6_MGM_REPORT, &flt);
  ICMP6_FILTER_SETPASS(ICMPV6_MGM_REDUCTION, &flt);
  ICMP6_FILTER_SETPASS(ICMPV6_MLD2_REPORT, &flt);
  if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &flt, sizeof(flt))) {
    goto err;
  }

  mrt6_fd.fd = fd;

  mrt_fd.cb = mrib_receive_mrt;
  mrt6_fd.cb = mrib_receive_mrt6;

  uloop_fd_add(&mrt_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);
  uloop_fd_add(&mrt6_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

  fd = -1;
  errno = 0;

err:
  if (fd >= 0) {
    close(fd);
  }
  return -errno;
}

// Create new interface entry
static struct MribIface* mrib_get_iface(int ifindex) {
  if (mrt_fd.fd < 0 && mrib_init() < 0) {
    return nullptr;
  }

  size_t mifid = mrib_find(ifindex);
  if (mifid < MAXMIFS) {
    return &mifs[mifid];
  }

  errno = EBUSY;
  if ((mifid = mrib_find(0)) >= MAXMIFS) {
    return nullptr;
  }

  struct MribIface* iface = &mifs[mifid];

  struct vifctl ctl = {static_cast<vifi_t>(mifid),    VIFF_USE_IFINDEX, 1, 0,
                       {.vifc_lcl_ifindex = ifindex}, {INADDR_ANY}};
  if (setsockopt(mrt_fd.fd, IPPROTO_IP, MRT_ADD_VIF, &ctl, sizeof(ctl))) {
    return nullptr;
  }

  struct mif6ctl ctl6 = {static_cast<mifi_t>(mifid), 0, 1, static_cast<uint16_t>(ifindex), 0};
  if (setsockopt(mrt6_fd.fd, IPPROTO_IPV6, MRT6_ADD_MIF, &ctl6, sizeof(ctl6))) {
    return nullptr;
  }

  struct ip_mreqn mreq = {{INADDR_ALLIGMPV3RTRS_GROUP}, {INADDR_ANY}, ifindex};
  setsockopt(mrt_fd.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

  mreq.imr_multiaddr.s_addr = cpu_to_be32(INADDR_ALLRTRS_GROUP);
  setsockopt(mrt_fd.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

  struct ipv6_mreq mreq6 = {MLD2_ALL_MCR_INIT, static_cast<unsigned int>(ifindex)};
  setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6,
             sizeof(mreq6));

  mreq6.ipv6mr_multiaddr.s6_addr[15] = 0x02;
  setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6,
             sizeof(mreq6));

  iface->timer.cb = mrib_clean;
  iface->ifindex = ifindex;
  INIT_LIST_HEAD(&iface->routes);
  INIT_LIST_HEAD(&iface->queriers);
  return iface;
}

// Remove interfaces if it has no more users
static void mrib_clean_iface(struct MribIface* iface) {
  if (iface->users.empty() && list_empty(&iface->queriers)) {
    iface->ifindex = 0;
    mrib_clean(&iface->timer);

    size_t mifid = iface - mifs;
    struct vifctl ctl = {static_cast<vifi_t>(mifid),
                         VIFF_USE_IFINDEX,
                         1,
                         0,
                         {.vifc_lcl_ifindex = iface->ifindex},
                         {INADDR_ANY}};
    setsockopt(mrt_fd.fd, IPPROTO_IP, MRT_DEL_VIF, &ctl, sizeof(ctl));

    struct mif6ctl ctl6 = {static_cast<mifi_t>(mifid), 0, 1, static_cast<uint16_t>(iface->ifindex), 0};
    setsockopt(mrt6_fd.fd, IPPROTO_IPV6, MRT6_DEL_MIF, &ctl6, sizeof(ctl6));

    struct ip_mreqn mreq = {
        {INADDR_ALLIGMPV3RTRS_GROUP}, {INADDR_ANY}, iface->ifindex};
    setsockopt(mrt_fd.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

    mreq.imr_multiaddr.s_addr = cpu_to_be32(INADDR_ALLRTRS_GROUP);
    setsockopt(mrt_fd.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

    struct ipv6_mreq mreq6 = {MLD2_ALL_MCR_INIT, static_cast<unsigned int>(iface->ifindex)};
    setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6,
               sizeof(mreq6));

    mreq6.ipv6mr_multiaddr.s6_addr[15] = 0x02;
    setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6,
               sizeof(mreq6));
  }
}

// Register a new interface to mrib
int mrib_attach_user(struct MribUser* user,
                     int ifindex,
                     MribCallback* cb_newsource) {
  struct MribIface* iface = mrib_get_iface(ifindex);
  if (!iface) {
    return -errno;
  }

  if (user->iface == iface) {
    return -EALREADY;
  }

  iface->users.push_back(user);
  user->iface = iface;
  user->cb_newsource = cb_newsource;
  return 0;
}

// Deregister an interface from mrib
void mrib_detach_user(struct MribUser* user) {
  struct MribIface* iface = user->iface;
  if (!iface) {
    return;
  }

  user->iface = nullptr;
  list_del(&user->head);
  mrib_clean_iface(iface);
}

// Register a querier to mrib
int mrib_attach_querier(struct MribQuerier* querier,
                        int ifindex,
                        MribIGMPCallback* cb_igmp,
                        MribMLDCallback* cb_mld) {
  struct MribIface* iface = mrib_get_iface(ifindex);
  if (!iface) {
    return -errno;
  }

  list_add(&querier->head, &iface->queriers);
  querier->iface = iface;
  querier->cb_igmp = cb_igmp;
  querier->cb_mld = cb_mld;
  return 0;
}

// Deregister a querier from mrib
void mrib_detach_querier(struct MribQuerier* querier) {
  struct MribIface* iface = querier->iface;
  if (!iface) {
    return;
  }

  querier->iface = nullptr;
  list_del(&querier->head);
  mrib_clean_iface(iface);
}

// Add an interface to the filter
int mrib_filter_add(MribFilter* filter, struct MribUser* user) {
  struct MribIface* iface = user->iface;
  if (!iface) {
    return -ENOENT;
  }

  *filter |= 1 << (iface - mifs);
  return 0;
}

// Get MLD source address
int mrib_mld_source(struct MribQuerier* q, struct in6_addr* source) {
  struct sockaddr_in6 addr = {AF_INET6, 0, 0, MLD2_ALL_MCR_INIT,
                              static_cast<uint32_t>(q->iface->ifindex)};
  socklen_t alen = sizeof(addr);
  int sock = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
  int ret = 0;

  if (sock < 0 || connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
    ret = -errno;
  }

  if (ret || getsockname(sock, (struct sockaddr*)&addr, &alen)) {
    L_WARN("%s: failed to detect local source address on %d", __FUNCTION__,
           q->iface->ifindex);
    ret = -errno;
  }

  close(sock);

  if (ret == 0) {
    *source = addr.sin6_addr;
  }

  return ret;
}

// Get IGMP source address
int mrib_igmp_source(struct MribQuerier* q, struct in_addr* source) {
  struct sockaddr_in addr = {
      AF_INET, 0, {cpu_to_be32(INADDR_ALLHOSTS_GROUP)}, {0}};
  socklen_t alen = sizeof(addr);
  struct ifreq ifr = {.ifr_name = ""};
  int sock = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
  int ret = 0;

  ifr.ifr_ifindex = q->iface->ifindex;

  if (sock < 0 || ioctl(sock, SIOCGIFNAME, &ifr) ||
      setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name,
                 strlen(ifr.ifr_name))) {
    ret = -errno;
  }

  if (ret || connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
    ret = -errno;
  }

  if (ret || getsockname(sock, (struct sockaddr*)&addr, &alen)) {
    L_WARN("%s: failed to detect local source address on %d", __FUNCTION__,
           q->iface->ifindex);
    ret = -errno;
  }

  close(sock);

  if (ret == 0) {
    *source = addr.sin_addr;
  }

  return ret;
}
