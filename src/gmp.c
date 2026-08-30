/*
 * Copyright 2015 Steven Barth <steven at midlink.org>
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
#include <netinet/in.h>
#include <string.h>

#include "addr.h"
#include "gmp.h"
#include "querier.h"

uint16_t gmp_checksum(const void* data, size_t len) {
  const uint8_t* p = data;
  uint32_t sum = 0;

  while (len > 1) {
    uint16_t word;
    memcpy(&word, p, sizeof(word));
    sum += word;
    sum = (sum + (sum >> 16)) & 0xffff;
    p += 2;
    len -= 2;
  }

  if (len == 1) {
    uint16_t word = 0;
    memcpy(&word, p, 1);
    sum += word;
    sum = (sum + (sum >> 16)) & 0xffff;
  }

  return (uint16_t)~sum;
}

static int gmp_float_decode(unsigned int value,
                            unsigned int flag_bit,
                            unsigned int exp_shift,
                            unsigned int mant_mask) {
  if (!(value & flag_bit)) {
    return (int)value;
  }

  unsigned int exp = (value >> exp_shift) & 0x7;
  unsigned int mant = (value & mant_mask) | (mant_mask + 1);
  return (int)(mant << (exp + 3));
}

static unsigned int gmp_float_encode(int value,
                                     unsigned int flag_bit,
                                     unsigned int exp_shift,
                                     unsigned int mant_mask) {
  if (value < (int)flag_bit) {
    return (unsigned int)value;
  }

  unsigned int exp = 3;
  while (((unsigned int)value >> exp) > (2 * mant_mask + 1) && exp <= 10) {
    ++exp;
  }

  if (exp > 10) {
    return flag_bit | (mant_mask << exp_shift) | mant_mask;
  }

  return flag_bit | ((exp - 3) << exp_shift) |
         (((unsigned int)value >> exp) & mant_mask);
}

int gmp_float8_decode(uint8_t value) {
  return gmp_float_decode(value, 0x80, 4, 0xf);
}

uint8_t gmp_float8_encode(int value) {
  return (uint8_t)gmp_float_encode(value, 0x80, 4, 0xf);
}

int gmp_float16_decode(uint16_t value) {
  return gmp_float_decode(value, 0x8000, 12, 0xfff);
}

uint16_t gmp_float16_encode(int value) {
  return (uint16_t)gmp_float_encode(value, 0x8000, 12, 0xfff);
}

bool gmp_ipv4_router_alert(const uint8_t* opts, size_t len) {
  size_t i = 0;
  while (i < len) {
    uint8_t type = opts[i];
    if (type == 0) {
      break;
    }
    if (type == 1) {
      ++i;
      continue;
    }
    if (i + 1 >= len) {
      break;
    }
    uint8_t olen = opts[i + 1];
    if (olen < 2 || i + olen > len) {
      break;
    }
    if (type == 0x94 && olen == 4 && opts[i + 2] == 0 && opts[i + 3] == 0) {
      return true;
    }
    i += olen;
  }
  return false;
}

bool gmp_ipv6_router_alert(const uint8_t* hbh, size_t len) {
  if (len < 2) {
    return false;
  }

  size_t hlen = ((size_t)hbh[1] + 1) * 8;
  if (hlen < len) {
    len = hlen;
  }

  size_t i = 2;
  while (i < len) {
    uint8_t type = hbh[i];
    if (type == 0) {
      ++i;
      continue;
    }
    if (i + 1 >= len) {
      break;
    }
    uint8_t olen = hbh[i + 1];
    if (i + 2 + olen > len) {
      break;
    }
    if (type == 0x05 && olen == 2 && hbh[i + 2] == 0 && hbh[i + 3] == 0) {
      return true;
    }
    i += 2 + (size_t)olen;
  }
  return false;
}

struct mld_query {
  struct mld_hdr mld;
  uint8_t s_qrv;
  uint8_t qqic;
  uint16_t nsrc;
  struct in6_addr addrs[];
};

struct gmp_query {
  struct in6_addr group;
  const struct in6_addr* sources;
  size_t nsrc;
  bool general;
  bool suppress;
  bool full_length;
  int robustness;
  omgp_time_t mrd;
  omgp_time_t query_interval;
};

static size_t gmp_addr_len(enum gmp_family family) {
  return (family == GMP_MLD) ? sizeof(struct in6_addr) : sizeof(struct in_addr);
}

// Load a wire address of the family as a (v4-mapped) IPv6 address
static void gmp_load_addr(enum gmp_family family,
                          struct in6_addr* dst,
                          const uint8_t* src) {
  if (family == GMP_MLD) {
    memcpy(dst, src, sizeof(*dst));
  } else {
    in_addr_t addr4;
    memcpy(&addr4, src, sizeof(addr4));
    addr_map(dst, addr4);
  }
}

// Test if a (v4-mapped) group address is valid and relevant for the family
static bool gmp_valid_group(enum gmp_family family,
                            const struct in6_addr* addr) {
  if (family == GMP_IGMP) {
    return IN_MULTICAST(be32toh(addr_unmap(addr)));
  }
  return IN6_IS_ADDR_MULTICAST(addr);
}

// Handle one group record of an IGMPv3 / MLDv2 report
// (RFC 3376 4.2.4 and RFC 3810 5.2 share the layout; only the address width
// differs)
static ssize_t gmp_handle_record(struct groups* groups,
                                 enum gmp_family family,
                                 const uint8_t* data,
                                 size_t len) {
  size_t alen = gmp_addr_len(family);
  size_t hdrlen = 4 + alen;
  if (len < hdrlen) {
    return -1;
  }

  uint8_t type = data[0];
  size_t aux = (size_t)data[1] * 4;
  uint16_t nsrc_be;
  memcpy(&nsrc_be, &data[2], sizeof(nsrc_be));
  size_t nsrc = ntohs(nsrc_be);

  size_t read = hdrlen + nsrc * alen + aux;
  if (len < read) {
    return -1;
  }

  struct in6_addr addr;
  gmp_load_addr(family, &addr, &data[4]);

  if (type >= UPDATE_IS_INCLUDE && type <= UPDATE_BLOCK &&
      gmp_valid_group(family, &addr)) {
    struct in6_addr sources[QUERIER_MAX_SOURCE + 1];
    if (nsrc > QUERIER_MAX_SOURCE + 1) {
      nsrc = QUERIER_MAX_SOURCE + 1;
    }
    for (size_t i = 0; i < nsrc; ++i) {
      gmp_load_addr(family, &sources[i], &data[hdrlen + i * alen]);
    }

    groups_update_state(groups, &addr, nsrc ? sources : NULL, nsrc, type);
  }

  return (ssize_t)read;
}

// Iterate the group records of an IGMPv3 / MLDv2 report
static void gmp_handle_report(struct groups* groups,
                              enum gmp_family family,
                              const uint8_t* data,
                              size_t len,
                              size_t count) {
  size_t offset = 8;
  while (count > 0 && offset < len) {
    ssize_t read =
        gmp_handle_record(groups, family, &data[offset], len - offset);
    if (read < 0) {
      break;
    }

    offset += (size_t)read;
    --count;
  }
}

// Handle a normalized query: run the querier election and update timers.
// Legacy short queries are deliberately excluded from the election.
static void gmp_handle_query(struct querier_iface* q,
                             enum gmp_family family,
                             const struct gmp_query* p,
                             int election,
                             const char* fromstr) {
  omgp_time_t now = omgp_time();

  if (!p->suppress && !p->general) {
    groups_update_timers(&q->groups, &p->group, p->sources, p->nsrc);
  }

  if (election != 0 && p->full_length) {
    struct groups_config* cfg =
        (family == GMP_MLD) ? &q->groups.cfg_v6 : &q->groups.cfg_v4;
    bool was_other = q->proto[family].other_querier;
    if (election < 0) {
      q->proto[family].other_querier = true;
    }
    bool other = q->proto[family].other_querier;

    omgp_time_t qri =
        (other && p->general) ? p->mrd : cfg->query_response_interval;
    omgp_time_t qi = other ? p->query_interval : cfg->query_interval;
    groups_update_config(&q->groups, family == GMP_MLD, qri, qi, p->robustness);

    if (election < 0) {
      q->proto[family].next_query = now + (cfg->query_response_interval / 2) +
                                    (cfg->robustness * cfg->query_interval);
      if (!was_other) {
        L_INFO("%s: detected other querier %s on %d", __FUNCTION__, fromstr,
               q->ifindex);
      }
    }
  }
}

// Receive and parse an IGMP-packet (called by mrib as callback)
void igmp_handle(struct mrib_querier* mrib,
                 const struct igmphdr* igmp,
                 size_t len,
                 const struct sockaddr_in* from) {
  struct querier_iface* q = container_of(mrib, struct querier_iface, mrib);
  char addrbuf[INET_ADDRSTRLEN];
  struct in6_addr group;

  addr_map(&group, igmp->group);
  inet_ntop(AF_INET, &from->sin_addr, addrbuf, sizeof(addrbuf));

  if (igmp->type == IGMP_HOST_MEMBERSHIP_QUERY) {
    const struct igmpv3_query* query = (const struct igmpv3_query*)igmp;

    if (len != sizeof(*igmp) &&
        (len < sizeof(*query) ||
         len < sizeof(*query) + ntohs(query->nsrcs) * sizeof(struct in_addr))) {
      return;
    }

    if (query->group && !gmp_valid_group(GMP_IGMP, &group)) {
      return;
    }

    if (len > sizeof(*igmp) && !query->group && query->nsrcs) {
      return;
    }

    struct in_addr local;
    if (mrib_igmp_source(mrib, &local)) {
      return;
    }

    struct gmp_query p = {
        .group = group,
        .general = !query->group,
        .robustness = 2,
        .mrd = 10000,
        .query_interval = 125000,
        .full_length = len > sizeof(*igmp),
    };

    if (p.full_length) {
      p.mrd = (omgp_time_t)100 * gmp_float8_decode(igmp->code);
    } else if (igmp->code) {
      p.mrd = (omgp_time_t)100 * igmp->code;
    }

    struct in6_addr sources[QUERIER_MAX_SOURCE + 1];
    if (p.full_length) {
      if (query->qrv) {
        p.robustness = query->qrv;
      }
      if (query->qqic) {
        p.query_interval = (omgp_time_t)gmp_float8_decode(query->qqic) * 1000;
      }

      p.suppress = query->suppress;
      p.nsrc = ntohs(query->nsrcs);
      if (p.nsrc > QUERIER_MAX_SOURCE + 1) {
        p.nsrc = QUERIER_MAX_SOURCE + 1;
      }
      for (size_t i = 0; i < p.nsrc; ++i) {
        addr_map(&sources[i], query->srcs[i]);
      }
      p.sources = sources;
    }

    gmp_handle_query(q, GMP_IGMP, &p,
                     memcmp(&from->sin_addr, &local, sizeof(local)), addrbuf);
  } else if (igmp->type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
    const struct igmpv3_report* report = (const struct igmpv3_report*)igmp;
    if (len <= sizeof(*report)) {
      return;
    }

    gmp_handle_report(&q->groups, GMP_IGMP, (const uint8_t*)igmp, len,
                      ntohs(report->ngrec));
  } else if (igmp->type == IGMPV2_HOST_MEMBERSHIP_REPORT ||
             igmp->type == IGMP_HOST_LEAVE_MESSAGE ||
             igmp->type == IGMP_HOST_MEMBERSHIP_REPORT) {
    if (len != sizeof(*igmp) || !gmp_valid_group(GMP_IGMP, &group)) {
      return;
    }

    groups_update_state(
        &q->groups, &group, NULL, 0,
        (igmp->type == IGMPV2_HOST_MEMBERSHIP_REPORT) ? UPDATE_REPORT
        : (igmp->type == IGMP_HOST_MEMBERSHIP_REPORT) ? UPDATE_REPORT_V1
                                                      : UPDATE_DONE);
  }

  ev_timer_set(&q->timeout, 0);
}

// Receive and parse an MLD-packet (called by mrib as callback)
void mld_handle(struct mrib_querier* mrib,
                const struct mld_hdr* hdr,
                size_t len,
                const struct sockaddr_in6* from) {
  struct querier_iface* q = container_of(mrib, struct querier_iface, mrib);
  char addrbuf[ADDR_BUFLEN];
  const char* addrstr = addr_ntop(addrbuf, sizeof(addrbuf), &from->sin6_addr);
  uint8_t type = hdr->mld_icmp6_hdr.icmp6_type;

  if (type == MLD_LISTENER_QUERY) {
    const struct mld_query* query = (const struct mld_query*)hdr;

    if (len != sizeof(struct mld_hdr) &&
        (len < sizeof(*query) ||
         len < sizeof(*query) + ntohs(query->nsrc) * sizeof(struct in6_addr))) {
      return;
    }

    if (!IN6_IS_ADDR_UNSPECIFIED(&query->mld.mld_addr) &&
        !gmp_valid_group(GMP_MLD, &query->mld.mld_addr)) {
      return;
    }

    if (len > sizeof(struct mld_hdr) &&
        IN6_IS_ADDR_UNSPECIFIED(&query->mld.mld_addr) && query->nsrc) {
      return;
    }

    struct in6_addr local;
    if (mrib_mld_source(mrib, &local)) {
      return;
    }

    struct gmp_query p = {
        .group = query->mld.mld_addr,
        .general = IN6_IS_ADDR_UNSPECIFIED(&query->mld.mld_addr),
        .robustness = 2,
        .mrd = 10000,
        .query_interval = 125000,
        .full_length = len > sizeof(struct mld_hdr),
        .sources = query->addrs,
    };

    uint16_t mrc = ntohs(hdr->mld_icmp6_hdr.icmp6_dataun.icmp6_un_data16[0]);
    if (p.full_length) {
      p.mrd = gmp_float16_decode(mrc);
    } else if (mrc) {
      p.mrd = mrc;
    }

    if (p.full_length) {
      if (query->s_qrv & 0x7) {
        p.robustness = query->s_qrv & 0x7;
      }
      if (query->qqic) {
        p.query_interval = (omgp_time_t)gmp_float8_decode(query->qqic) * 1000;
      }

      p.suppress = query->s_qrv & QUERIER_SUPPRESS;
      p.nsrc = ntohs(query->nsrc);
    }

    gmp_handle_query(q, GMP_MLD, &p,
                     memcmp(&from->sin6_addr, &local, sizeof(local)), addrstr);
  } else if (type == MLDV2_LISTENER_REPORT) {
    if (len <= sizeof(struct icmp6_hdr)) {
      return;
    }

    gmp_handle_report(
        &q->groups, GMP_MLD, (const uint8_t*)hdr, len,
        ntohs(hdr->mld_icmp6_hdr.icmp6_dataun.icmp6_un_data16[1]));
  } else if (type == MLD_LISTENER_REPORT || type == MLD_LISTENER_REDUCTION) {
    if (len != sizeof(struct mld_hdr) ||
        !gmp_valid_group(GMP_MLD, &hdr->mld_addr)) {
      return;
    }

    groups_update_state(
        &q->groups, &hdr->mld_addr, NULL, 0,
        (type == MLD_LISTENER_REPORT) ? UPDATE_REPORT : UPDATE_DONE);
  }

  ev_timer_set(&q->timeout, 0);
}

// Send generic / group-specific / group-and-source specific IGMP-query
static int igmp_send_query(struct querier_iface* q,
                           const struct in6_addr* group,
                           const struct list_head* sources,
                           bool suppress) {
  uint8_t qqic = gmp_float8_encode(
      (int)(((group) ? q->groups.cfg_v4.last_listener_query_interval
                     : q->groups.cfg_v4.query_response_interval) /
            100));
  union {
    struct igmpv3_query q;
    uint8_t buf[sizeof(struct igmpv3_query) +
                QUERIER_MAX_SOURCE * sizeof(struct in_addr)];
  } query = {.q = {
                 .type = IGMP_HOST_MEMBERSHIP_QUERY,
                 .code = qqic,
                 .qrv = (uint8_t)(q->groups.cfg_v4.robustness & 0x7),
                 .suppress = suppress,
                 .qqic = gmp_float8_encode(
                     (int)(q->groups.cfg_v4.query_interval / 1000)),
             }};

  struct group_source* s;
  size_t cnt = 0;
  if (sources) {
    list_for_each_entry (s, sources, head) {
      if (cnt >= QUERIER_MAX_SOURCE) {
        L_WARN("%s: maximum source count (%d) exceeded", __FUNCTION__,
               QUERIER_MAX_SOURCE);
        break;
      }

      query.q.srcs[cnt++] = addr_unmap(&s->addr);
    }
  }
  query.q.nsrcs = htons((uint16_t)cnt);

  struct sockaddr_in dest = {.sin_family = AF_INET,
                             .sin_addr = {htonl(0xe0000001U)}};
  if (group) {
    query.q.group = addr_unmap(group);
    dest.sin_addr.s_addr = query.q.group;
  }

  return mrib_send_igmp(&q->mrib, &query.q,
                        sizeof(query.q) + cnt * sizeof(query.q.srcs[0]), &dest);
}

// Send generic / group-specific / group-and-source specific MLD-query
static int mld_send_query(struct querier_iface* q,
                          const struct in6_addr* group,
                          const struct list_head* sources,
                          bool suppress) {
  uint16_t mrc = htons(gmp_float16_encode(
      (int)((group) ? q->groups.cfg_v6.last_listener_query_interval
                    : q->groups.cfg_v6.query_response_interval)));
  union {
    struct mld_query q;
    uint8_t buf[sizeof(struct mld_query) +
                QUERIER_MAX_SOURCE * sizeof(struct in6_addr)];
  } query = {.q = {
                 .mld = {.mld_icmp6_hdr = {MLD_LISTENER_QUERY,
                                           0,
                                           0,
                                           {.icmp6_un_data16 = {mrc, 0}}}},
                 .s_qrv = (uint8_t)((q->groups.cfg_v6.robustness & 0x7) |
                                    (suppress ? QUERIER_SUPPRESS : 0)),
                 .qqic = gmp_float8_encode(
                     (int)(q->groups.cfg_v6.query_interval / 1000)),
             }};

  struct group_source* s;
  size_t cnt = 0;
  if (sources) {
    list_for_each_entry (s, sources, head) {
      if (cnt >= QUERIER_MAX_SOURCE) {
        L_WARN("%s: maximum source count (%d) exceeded", __FUNCTION__,
               QUERIER_MAX_SOURCE);
        break;
      }

      query.q.addrs[cnt++] = s->addr;
    }
  }
  query.q.nsrc = htons((uint16_t)cnt);

  struct sockaddr_in6 dest = {
      .sin6_family = AF_INET6,
      .sin6_addr = IPV6_ALL_NODES_INIT,
      .sin6_scope_id = (uint32_t)q->ifindex,
  };

  if (group) {
    query.q.mld.mld_addr = dest.sin6_addr = *group;
  }

  return mrib_send_mld(&q->mrib, &query.q.mld,
                       sizeof(query.q) + cnt * sizeof(query.q.addrs[0]), &dest);
}

int gmp_send_query(struct querier_iface* q,
                   enum gmp_family family,
                   const struct in6_addr* group,
                   const struct list_head* sources,
                   bool suppress) {
  if (family == GMP_MLD) {
    return mld_send_query(q, group, sources, suppress);
  }
  return igmp_send_query(q, group, sources, suppress);
}
