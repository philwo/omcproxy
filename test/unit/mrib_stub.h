#pragma once

#include "src/mrib.h"

extern struct in_addr stub_igmp_source;
extern struct in6_addr stub_mld_source;

extern uint8_t stub_sent[2048];
extern size_t stub_sent_len;
extern int stub_sent_family;
extern int stub_mrib_attach_error;
extern size_t stub_mrib_attach_calls;
extern size_t stub_mrib_detach_calls;
