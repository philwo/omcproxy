#pragma once

#include <libubox/uloop.h>

#include "src/omcproxy.h"

extern omgp_time_t stub_now;

void stub_advance(omgp_time_t delta);
