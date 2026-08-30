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

#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "config.h"
#include "ev.h"
#include "omcproxy.h"
#include "proxy.h"

static int setup_proxy(char* spec) {
  struct proxy_config cfg;
  if (config_parse_proxy(spec, &cfg)) {
    return -EINVAL;
  }

  int uplink = (int)if_nametoindex(cfg.uplink);
  if (!uplink) {
    L_WARN("%s(%s): %s", __FUNCTION__, cfg.uplink, strerror(errno));
    return -errno;
  }

  int downlinks[CONFIG_MAX_DOWNLINKS];
  for (size_t i = 0; i < cfg.downlink_count; ++i) {
    downlinks[i] = (int)if_nametoindex(cfg.downlinks[i]);
    if (!downlinks[i]) {
      L_WARN("%s(%s): %s (%s)", __FUNCTION__, cfg.uplink, strerror(errno),
             cfg.downlinks[i]);
      return -errno;
    }
  }

  return proxy_set(uplink, downlinks, cfg.downlink_count, cfg.flags);
}

static struct ev_fd signal_fd;

static void handle_signalfd(struct ev_fd* efd, __unused uint32_t events) {
  struct signalfd_siginfo info;
  while (read(efd->fd, &info, sizeof(info)) == sizeof(info)) {
  }
  ev_break();
}

static void usage(const char* arg) {
  fprintf(
      stderr,
      "Usage: %s [options] <proxy1> [<proxy2>] [...]\n"
      "\nProxy examples:\n"
      "eth1,eth2\n"
      "eth1,eth2,eth3,scope=organization\n"
      "\nProxy options (each option may only occur once):\n"
      "	<interface>			interfaces to proxy (first is uplink)\n"
      "	scope=<scope>			minimum multicast scope to proxy\n"
      "		[global,organization,site,admin,realm] (default: global)\n"
      "\nOptions:\n"
      "	-v				verbose logging\n"
      "	-h				show this help\n",
      arg);
}

int main(int argc, char** argv) {
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  openlog("omcproxy", LOG_PERROR | LOG_PID, LOG_DAEMON);
  setlogmask(LOG_UPTO(L_LEVEL));

  if (getuid()) {
    L_ERR("must be run as root!");
    return 2;
  }

  if (ev_init()) {
    L_ERR("failed to initialize event loop: %s", strerror(errno));
    return 2;
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigprocmask(SIG_BLOCK, &mask, NULL);

  int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sfd < 0 || ev_fd_add(&signal_fd, sfd, EV_READ, handle_signalfd)) {
    L_ERR("failed to set up signal handling: %s", strerror(errno));
    return 2;
  }

  bool start = true;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-h")) {
      usage(argv[0]);
      return 0;
    } else if (!strncmp(argv[i], "-v", 2)) {
      const char* value = &argv[i][2];
      char* end = NULL;
      errno = 0;
      long parsed = strtol(value, &end, 10);
      int log_level = errno == 0 && end != value && *end == '\0' &&
                              parsed > 0 && parsed <= LOG_DEBUG
                          ? (int)parsed
                          : LOG_DEBUG;
      setlogmask(LOG_UPTO(log_level));
      continue;
    }

    if (setup_proxy(argv[i])) {
      fprintf(stderr, "failed to setup proxy: %s\n", argv[i]);
      start = false;
    }
  }

  if (argc < 2) {
    usage(argv[0]);
    start = false;
  }

  if (start) {
    ev_run();
  }

  proxy_update(true);
  proxy_flush();

  ev_fd_del(&signal_fd);
  close(sfd);
  ev_deinit();
  return start ? 0 : 1;
}
