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

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <net/if.h>
#include <sstream>
#include <unistd.h>

#include <libubox/uloop.h>
#include <string>
#include <vector>

#include "omcproxy.h"
#include "proxy.h"

long log_level = LOG_WARNING;

class Proxy {
 private:
  unsigned int uplink{};
  std::vector<unsigned int> downlinks;
  ProxyScope scope;

 public:
  Proxy() : scope(PROXY_GLOBAL) {}

  [[nodiscard]] unsigned int HasUplink() const { return uplink != 0; }

  void SetUplink(const std::string& src) {
    uplink = if_nametoindex(src.c_str());
    if (!uplink) {
      throw std::invalid_argument("invalid uplink interface '" + src +
                                  "': " + strerror(errno));
    }
  }

  void SetScope(const std::string& scope_str) {
    if (scope_str == "global") {
      scope = PROXY_GLOBAL;
    } else if (scope_str == "organization") {
      scope = PROXY_ORGLOCAL;
    } else if (scope_str == "site") {
      scope = PROXY_SITELOCAL;
    } else if (scope_str == "admin") {
      scope = PROXY_ADMINLOCAL;
    } else if (scope_str == "realm") {
      scope = PROXY_REALMLOCAL;
    } else {
      throw std::invalid_argument("invalid scope '" + scope_str + "'");
    }
  }

  void AddDownlink(const std::string& dst) {
    unsigned int downlink = if_nametoindex(dst.c_str());
    if (!downlink) {
      throw std::invalid_argument("invalid downlink interface '" + dst +
                                  "': " + strerror(errno));
    }
    downlinks.push_back(downlink);
    if (downlinks.size() > 32) {
      throw std::invalid_argument("maximum number of destinations exceeded");
    }
  }

  void SetProxy() {
    if (proxy_set(uplink, downlinks.data(), downlinks.size(), ProxyFlags(scope)) != 0) {
      throw std::runtime_error(std::string("failed to set proxy: ") + strerror(errno));
    }
  }
};

omcp_time_t omcp_time() {
  struct timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((omcp_time_t)ts.tv_sec * OMCP_TIME_PER_SECOND) +
         ((omcp_time_t)ts.tv_nsec / (1000000000 / OMCP_TIME_PER_SECOND));
}

static void handle_signal(__attribute__((unused)) int signal) {
  uloop_end();
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
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  openlog("omcproxy", LOG_PERROR, LOG_DAEMON);

  if (getuid()) {
    std::cerr << "must be run as root!" << std::endl;
    return 2;
  }

  uloop_init();
  bool start = true;

  for (ssize_t i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "-h") {
      usage(argv[0]);
      return 1;
    }

    if (std::string(argv[i]).substr(0, 2) == "-v") {
      try {
        log_level = std::stoi(std::string(argv[i]).substr(2));
        if (log_level <= 0) {
          usage(argv[0]);
          return 1;
        }
        log_level = (log_level > 7) ? 7 : log_level;
      } catch (const std::exception& e) {
        usage(argv[0]);
        return 1;
      }
      continue;
    }

    std::string arg(argv[i]);
    std::istringstream iss(arg);
    std::string token;
    try {
      Proxy proxy;
      while (std::getline(iss, token, ',')) {
        if (token.find("scope=") == 0) {
          proxy.SetScope(token.substr(6));
        } else if (!proxy.HasUplink()) {
          proxy.SetUplink(token);
        } else {
          proxy.AddDownlink(token);
        }
      }
      proxy.SetProxy();
    } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
      start = false;
    }
  }

  if (argc < 2) {
    usage(argv[0]);
    start = false;
  }

  if (start) {
    uloop_run();
  }

  proxy_update(true);
  proxy_flush();

  uloop_done();
  return 0;
}
