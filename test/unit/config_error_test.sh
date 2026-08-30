#!/bin/sh
set -u

omcproxy="${1:?usage: config_error_test.sh <path-to-omcproxy>}"

if ! unshare -r true 2>/dev/null; then
  echo "skip: unprivileged user namespaces unavailable"
  exit 77
fi

if unshare -r "$omcproxy" nosuchif0,nosuchif1 2>/dev/null; then
  echo "fail: invalid proxy config exited zero"
  exit 1
fi

if unshare -r "$omcproxy" 2>/dev/null; then
  echo "fail: missing arguments exited zero"
  exit 1
fi

echo "ok: config errors exit nonzero"
exit 0
