#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=./_common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

load_state

if heartbeat_daemon_alive; then
  echo "[stage 03] stopping auto-heartbeat daemon pid=${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID}"
  stop_heartbeat_daemon
else
  echo "[stage 03] auto-heartbeat daemon already stopped"
fi

if ! save_state; then
  echo "[stage 03] warning: failed to persist heartbeat daemon state into ${STATE_FILE}" >&2
fi

echo "[stage 03] heartbeat loss triggered"
echo ""
echo "next:"
echo "  ./hack/staged-remediation/05_wait_for_miss.sh"
