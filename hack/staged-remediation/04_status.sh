#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=./_common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_cmd docker
load_state

echo "[stage 04] current status"
echo "state_file=${STATE_FILE}"
echo "container_name=${TRUSTD_STAGE_CONTAINER_NAME}"
echo "demo_pid=${TRUSTD_STAGE_DEMO_PID:-}"
echo "heartbeat_daemon_pid=${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID:-}"
if heartbeat_daemon_alive; then
  echo "heartbeat_daemon_state=running"
else
  echo "heartbeat_daemon_state=stopped"
fi
echo "rtmr_file=${TRUSTD_STAGE_RTMR_FILE}"
echo "heartbeat_file=${TRUSTD_STAGE_HEARTBEAT_FILE}"
echo "log_file=${TRUSTD_STAGE_DEMO_LOG}"
echo ""
docker inspect "${TRUSTD_STAGE_CONTAINER_NAME}" \
  --format 'status={{.State.Status}} restarts={{.RestartCount}} pid={{.State.Pid}}'
echo ""
echo "last demo logs:"
tail -n 40 "${TRUSTD_STAGE_DEMO_LOG}" || true
