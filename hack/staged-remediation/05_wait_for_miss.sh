#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=./_common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_cmd docker
load_state

sleep_secs=$(( TRUSTD_STAGE_HEARTBEAT_TIMEOUT + 2 ))
before_restarts="$(container_restart_count)"
before_pid="${TRUSTD_STAGE_CONTAINER_PID}"

if heartbeat_daemon_alive; then
  echo "[stage 05] stopping auto-heartbeat daemon pid=${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID}"
  stop_heartbeat_daemon
  if ! save_state; then
    echo "[stage 05] warning: failed to persist heartbeat daemon state into ${STATE_FILE}" >&2
  fi
else
  echo "[stage 05] auto-heartbeat daemon already stopped"
fi

echo "[stage 05] wait for miss/remediation"
echo "waiting ${sleep_secs}s (timeout=${TRUSTD_STAGE_HEARTBEAT_TIMEOUT}s)"
sleep "${sleep_secs}"

after_restarts="$(container_restart_count)"
after_pid="$(docker inspect -f '{{.State.Pid}}' "${TRUSTD_STAGE_CONTAINER_NAME}")"

echo "[stage 05] restart_count before=${before_restarts} after=${after_restarts}"
echo "[stage 05] container_pid before=${before_pid} after=${after_pid}"
if [[ "${after_restarts}" != "${before_restarts}" ]]; then
  echo "[stage 05] restart_count changed: container restart observed"
else
  echo "[stage 05] restart_count unchanged"
fi
if [[ -n "${before_pid}" && -n "${after_pid}" && "${before_pid}" != "${after_pid}" ]]; then
  echo "[stage 05] pid changed: process reset observed"
else
  echo "[stage 05] pid unchanged"
fi

if grep -q "event kind=HeartbeatMiss" "${TRUSTD_STAGE_DEMO_LOG}"; then
  echo "[stage 05] heartbeat miss observed in demo log"
else
  echo "[stage 05] heartbeat miss not observed in demo log"
fi

if grep -q "remediation invoked: .*measurement_count=0" "${TRUSTD_STAGE_DEMO_LOG}"; then
  echo "[stage 05] logical reset observed (measurement_count=0 after remediation)"
else
  echo "[stage 05] logical reset marker not found in demo log"
fi

TRUSTD_STAGE_CONTAINER_PID="${after_pid}"
if ! save_state; then
  echo "[stage 05] warning: failed to persist updated PID into state file (${STATE_FILE})" >&2
fi

echo ""
echo "recent logs:"
tail -n 80 "${TRUSTD_STAGE_DEMO_LOG}" || true
echo ""
echo "next:"
echo "  ./hack/staged-remediation/04_status.sh"
echo "  ./hack/staged-remediation/99_cleanup.sh"
