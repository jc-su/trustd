#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=./_common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_cmd docker
require_cmd awk
require_cmd mktemp

TRUSTD_STAGE_IMAGE="${TRUSTD_DEMO_IMAGE:-alpine:3.20}"
TRUSTD_STAGE_HEARTBEAT_TIMEOUT="${TRUSTD_HEARTBEAT_TIMEOUT_SECONDS:-5}"
TRUSTD_STAGE_HEARTBEAT_INTERVAL="${TRUSTD_HEARTBEAT_INTERVAL_SECONDS:-1}"
TRUSTD_STAGE_MAX_RUNTIME="${TRUSTD_DEMO_MAX_RUNTIME_SECONDS:-180}"
TRUSTD_STAGE_REMEDIATION_MODE="${TRUSTD_DEMO_REMEDIATION_MODE:-docker}"

TRUSTD_STAGE_CONTAINER_NAME="trustd-remediation-stage-$(date +%s)"
TRUSTD_STAGE_TMP_DIR="$(mktemp -d)"
TRUSTD_STAGE_RTMR_FILE="${TRUSTD_STAGE_TMP_DIR}/container_rtmr"
TRUSTD_STAGE_HEARTBEAT_FILE="${TRUSTD_STAGE_TMP_DIR}/container_heartbeat"
TRUSTD_STAGE_DEMO_LOG="${TRUSTD_STAGE_TMP_DIR}/demo.log"
TRUSTD_STAGE_DEMO_PID=""
TRUSTD_STAGE_HEARTBEAT_DAEMON_PID=""

echo "[stage 01] create container: ${TRUSTD_STAGE_CONTAINER_NAME} (${TRUSTD_STAGE_IMAGE})"
docker run -d --name "${TRUSTD_STAGE_CONTAINER_NAME}" --restart unless-stopped "${TRUSTD_STAGE_IMAGE}" \
  sh -c 'trap "exit 0" TERM INT; while true; do sleep 1; done' >/dev/null

TRUSTD_STAGE_CONTAINER_PID="$(docker inspect -f '{{.State.Pid}}' "${TRUSTD_STAGE_CONTAINER_NAME}")"
if [[ -z "${TRUSTD_STAGE_CONTAINER_PID}" || "${TRUSTD_STAGE_CONTAINER_PID}" == "0" ]]; then
  echo "[stage 01] failed to resolve container PID" >&2
  exit 1
fi

TRUSTD_STAGE_CGROUP_PATH="$(
  awk -F: '
    $1 == "0" { print $3; found=1; exit }
    END { if (!found) exit 1 }
  ' "/proc/${TRUSTD_STAGE_CONTAINER_PID}/cgroup" 2>/dev/null || true
)"
if [[ -z "${TRUSTD_STAGE_CGROUP_PATH}" ]]; then
  TRUSTD_STAGE_CGROUP_PATH="$(awk -F: 'NR==1 {print $3}' "/proc/${TRUSTD_STAGE_CONTAINER_PID}/cgroup" 2>/dev/null || true)"
fi
if [[ -z "${TRUSTD_STAGE_CGROUP_PATH}" ]]; then
  echo "[stage 01] failed to resolve cgroup path from /proc/${TRUSTD_STAGE_CONTAINER_PID}/cgroup" >&2
  exit 1
fi

if [[ "${TRUSTD_STAGE_REMEDIATION_MODE}" == "signal" ]]; then
  if [[ ! -f "/sys/fs/cgroup${TRUSTD_STAGE_CGROUP_PATH}/cgroup.procs" && ! -f "/sys/fs/cgroup${TRUSTD_STAGE_CGROUP_PATH}/tasks" ]]; then
    echo "[stage 01] cgroup process file not found under /sys/fs/cgroup${TRUSTD_STAGE_CGROUP_PATH}" >&2
    echo "[stage 01] signal-mode remediation likely unavailable on this host" >&2
    exit 1
  fi
fi

write_rtmr_state "seed"
write_heartbeat_pulse "seed"
save_state

echo "[stage 01] done"
echo "state_file=${STATE_FILE}"
echo "container_name=${TRUSTD_STAGE_CONTAINER_NAME}"
echo "container_pid=${TRUSTD_STAGE_CONTAINER_PID}"
echo "cgroup_path=${TRUSTD_STAGE_CGROUP_PATH}"
echo "rtmr_file=${TRUSTD_STAGE_RTMR_FILE}"
echo "heartbeat_file=${TRUSTD_STAGE_HEARTBEAT_FILE}"
echo "heartbeat_interval=${TRUSTD_STAGE_HEARTBEAT_INTERVAL}s"
echo "demo_log=${TRUSTD_STAGE_DEMO_LOG}"
echo ""
echo "next: ./hack/staged-remediation/02_start_demo.sh"
