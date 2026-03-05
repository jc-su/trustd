#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

STATE_FILE="${TRUSTD_STAGE_STATE_FILE:-/tmp/trustd-remediation-stage.env}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

write_state_var() {
  local key="$1"
  local value="$2"
  printf "%s=%q\n" "${key}" "${value}" >> "${STATE_FILE}"
}

save_state() {
  umask 000
  : > "${STATE_FILE}"
  write_state_var "TRUSTD_STAGE_TMP_DIR" "${TRUSTD_STAGE_TMP_DIR:-}"
  write_state_var "TRUSTD_STAGE_CONTAINER_NAME" "${TRUSTD_STAGE_CONTAINER_NAME:-}"
  write_state_var "TRUSTD_STAGE_CONTAINER_PID" "${TRUSTD_STAGE_CONTAINER_PID:-}"
  write_state_var "TRUSTD_STAGE_CGROUP_PATH" "${TRUSTD_STAGE_CGROUP_PATH:-}"
  write_state_var "TRUSTD_STAGE_RTMR_FILE" "${TRUSTD_STAGE_RTMR_FILE:-}"
  write_state_var "TRUSTD_STAGE_HEARTBEAT_FILE" "${TRUSTD_STAGE_HEARTBEAT_FILE:-}"
  write_state_var "TRUSTD_STAGE_DEMO_LOG" "${TRUSTD_STAGE_DEMO_LOG:-}"
  write_state_var "TRUSTD_STAGE_DEMO_PID" "${TRUSTD_STAGE_DEMO_PID:-}"
  write_state_var "TRUSTD_STAGE_HEARTBEAT_DAEMON_PID" "${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID:-}"
  write_state_var "TRUSTD_STAGE_HEARTBEAT_TIMEOUT" "${TRUSTD_STAGE_HEARTBEAT_TIMEOUT:-5}"
  write_state_var "TRUSTD_STAGE_HEARTBEAT_INTERVAL" "${TRUSTD_STAGE_HEARTBEAT_INTERVAL:-1}"
  write_state_var "TRUSTD_STAGE_MAX_RUNTIME" "${TRUSTD_STAGE_MAX_RUNTIME:-180}"
  write_state_var "TRUSTD_STAGE_REMEDIATION_MODE" "${TRUSTD_STAGE_REMEDIATION_MODE:-docker}"
  write_state_var "TRUSTD_STAGE_IMAGE" "${TRUSTD_STAGE_IMAGE:-alpine:3.20}"
  chmod 0666 "${STATE_FILE}" >/dev/null 2>&1 || true
}

load_state() {
  if [[ ! -f "${STATE_FILE}" ]]; then
    echo "state file not found: ${STATE_FILE}" >&2
    echo "run stage 01 first" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${STATE_FILE}"
}

write_rtmr_state() {
  local marker="$1"
  printf "%s\trtmr-1\tinit-1\t1\n# %s\n" \
    "${TRUSTD_STAGE_CGROUP_PATH}" "${marker}" > "${TRUSTD_STAGE_RTMR_FILE}"
}

write_heartbeat_pulse() {
  local marker="$1"
  printf "heartbeat=%s\n" "${marker}" > "${TRUSTD_STAGE_HEARTBEAT_FILE}"
}

container_restart_count() {
  docker inspect "${TRUSTD_STAGE_CONTAINER_NAME}" --format '{{.RestartCount}}'
}

heartbeat_daemon_alive() {
  [[ -n "${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID:-}" ]] && \
    kill -0 "${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID}" >/dev/null 2>&1
}

stop_heartbeat_daemon() {
  if heartbeat_daemon_alive; then
    kill "${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID}" >/dev/null 2>&1 || true
  fi
  TRUSTD_STAGE_HEARTBEAT_DAEMON_PID=""
}
