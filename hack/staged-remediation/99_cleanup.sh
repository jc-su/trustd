#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=./_common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

require_cmd docker
load_state

echo "[stage 99] cleanup"

if [[ -n "${TRUSTD_STAGE_DEMO_PID:-}" ]] && kill -0 "${TRUSTD_STAGE_DEMO_PID}" >/dev/null 2>&1; then
  kill "${TRUSTD_STAGE_DEMO_PID}" >/dev/null 2>&1 || true
  wait "${TRUSTD_STAGE_DEMO_PID}" >/dev/null 2>&1 || true
fi

stop_heartbeat_daemon || true
docker rm -f "${TRUSTD_STAGE_CONTAINER_NAME}" >/dev/null 2>&1 || true
rm -rf "${TRUSTD_STAGE_TMP_DIR}" >/dev/null 2>&1 || true
rm -f "${STATE_FILE}" >/dev/null 2>&1 || true

echo "[stage 99] done"
