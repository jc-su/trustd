#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=./_common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

load_state

demo_running=0
if [[ -n "${TRUSTD_STAGE_DEMO_PID:-}" ]] && kill -0 "${TRUSTD_STAGE_DEMO_PID}" >/dev/null 2>&1; then
  demo_running=1
  echo "[stage 02] demo already running with pid=${TRUSTD_STAGE_DEMO_PID}"
fi

demo_cmd=()
if [[ -n "${TRUSTD_DEMO_BINARY:-}" ]]; then
  if [[ ! -x "${TRUSTD_DEMO_BINARY}" ]]; then
    echo "[stage 02] TRUSTD_DEMO_BINARY is not executable: ${TRUSTD_DEMO_BINARY}" >&2
    exit 1
  fi
  demo_cmd=("${TRUSTD_DEMO_BINARY}")
elif command -v cargo >/dev/null 2>&1; then
  demo_cmd=("cargo" "run" "--example" "non_tdx_remediation_demo" "--")
else
  fallback_bin="${ROOT_DIR}/target/debug/examples/non_tdx_remediation_demo"
  if [[ -x "${fallback_bin}" ]]; then
    demo_cmd=("${fallback_bin}")
  else
    echo "[stage 02] cargo not found and fallback binary missing: ${fallback_bin}" >&2
    echo "[stage 02] build once as normal user:" >&2
    echo "  cargo build --example non_tdx_remediation_demo" >&2
    exit 1
  fi
fi

if [[ "${demo_running}" -eq 0 ]]; then
  echo "[stage 02] start demo process"
  (
    cd "${ROOT_DIR}"
    "${demo_cmd[@]}" \
      --rtmr-path "${TRUSTD_STAGE_RTMR_FILE}" \
      --heartbeat-path "${TRUSTD_STAGE_HEARTBEAT_FILE}" \
      --cgroup-path "${TRUSTD_STAGE_CGROUP_PATH}" \
      --container-name "${TRUSTD_STAGE_CONTAINER_NAME}" \
      --remediation-mode "${TRUSTD_STAGE_REMEDIATION_MODE}" \
      --heartbeat-timeout-seconds "${TRUSTD_STAGE_HEARTBEAT_TIMEOUT}" \
      --max-runtime-seconds "${TRUSTD_STAGE_MAX_RUNTIME}" \
      > "${TRUSTD_STAGE_DEMO_LOG}" 2>&1
  ) &
  TRUSTD_STAGE_DEMO_PID="$!"
fi

if heartbeat_daemon_alive; then
  echo "[stage 02] auto-heartbeat daemon already running with pid=${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID}"
else
  echo "[stage 02] start auto-heartbeat daemon (interval=${TRUSTD_STAGE_HEARTBEAT_INTERVAL}s)"
  (
    while true; do
      status="$(docker inspect -f '{{.State.Status}}' "${TRUSTD_STAGE_CONTAINER_NAME}" 2>/dev/null || true)"
      if [[ "${status}" == "running" ]]; then
        write_heartbeat_pulse "auto-$(date +%s%N)"
      fi
      sleep "${TRUSTD_STAGE_HEARTBEAT_INTERVAL}"
    done
  ) >/dev/null 2>&1 &
  TRUSTD_STAGE_HEARTBEAT_DAEMON_PID="$!"
fi

if ! save_state; then
  echo "[stage 02] warning: failed to persist process IDs into state file (${STATE_FILE})" >&2
fi

echo "[stage 02] demo_pid=${TRUSTD_STAGE_DEMO_PID:-}"
echo "[stage 02] heartbeat_daemon_pid=${TRUSTD_STAGE_HEARTBEAT_DAEMON_PID:-}"
echo "[stage 02] log_file=${TRUSTD_STAGE_DEMO_LOG}"
echo ""
echo "tail logs:"
echo "  tail -f '${TRUSTD_STAGE_DEMO_LOG}'"
echo ""
echo "next:"
echo "  ./hack/staged-remediation/03_trigger_heartbeat_loss.sh"
echo "  ./hack/staged-remediation/04_status.sh"
