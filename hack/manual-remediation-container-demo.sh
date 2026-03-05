#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

CONTAINER_IMAGE="${TRUSTD_DEMO_IMAGE:-alpine:3.20}"
CONTAINER_NAME="trustd-remediation-demo-$(date +%s)"
HEARTBEAT_TIMEOUT="${TRUSTD_HEARTBEAT_TIMEOUT_SECONDS:-5}"
MAX_RUNTIME="${TRUSTD_DEMO_MAX_RUNTIME_SECONDS:-180}"
REMEDIATION_MODE="${TRUSTD_DEMO_REMEDIATION_MODE:-docker}"

TMP_DIR="$(mktemp -d)"
RTMR_FILE="${TMP_DIR}/container_rtmr"
HEARTBEAT_FILE="${TMP_DIR}/container_heartbeat"
ENV_FILE="${TMP_DIR}/demo.env"
DEMO_PID=""
CONTAINER_STARTED=0

cleanup() {
  set +e
  if [[ -n "${DEMO_PID}" ]] && kill -0 "${DEMO_PID}" >/dev/null 2>&1; then
    kill "${DEMO_PID}" >/dev/null 2>&1 || true
    wait "${DEMO_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${CONTAINER_STARTED}" -eq 1 ]]; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require docker
require awk
require cargo

echo "[demo] starting container ${CONTAINER_NAME} (${CONTAINER_IMAGE})"
docker run -d --name "${CONTAINER_NAME}" --restart unless-stopped "${CONTAINER_IMAGE}" \
  sh -c 'trap "exit 0" TERM INT; while true; do sleep 1; done' >/dev/null
CONTAINER_STARTED=1

container_pid="$(docker inspect -f '{{.State.Pid}}' "${CONTAINER_NAME}")"
if [[ -z "${container_pid}" || "${container_pid}" == "0" ]]; then
  echo "[demo] failed to resolve container PID" >&2
  exit 1
fi

cgroup_path="$(
  awk -F: '
    $1 == "0" { print $3; found=1; exit }
    END { if (!found) exit 1 }
  ' "/proc/${container_pid}/cgroup" 2>/dev/null || true
)"
if [[ -z "${cgroup_path}" ]]; then
  cgroup_path="$(awk -F: 'NR==1 {print $3}' "/proc/${container_pid}/cgroup" 2>/dev/null || true)"
fi
if [[ -z "${cgroup_path}" ]]; then
  echo "[demo] failed to resolve cgroup path from /proc/${container_pid}/cgroup" >&2
  exit 1
fi

if [[ "${REMEDIATION_MODE}" == "signal" ]]; then
  if [[ ! -f "/sys/fs/cgroup${cgroup_path}/cgroup.procs" && ! -f "/sys/fs/cgroup${cgroup_path}/tasks" ]]; then
    echo "[demo] cgroup process file not found under /sys/fs/cgroup${cgroup_path}" >&2
    echo "[demo] remediation signal path likely unavailable on this host" >&2
    exit 1
  fi
fi

write_state() {
  local marker="$1"
  printf "%s\trtmr-1\tinit-1\t1\n# %s\n" "${cgroup_path}" "${marker}" > "${RTMR_FILE}"
}

write_state "seed"
printf "heartbeat=seed\n" > "${HEARTBEAT_FILE}"

cat > "${ENV_FILE}" <<EOF
export TRUSTD_DEMO_CONTAINER_NAME='${CONTAINER_NAME}'
export TRUSTD_DEMO_CGROUP_PATH='${cgroup_path}'
export TRUSTD_DEMO_RTMR_FILE='${RTMR_FILE}'
export TRUSTD_DEMO_HEARTBEAT_FILE='${HEARTBEAT_FILE}'
heartbeat_once() {
  printf "heartbeat=hb-\$(date +%s%N)\\n" > "\${TRUSTD_DEMO_HEARTBEAT_FILE}"
}
EOF

echo "[demo] container_name=${CONTAINER_NAME}"
echo "[demo] container_pid=${container_pid}"
echo "[demo] cgroup_path=${cgroup_path}"
echo "[demo] fake_rtmr_file=${RTMR_FILE}"
echo "[demo] fake_heartbeat_file=${HEARTBEAT_FILE}"
echo "[demo] helper_env=${ENV_FILE}"
echo "[demo] remediation_mode=${REMEDIATION_MODE}"
echo ""
echo "[demo] in another terminal:"
echo "  source '${ENV_FILE}'"
echo "  heartbeat_once"
echo "  heartbeat_once"
echo "  # then stop heartbeats and wait > ${HEARTBEAT_TIMEOUT}s"
echo ""
echo "[demo] optional watcher commands:"
echo "  docker inspect '${CONTAINER_NAME}' --format 'status={{.State.Status}} restarts={{.RestartCount}} pid={{.State.Pid}}'"
echo "  docker ps -a --filter name='${CONTAINER_NAME}'"
echo ""

(
  cd "${ROOT_DIR}"
  cargo run --example non_tdx_remediation_demo -- \
    --rtmr-path "${RTMR_FILE}" \
    --heartbeat-path "${HEARTBEAT_FILE}" \
    --cgroup-path "${cgroup_path}" \
    --container-name "${CONTAINER_NAME}" \
    --remediation-mode "${REMEDIATION_MODE}" \
    --heartbeat-timeout-seconds "${HEARTBEAT_TIMEOUT}" \
    --max-runtime-seconds "${MAX_RUNTIME}"
) &
DEMO_PID="$!"

wait "${DEMO_PID}"
DEMO_PID=""

echo "[demo] demo process finished, inspecting container restart state"
docker inspect "${CONTAINER_NAME}" \
  --format 'status={{.State.Status}} restarts={{.RestartCount}} pid={{.State.Pid}}'
