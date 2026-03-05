#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TRUSTD_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="$(cd -- "${TRUSTD_DIR}/.." && pwd)"
KUBEVIRT_DIR="${ROOT_DIR}/kubevirt"

usage() {
  cat <<'EOF'
Usage:
  ./hack/run-remediation-cases.sh [--case heartbeat|attestation|all]

Cases:
  heartbeat    Run trustd staged demo and assert heartbeat-miss remediation.
  attestation  Run kubevirt collector tests for attestation-fail remediation paths.
  all          Run both cases (default).

Environment:
  TRUSTD_HEARTBEAT_TIMEOUT_SECONDS   Override heartbeat timeout for heartbeat case.
  TRUSTD_DEMO_MAX_RUNTIME_SECONDS    Override demo max runtime for heartbeat case.
  TRUSTD_DEMO_IMAGE                  Override demo container image (default alpine:3.20).
EOF
}

case_name="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --case" >&2
        usage
        exit 2
      fi
      case_name="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "${case_name}" in
  heartbeat|attestation|all)
    ;;
  *)
    echo "invalid case: ${case_name}" >&2
    usage
    exit 2
    ;;
esac

run_heartbeat_case() {
  if ! docker info >/dev/null 2>&1; then
    echo "[case heartbeat] docker is not reachable for current user" >&2
    echo "[case heartbeat] fix by running with docker permission (or sudo) and rerun" >&2
    return 1
  fi

  local state_file
  state_file="$(mktemp /tmp/trustd-remediation-stage.XXXXXX.env)"
  local output_file
  output_file="$(mktemp /tmp/trustd-remediation-heartbeat.XXXXXX.log)"
  local run_status=0
  local verify_status=0

  echo "[case heartbeat] start"
  set +e
  (
    cd "${TRUSTD_DIR}"
    rm -f "${state_file}"
    TRUSTD_STAGE_STATE_FILE="${state_file}" ./hack/staged-remediation/01_setup.sh
    TRUSTD_STAGE_STATE_FILE="${state_file}" ./hack/staged-remediation/02_start_demo.sh
    TRUSTD_STAGE_STATE_FILE="${state_file}" ./hack/staged-remediation/03_trigger_heartbeat_loss.sh
    TRUSTD_STAGE_STATE_FILE="${state_file}" ./hack/staged-remediation/05_wait_for_miss.sh
  ) >"${output_file}" 2>&1
  run_status=$?
  set -e
  cat "${output_file}"

  if [[ "${run_status}" -eq 0 ]]; then
    if ! grep -q "heartbeat miss observed in demo log" "${output_file}"; then
      echo "[case heartbeat] expected heartbeat miss marker not found" >&2
      verify_status=1
    fi

    if ! grep -Eq "restart_count changed: container restart observed|pid changed: process reset observed" "${output_file}"; then
      echo "[case heartbeat] expected physical remediation marker not found" >&2
      verify_status=1
    fi

    if ! grep -q "logical reset observed (measurement_count=0 after remediation)" "${output_file}"; then
      echo "[case heartbeat] expected logical reset marker not found" >&2
      verify_status=1
    fi
  else
    echo "[case heartbeat] staged run failed before verification checks" >&2
  fi

  (
    cd "${TRUSTD_DIR}"
    TRUSTD_STAGE_STATE_FILE="${state_file}" ./hack/staged-remediation/99_cleanup.sh >/dev/null 2>&1 || true
  )
  rm -f "${state_file}" "${output_file}"

  if [[ "${run_status}" -ne 0 || "${verify_status}" -ne 0 ]]; then
    echo "[case heartbeat] FAIL" >&2
    return 1
  fi

  echo "[case heartbeat] PASS"
  return 0
}

run_attestation_case() {
  echo "[case attestation] start"
  (
    cd "${KUBEVIRT_DIR}"
    ./hack/run-trustd-remediation-attestation-tests.sh
  )
  echo "[case attestation] PASS"
}

failed=0

if [[ "${case_name}" == "heartbeat" || "${case_name}" == "all" ]]; then
  if ! run_heartbeat_case; then
    failed=1
  fi
fi

if [[ "${case_name}" == "attestation" || "${case_name}" == "all" ]]; then
  if ! run_attestation_case; then
    failed=1
  fi
fi

if [[ "${failed}" -ne 0 ]]; then
  echo "[summary] remediation case checks failed" >&2
  exit 1
fi

echo "[summary] all selected remediation case checks passed"
