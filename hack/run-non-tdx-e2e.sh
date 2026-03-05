#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${TRUSTD_E2E_IMAGE:-rust:1.86-bookworm}"

echo "[non-tdx-e2e] running trustd monitor/remediation test in docker image: ${IMAGE}"
docker run --rm \
  -v "${ROOT_DIR}:/workspace" \
  -w /workspace \
  "${IMAGE}" \
  bash -lc "cargo test --test non_tdx_monitor_remediation_e2e -- --nocapture"
