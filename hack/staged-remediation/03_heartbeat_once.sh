#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "[stage 03] manual heartbeat pulse mode was replaced by auto-heartbeat."
echo "[stage 03] redirecting to trigger heartbeat loss."
exec "${SCRIPT_DIR}/03_trigger_heartbeat_loss.sh"
