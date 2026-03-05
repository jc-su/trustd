# trustd

In-guest attestation component for TDX CVMs.

This replaces the legacy `cvm-agent` path.

## Design

- `src/securityfs.rs`: kernel securityfs adapter (`container_attest`, `container_rtmr`) with parser-focused unit tests.
- `src/tdquote.rs`: TSM quote adapter (`inblob`/`outblob`) with strict input validation.
- `src/remediation.rs`: in-guest cgroup restart primitive (`SIGTERM` with `SIGKILL` fallback) used for remediation.
- `src/state.rs`: thread-safe container state cache and liveness heartbeat monitor settings.
- `src/event_bus.rs`: broadcast event fan-out used by gRPC streaming.
- `src/liveness.rs`: optional trustd-local liveness probe loop (`cgroup.procs/tasks`) that can emit heartbeats without external reporters.
- `src/service.rs`: tonic gRPC service implementation mapped from `proto/v1/trustd.proto`.
- `src/watcher.rs`: event-driven watcher loop (`poll` + diffing) that updates RTMR state and emits measurement lifecycle events.
- `src/main.rs`: runtime wiring, signal handling, and gRPC-over-vsock serve path.

## Integration Notes

- Transport is `gRPC-over-vsock` only (no TCP listener).
- Expected host-side client is `kubevirt/pkg/virt-handler/trustd`.
- Includes `RestartContainer` RPC for host-triggered remediation without kernel interface changes.

## Remediation Flow

1. `virt-handler` receives `UNTRUSTED`/`STALE` verifier verdict.
2. `virt-handler` calls `trustd.RestartContainer(cgroup_path)`.
3. `trustd` performs logical reset first (`rtmr3/initial_rtmr3/count/liveness-heartbeat` cleared, `pending_rebootstrap=true`).
4. `trustd` emits remediation lifecycle events via watch stream:
   - `remediation_begin`
   - `remediation_done` or `remediation_failed`
5. `trustd` signals processes in that cgroup (`SIGTERM` + `SIGKILL` fallback).
6. container runtime recreates container; kernel emits fresh measurement event.
7. collector re-attests and only clears pending rebootstrap on a fresh `TRUSTED` verdict.

KubeVirt knobs (virt-handler env):

- `TRUSTFNCALL_REMEDIATE_ON_UNTRUSTED=none|alert|restart|kill` (fallback only when verifier does not return a policy action)
- `TRUSTFNCALL_REMEDIATE_ON_STALE=none|alert|restart|kill` (fallback only when verifier does not return a policy action)
- `TRUSTFNCALL_REMEDIATION_COOLDOWN_SECONDS=<positive-int>`

## Build and Test

```bash
cargo test --lib
cargo test --test non_tdx_monitor_remediation_e2e -- --nocapture
cargo clippy --all-targets -- -D warnings
```

### Non-TDX End-to-End Test

`trustd` can be validated on a normal (non-TDX) developer machine with a userspace RTMR fixture and fake quote provider.

- Test file: `tests/non_tdx_monitor_remediation_e2e.rs`
- Coverage:
  - watcher state sync from userspace RTMR file
  - heartbeat monitor start/heartbeat miss event flow
  - explicit liveness heartbeat reporting flow
  - remediation trigger via `RestartContainer`

Run locally:

```bash
cargo test --test non_tdx_monitor_remediation_e2e -- --nocapture
```

Run in Docker:

```bash
./hack/run-non-tdx-e2e.sh
```

### Manual Container Remediation Demo

You can run a manual end-to-end demo with a real Docker container plus:
- a fake userspace RTMR source (integrity/measurement channel)
- a fake heartbeat file source (liveness channel)

```bash
./hack/manual-remediation-container-demo.sh
```

What it does:
- creates a temporary container (`alpine`) with restart policy
- resolves its real host cgroup path
- starts `examples/non_tdx_remediation_demo.rs` (watcher + heartbeat monitor + remediation)
- asks you to manually pulse the fake heartbeat source (`heartbeat_once`) a few times
- after you stop heartbeats, a heartbeat miss triggers `RestartContainer` remediation

The script prints a temporary `demo.env` file path with helper function:
- `source <demo.env>`
- `heartbeat_once` to simulate one liveness heartbeat update

By default this demo uses `--remediation-mode docker` (non-root friendly).
If you want kernel-style cgroup signaling instead, use:

```bash
TRUSTD_DEMO_REMEDIATION_MODE=signal ./hack/manual-remediation-container-demo.sh
```

### Staged Manual Demo (Step-by-Step)

If you want to inspect each stage output separately, use the staged scripts:

```bash
./hack/staged-remediation/01_setup.sh
./hack/staged-remediation/02_start_demo.sh
./hack/staged-remediation/03_trigger_heartbeat_loss.sh
./hack/staged-remediation/04_status.sh
./hack/staged-remediation/05_wait_for_miss.sh
./hack/staged-remediation/99_cleanup.sh
```

Notes:
- Auto-heartbeat runs after stage 02; no manual pulse is required.
- Use stage 03 to explicitly trigger heartbeat loss, or run stage 05 (which also stops auto-heartbeat first).
- Shared state is persisted in `TRUSTD_STAGE_STATE_FILE` (default: `/tmp/trustd-remediation-stage.env`).
- You can inspect logs any time with `./hack/staged-remediation/04_status.sh`.
- `03_heartbeat_once.sh` remains as a compatibility alias and now redirects to trigger heartbeat loss.
- For the real trustd signal path, run with:
  `TRUSTD_DEMO_REMEDIATION_MODE=signal`
  and use sufficient privileges (often `sudo`) so cgroup PID signals are allowed.
- If `sudo` loses your Cargo env, build once as your user then run stage 02 with binary:
  `cargo build --example non_tdx_remediation_demo`
  `sudo TRUSTD_DEMO_REMEDIATION_MODE=signal TRUSTD_DEMO_BINARY=/home/jcsu/Dev/tee-mcp/trustd/target/debug/examples/non_tdx_remediation_demo ./hack/staged-remediation/02_start_demo.sh`
- If you previously created the state file with restrictive perms, reset it:
  `rm -f /tmp/trustd-remediation-stage.env` then rerun `01_setup.sh`.

## Run

```bash
cargo run -- --vsock-port 1235
```

### Optional: Trustd-Local Heartbeat Mode

If you run trustd without kubevirt heartbeat injection, enable internal liveness probing:

```bash
cargo run -- \
  --self-heartbeat-enabled \
  --self-heartbeat-auto-monitor \
  --self-heartbeat-interval-seconds 5 \
  --self-heartbeat-timeout-seconds 15
```

Behavior:
- trustd probes `/sys/fs/cgroup/<cgroup>/cgroup.procs` (fallback `tasks`) for each tracked container.
- when processes are present, trustd records heartbeat and emits `Heartbeat` events itself.
- if heartbeats stop and monitor timeout elapses, `HeartbeatMiss` still fires as before.

Notes:
- External `ReportHeartbeat` is still supported and can coexist.
- In kubevirt deployments, keep collector heartbeat enabled unless you intentionally switch to trustd-local mode.

### Unified Remediation Case Checks

To validate both remediation-trigger paths with one entrypoint:

```bash
cd /home/jcsu/Dev/tee-mcp/trustd
./hack/run-remediation-cases.sh --case heartbeat
./hack/run-remediation-cases.sh --case attestation
./hack/run-remediation-cases.sh --case all
```

`--case heartbeat`:
- runs staged trustd demo
- asserts `HeartbeatMiss`
- asserts logical reset marker
- asserts restart/PID-change remediation marker
- requires Docker access for the current user (or equivalent sudo setup)

`--case attestation`:
- runs kubevirt collector tests that cover
  - untrusted verifier verdict -> remediation request
  - fail-closed after remediation when re-attestation fails

Compatibility script names:
- canonical: `/home/jcsu/Dev/tee-mcp/kubevirt/hack/run-trustd-remediation-attestation-tests.sh`
- legacy alias: `/home/jcsu/Dev/tee-mcp/kubevirt/hack/run-trustd-attestation-fail-tests.sh`
