use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::securityfs::{DEFAULT_ATTEST_PATH, DEFAULT_RTMR_PATH};
use crate::tdquote::DEFAULT_TSM_BASE_PATH;

/// Controls how aggressively trustd drives the measurement + remediation
/// loop. Orthogonal to the AttestWorkload RPC,
/// which always work regardless of mode.
///
/// Canonical use:
///   - `Off`: experiments and cost-of-lifecycle benchmarks. trustd only
///     runs the container lifecycle (StartContainer/StopContainer) and
///     responds to attestation RPCs when asked. No self-driven watcher,
///     no remediation. Matches the "non-attested lifecycle" baseline.
///   - `Observe`: watcher is active and publishes measurement events to
///     the EventBus for external subscribers (e.g., the host-side
///     verifier's watcher can pull this). Remediation actions are
///     suppressed so benchmarks do not kill containers mid-run.
///   - `Enforce`: full pipeline — watcher + remediation policy in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MeasurementMode {
    Off,
    Observe,
    Enforce,
}

impl MeasurementMode {
    pub fn watcher_enabled(self) -> bool {
        !matches!(self, MeasurementMode::Off)
    }

    pub fn remediation_enabled(self) -> bool {
        matches!(self, MeasurementMode::Enforce)
    }
}

pub const DEFAULT_VSOCK_PORT: u32 = 1235;
pub const DEFAULT_POLL_TIMEOUT_MS: i32 = 30_000;
pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/run/trustd.sock";
pub const DEFAULT_CGROUP_ROOT_PATH: &str = "/sys/fs/cgroup";
pub const DEFAULT_SELF_HEARTBEAT_INTERVAL_SECONDS: u64 = 10;
pub const DEFAULT_SELF_HEARTBEAT_TIMEOUT_SECONDS: u32 = 90;

#[derive(Debug, Clone, Parser)]
#[command(name = "trustd", about = "TrustFnCall in-guest trust daemon")]
pub struct Config {
    /// AF_VSOCK port used by trustd.
    #[arg(long, default_value_t = DEFAULT_VSOCK_PORT)]
    pub vsock_port: u32,

    /// Unix socket path for in-VM clients (e.g. MCP Server).
    #[arg(long, default_value = DEFAULT_UNIX_SOCKET_PATH)]
    pub unix_socket_path: PathBuf,

    /// Path to securityfs container_attest file.
    #[arg(long, default_value = DEFAULT_ATTEST_PATH)]
    pub attest_path: PathBuf,

    /// Path to securityfs container_rtmr file.
    #[arg(long, default_value = DEFAULT_RTMR_PATH)]
    pub rtmr_path: PathBuf,

    /// Path to TSM configfs base.
    #[arg(long, default_value = DEFAULT_TSM_BASE_PATH)]
    pub tsm_path: PathBuf,

    /// poll(2) timeout in milliseconds; 0 or negative means wait forever.
    #[arg(long, default_value_t = DEFAULT_POLL_TIMEOUT_MS)]
    pub poll_timeout_ms: i32,

    /// Enable internal cgroup-process-based heartbeat generation in trustd.
    #[arg(long, default_value_t = false)]
    pub self_heartbeat_enabled: bool,

    /// Internal heartbeat scan interval in seconds when self heartbeat is enabled.
    #[arg(long, default_value_t = DEFAULT_SELF_HEARTBEAT_INTERVAL_SECONDS)]
    pub self_heartbeat_interval_seconds: u64,

    /// Automatically enable heartbeat monitoring for newly tracked containers.
    #[arg(long, default_value_t = false)]
    pub self_heartbeat_auto_monitor: bool,

    /// Heartbeat timeout to use when auto-monitor is enabled.
    #[arg(long, default_value_t = DEFAULT_SELF_HEARTBEAT_TIMEOUT_SECONDS)]
    pub self_heartbeat_timeout_seconds: u32,

    /// Host cgroup filesystem root used by internal liveness probing.
    #[arg(long, default_value = DEFAULT_CGROUP_ROOT_PATH)]
    pub cgroup_root_path: PathBuf,

    /// How aggressively trustd drives the measurement + remediation loop.
    /// See [`MeasurementMode`] for semantics. Defaults to Enforce (full
    /// production pipeline). Use `off` for lifecycle-only benchmarks and
    /// `observe` when you want measurements emitted without remediation
    /// side-effects killing a running experiment.
    #[arg(long, value_enum, default_value_t = MeasurementMode::Enforce)]
    pub measurement_mode: MeasurementMode,
}
