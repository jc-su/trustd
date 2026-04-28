//! Container runtime abstraction.
//!
//! Trait [`ContainerRuntime`] + [`DockerRuntime`] implementation via `bollard`.
//! trustd uses this to start, stop, and inspect containers inside the CVM.
//! The trait allows swapping Docker for containerd without changing the
//! lifecycle/service/remediation logic.

use async_trait::async_trait;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions,
    LogsOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::models::HostConfig;
use bollard::Docker;
use futures_util::StreamExt;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Specification for a container to start. Stored in [`SpecStore`](crate::spec_store::SpecStore)
/// so remediation can recreate a container from the same inputs.
#[derive(Clone, Debug)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub env: Vec<String>,
    pub ports: Vec<i32>,
    pub network_host: bool,
    pub labels: HashMap<String, String>,
    pub ready_marker: String,
}

impl Default for ContainerSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: String::new(),
            env: Vec::new(),
            ports: Vec::new(),
            network_host: false,
            labels: HashMap::new(),
            ready_marker: "TRUSTWEAVE_READY".into(),
        }
    }
}

/// Result of a container start.
#[derive(Debug, Clone)]
pub struct StartResult {
    pub container_id: String,
    pub cgroup_path: String,
}

/// Info about a running container.
#[derive(Debug, Clone)]
pub struct RunningContainerInfo {
    pub name: String,
    pub image: String,
    pub container_id: String,
    pub cgroup_path: String,
    pub started_at: i64,
    pub ports: Vec<i32>,
}

/// Abstract container runtime. The lifecycle manager calls this trait;
/// the concrete implementation talks to Docker (or containerd later).
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    async fn create_and_start(&self, spec: &ContainerSpec) -> Result<StartResult, RuntimeError>;
    async fn stop_and_remove(&self, name: &str, timeout_secs: u32) -> Result<(), RuntimeError>;
    async fn list_running(&self) -> Result<Vec<RunningContainerInfo>, RuntimeError>;
    async fn inspect(&self, name: &str) -> Result<Option<RunningContainerInfo>, RuntimeError>;
    /// Stream container stdout lines via a channel. The receiver gets
    /// one String per line. Used by the lifecycle manager to detect the
    /// `[TRUSTWEAVE_READY]` marker.
    async fn stream_logs(
        &self,
        name: &str,
        since: i64,
    ) -> Result<mpsc::Receiver<String>, RuntimeError>;
}

/// bollard-backed Docker runtime.
pub struct DockerRuntime {
    client: Docker,
}

impl DockerRuntime {
    /// Connect to the local Docker daemon. Retries briefly on failure so a
    /// race between `docker.service` reaching READY=1 and `trustd` starting
    /// — or Docker being momentarily unreachable after restart — doesn't
    /// leave trustd with a dead bollard client. Happy path is ~0ms; worst
    /// case is ~600ms (3 × 200ms) before we give up.
    pub fn new() -> Result<Self, RuntimeError> {
        const MAX_ATTEMPTS: u32 = 3;
        const BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);
        let mut last_err: Option<String> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match Docker::connect_with_socket_defaults() {
                Ok(client) => return Ok(Self { client }),
                Err(e) => {
                    let msg = e.to_string();
                    if attempt < MAX_ATTEMPTS {
                        warn!(attempt, error = %msg, "bollard connect failed; retrying");
                        std::thread::sleep(BACKOFF);
                    }
                    last_err = Some(msg);
                }
            }
        }
        Err(RuntimeError::Connect(last_err.unwrap_or_default()))
    }

    /// Resolve the cgroup path for a running container.
    ///
    /// Reads `/proc/<pid>/cgroup` off the container's init pid — authoritative
    /// regardless of docker's cgroup driver. cgroup v2 lines look like
    /// `0::/system.slice/docker-<id>.scope` (systemd) or `0::/docker/<id>`
    /// (cgroupfs). Falls back to a driver-heuristic string on failure so
    /// older callers still get *something* useful.
    async fn resolve_cgroup(&self, name: &str) -> String {
        let info = match self.client.inspect_container(name, None::<InspectContainerOptions>).await {
            Ok(i) => i,
            Err(e) => {
                warn!(error = %e, container = %name, "failed to inspect container for cgroup");
                return String::new();
            }
        };
        let pid = info.state.as_ref().and_then(|s| s.pid).unwrap_or(0);
        if pid > 0 {
            let path = format!("/proc/{}/cgroup", pid);
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                // cgroup v2 has a single line `0::/<path>`; v1 has many. The
                // unified hierarchy (v2) entry is the one the IMA patch keys on.
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("0::") {
                        let trimmed = rest.trim();
                        if !trimmed.is_empty() {
                            return trimmed.to_string();
                        }
                    }
                }
            }
        }
        // Fallback: synthesize from inspect (pre-start containers have no pid).
        let id = info.id.unwrap_or_default();
        let parent = info
            .host_config
            .and_then(|h| h.cgroup_parent)
            .unwrap_or_default();
        if parent.is_empty() {
            format!("/docker/{}", id)
        } else {
            format!("{}/docker-{}.scope", parent, &id[..12.min(id.len())])
        }
    }
}

#[async_trait]
impl ContainerRuntime for DockerRuntime {
    async fn create_and_start(&self, spec: &ContainerSpec) -> Result<StartResult, RuntimeError> {
        // Remove any stale container with the same name (idempotent).
        let _ = self.stop_and_remove(&spec.name, 5).await;

        // Make sure the image is present. bollard's create_container does NOT
        // auto-pull (unlike `docker run`), so we do it explicitly — but ONLY
        // when the image isn't already cached. For pre-baked / locally-built
        // images (e.g. images baked into the qcow2 via `docker load` during
        // image build) this avoids a Docker Hub round-trip that would 404 on
        // private-name-only tags like `trustweave/sqlite-ready:latest`.
        if self.client.inspect_image(&spec.image).await.is_err() {
            use bollard::image::CreateImageOptions;
            let opts = CreateImageOptions {
                from_image: spec.image.clone(),
                ..Default::default()
            };
            let mut stream = self.client.create_image(Some(opts), None, None);
            while let Some(event) = stream.next().await {
                if let Err(e) = event {
                    return Err(RuntimeError::Create(format!(
                        "pull {}: {}",
                        spec.image, e
                    )));
                }
            }
        }

        // Auto-bind trustd's Unix socket so the workload's TrustedMCP client
        // (mcp-sdk-fork's TrustdClient, default path /run/trustd.sock) can
        // reach us. Without this, TEE-on workloads abort at startup with
        // "Neither attestation authority nor trustd is available". Cheap to
        // mount unconditionally — non-TEE containers simply won't read it.
        let host_config = HostConfig {
            network_mode: if spec.network_host {
                Some("host".into())
            } else {
                None
            },
            binds: Some(vec!["/run/trustd.sock:/run/trustd.sock".to_string()]),
            ..Default::default()
        };

        let mut labels_map = spec.labels.clone();
        labels_map.insert("trustd.managed".into(), "true".into());

        // Inject the stable workload identity so in-container relying parties
        // (e.g. MCP fork's TrustdClient.attest_workload) can find themselves
        // without the operator having to set it explicitly. If the operator
        // already set it in spec.env, theirs wins.
        let mut env = spec.env.clone();
        let has_workload_id_env = env
            .iter()
            .any(|v| v.starts_with("TEE_MCP_WORKLOAD_ID="));
        if !has_workload_id_env && !spec.name.is_empty() {
            env.push(format!("TEE_MCP_WORKLOAD_ID={}", spec.name));
        }

        let config: Config<String> = Config {
            image: Some(spec.image.clone()),
            env: Some(env),
            labels: Some(labels_map),
            host_config: Some(host_config),
            ..Default::default()
        };

        let opts = CreateContainerOptions {
            name: &spec.name,
            platform: None,
        };
        let created = self
            .client
            .create_container(Some(opts), config)
            .await
            .map_err(|e| RuntimeError::Create(e.to_string()))?;

        debug!(container = %spec.name, id = %created.id, "container created");

        self.client
            .start_container(&spec.name, None::<StartContainerOptions<String>>)
            .await
            .map_err(|e| RuntimeError::Start(e.to_string()))?;

        debug!(container = %spec.name, "container started");

        let cgroup_path = self.resolve_cgroup(&spec.name).await;

        Ok(StartResult {
            container_id: created.id,
            cgroup_path,
        })
    }

    async fn stop_and_remove(&self, name: &str, timeout_secs: u32) -> Result<(), RuntimeError> {
        let stop_opts = Some(StopContainerOptions {
            t: timeout_secs as i64,
        });
        if let Err(e) = self.client.stop_container(name, stop_opts).await {
            debug!(container = %name, error = %e, "stop (may already be stopped)");
        }
        let rm_opts = Some(RemoveContainerOptions {
            force: true,
            ..Default::default()
        });
        if let Err(e) = self.client.remove_container(name, rm_opts).await {
            debug!(container = %name, error = %e, "remove (may already be removed)");
        }
        Ok(())
    }

    async fn list_running(&self) -> Result<Vec<RunningContainerInfo>, RuntimeError> {
        let mut filters = HashMap::new();
        filters.insert("label", vec!["trustd.managed=true"]);
        let opts = Some(ListContainersOptions {
            all: false,
            filters,
            ..Default::default()
        });
        let containers = self
            .client
            .list_containers(opts)
            .await
            .map_err(|e| RuntimeError::List(e.to_string()))?;

        Ok(containers
            .into_iter()
            .map(|c| {
                let name = c
                    .names
                    .unwrap_or_default()
                    .first()
                    .cloned()
                    .unwrap_or_default()
                    .trim_start_matches('/')
                    .to_string();
                RunningContainerInfo {
                    name,
                    image: c.image.unwrap_or_default(),
                    container_id: c.id.unwrap_or_default(),
                    cgroup_path: String::new(),
                    started_at: c.created.unwrap_or(0),
                    ports: vec![],
                }
            })
            .collect())
    }

    async fn inspect(&self, name: &str) -> Result<Option<RunningContainerInfo>, RuntimeError> {
        match self
            .client
            .inspect_container(name, None::<InspectContainerOptions>)
            .await
        {
            Ok(info) => Ok(Some(RunningContainerInfo {
                name: name.to_string(),
                image: info
                    .config
                    .and_then(|c| c.image)
                    .unwrap_or_default(),
                container_id: info.id.unwrap_or_default(),
                cgroup_path: String::new(),
                started_at: 0,
                ports: vec![],
            })),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(None),
            Err(e) => Err(RuntimeError::Inspect(e.to_string())),
        }
    }

    async fn stream_logs(
        &self,
        name: &str,
        since: i64,
    ) -> Result<mpsc::Receiver<String>, RuntimeError> {
        let opts = LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            since,
            ..Default::default()
        };
        let mut stream = self.client.logs(name, Some(opts));
        let (tx, rx) = mpsc::channel(64);

        let container_name = name.to_string();
        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                match result {
                    Ok(output) => {
                        let line = output.to_string();
                        for l in line.lines() {
                            if tx.send(l.to_string()).await.is_err() {
                                return; // receiver dropped
                            }
                        }
                    }
                    Err(e) => {
                        error!(container = %container_name, error = %e, "log stream error");
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("connect to container runtime: {0}")]
    Connect(String),
    #[error("create container: {0}")]
    Create(String),
    #[error("start container: {0}")]
    Start(String),
    #[error("stop container: {0}")]
    Stop(String),
    #[error("inspect container: {0}")]
    Inspect(String),
    #[error("list containers: {0}")]
    List(String),
    #[error("stream logs: {0}")]
    Logs(String),
}
