use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tonic::Request;
use trustd::error::AgentError;
use trustd::event_bus::{ContainerEventKind, EventBus};
use trustd::proto;
use trustd::proto::trustd_server::Trustd;
use trustd::remediation::{CgroupProcessRestarter, ContainerRestarter, RestartResult};
use trustd::securityfs::{
    AttestationResponse, Attestor, ContainerRtmrState, Measurement, RtmrReader,
};
use trustd::service::TrustdService;
use trustd::state::StateManager;
use trustd::tdquote::QuoteProvider;
use trustd::watcher::MeasurementWatcher;

#[derive(Parser, Debug)]
#[command(
    name = "non-tdx-remediation-demo",
    about = "Manual non-TDX monitor/remediation demo with userspace RTMR fixture"
)]
struct Args {
    #[arg(long)]
    rtmr_path: PathBuf,
    #[arg(long)]
    heartbeat_path: PathBuf,
    #[arg(long)]
    cgroup_path: String,
    #[arg(long, default_value_t = 5)]
    heartbeat_timeout_seconds: u32,
    #[arg(long, default_value_t = 100)]
    poll_timeout_ms: i32,
    #[arg(long, default_value_t = 120)]
    max_runtime_seconds: u64,
    #[arg(long, default_value_t = true)]
    remediate_on_miss: bool,
    #[arg(long, value_enum, default_value_t = RemediationMode::Docker)]
    remediation_mode: RemediationMode,
    #[arg(long)]
    container_name: Option<String>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum RemediationMode {
    Signal,
    Docker,
}

#[derive(Debug)]
struct DummyAttestor;

impl Attestor for DummyAttestor {
    fn attest(
        &self,
        cgroup_path: &str,
        nonce_hex: &str,
    ) -> Result<AttestationResponse, AgentError> {
        Ok(AttestationResponse {
            cgroup_path: cgroup_path.to_owned(),
            initial_rtmr3: "init".to_owned(),
            rtmr3: "rtmr".to_owned(),
            count: 1,
            nonce: nonce_hex.to_owned(),
            report_data: "ab".repeat(48),
            timestamp: 1,
            measurements: vec![Measurement {
                digest: "digest".to_owned(),
                file: "/usr/bin/demo".to_owned(),
            }],
        })
    }
}

#[derive(Debug, Default)]
struct UnavailableQuoter;

impl QuoteProvider for UnavailableQuoter {
    fn available(&self) -> bool {
        false
    }

    fn get_quote(&self, _report_data: &[u8]) -> Result<Vec<u8>, AgentError> {
        Err(AgentError::Unavailable(
            "TDX quote generation is unavailable in non-tdx demo".to_owned(),
        ))
    }
}

#[derive(Debug)]
struct UserspaceFileReader {
    path: PathBuf,
    last_snapshot: Mutex<Option<String>>,
}

impl UserspaceFileReader {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            last_snapshot: Mutex::new(None),
        }
    }

    fn read_snapshot(&self) -> Result<String, AgentError> {
        std::fs::read_to_string(&self.path).map_err(|source| AgentError::io(&self.path, source))
    }
}

impl RtmrReader for UserspaceFileReader {
    fn read_all(&self) -> Result<Vec<ContainerRtmrState>, AgentError> {
        let content = self.read_snapshot()?;
        let mut states = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let mut fields = trimmed.split('\t');
            let Some(cgroup_path) = fields.next() else {
                continue;
            };
            let Some(rtmr3) = fields.next() else {
                continue;
            };
            let Some(initial_rtmr3) = fields.next() else {
                continue;
            };
            let Some(count_text) = fields.next() else {
                continue;
            };

            let Ok(count) = count_text.parse::<i64>() else {
                continue;
            };

            states.push(ContainerRtmrState {
                cgroup_path: cgroup_path.to_owned(),
                rtmr3: rtmr3.to_owned(),
                initial_rtmr3: initial_rtmr3.to_owned(),
                count,
            });
        }

        Ok(states)
    }

    fn wait_and_read_all(
        &self,
        timeout_ms: i32,
    ) -> Result<Option<Vec<ContainerRtmrState>>, AgentError> {
        let timeout = if timeout_ms <= 0 {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        let deadline = Instant::now() + timeout;

        loop {
            let snapshot = self.read_snapshot()?;
            {
                let mut guard = self
                    .last_snapshot
                    .lock()
                    .expect("snapshot lock should not be poisoned");
                if guard.as_ref() != Some(&snapshot) {
                    *guard = Some(snapshot);
                    return self.read_all().map(Some);
                }
            }

            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[derive(Debug)]
struct DockerCliRestarter {
    container_name: String,
}

impl ContainerRestarter for DockerCliRestarter {
    fn restart(&self, cgroup_path: &str) -> Result<RestartResult, AgentError> {
        let output = Command::new("docker")
            .args(["restart", "--time", "0", &self.container_name])
            .output()
            .map_err(|error| {
                AgentError::Internal(format!(
                    "failed to execute docker restart for {}: {error}",
                    self.container_name
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AgentError::Internal(format!(
                "docker restart failed for {}: {}",
                self.container_name,
                stderr.trim()
            )));
        }

        Ok(RestartResult {
            cgroup_path: cgroup_path.to_owned(),
            signaled_pids: 1,
            force_killed_pids: 0,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let state = Arc::new(StateManager::new());
    let events = EventBus::new(128);
    let reader = Arc::new(UserspaceFileReader::new(args.rtmr_path.clone()));

    let restarter: Arc<dyn ContainerRestarter> = match args.remediation_mode {
        RemediationMode::Signal => Arc::new(CgroupProcessRestarter::default()),
        RemediationMode::Docker => {
            let Some(container_name) = args.container_name.clone() else {
                return Err("--container-name is required when --remediation-mode=docker".into());
            };
            Arc::new(DockerCliRestarter { container_name })
        }
    };
    let service = TrustdService::new(
        Arc::new(DummyAttestor),
        Arc::new(UnavailableQuoter),
        Arc::clone(&restarter),
        Arc::clone(&state),
        events.clone(),
        "non-tdx-demo",
    );

    let cancel = CancellationToken::new();
    let watcher = MeasurementWatcher::new(
        reader,
        Arc::clone(&state),
        events.clone(),
        args.poll_timeout_ms,
    );
    let watcher_handle = tokio::spawn(watcher.run(cancel.clone()));
    let mut rx = events.subscribe();

    service
        .start_heartbeat_monitor(Request::new(proto::HeartbeatMonitorRequest {
            cgroup_path: args.cgroup_path.clone(),
            timeout_seconds: args.heartbeat_timeout_seconds,
        }))
        .await?;

    println!("demo started");
    println!("rtmr_path={}", args.rtmr_path.display());
    println!("heartbeat_path={}", args.heartbeat_path.display());
    println!("cgroup_path={}", args.cgroup_path);
    println!(
        "heartbeat_timeout_seconds={} poll_timeout_ms={} max_runtime_seconds={}",
        args.heartbeat_timeout_seconds, args.poll_timeout_ms, args.max_runtime_seconds
    );
    println!("remediation_mode={:?}", args.remediation_mode);
    if let Some(container_name) = args.container_name.as_deref() {
        println!("container_name={container_name}");
    }
    println!("waiting for events...");

    let heartbeat_cancel = cancel.clone();
    let heartbeat_service = service.clone();
    let heartbeat_cgroup = args.cgroup_path.clone();
    let heartbeat_path = args.heartbeat_path.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut last_snapshot = std::fs::read_to_string(&heartbeat_path).ok();
        loop {
            if heartbeat_cancel.is_cancelled() {
                return;
            }

            if let Ok(snapshot) = std::fs::read_to_string(&heartbeat_path) {
                let changed = last_snapshot.as_ref() != Some(&snapshot);
                if changed {
                    last_snapshot = Some(snapshot);
                    let _ = heartbeat_service
                        .report_heartbeat(Request::new(proto::HeartbeatReportRequest {
                            cgroup_path: heartbeat_cgroup.clone(),
                        }))
                        .await;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let deadline = Instant::now() + Duration::from_secs(args.max_runtime_seconds);
    let mut miss_seen = false;

    while Instant::now() < deadline {
        let event = match timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Ok(event)) => event,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => continue,
        };

        println!(
            "event kind={:?} cgroup={} count={:?} rtmr3={:?}",
            event.kind, event.cgroup_path, event.measurement_count, event.rtmr3
        );

        if event.kind != ContainerEventKind::HeartbeatMiss {
            continue;
        }

        miss_seen = true;
        if !args.remediate_on_miss {
            println!("heartbeat miss observed; remediation disabled by flag");
            break;
        }

        let response = service
            .restart_container(Request::new(proto::GetContainerStateRequest {
                cgroup_path: args.cgroup_path.clone(),
            }))
            .await;

        match response {
            Ok(state_response) => {
                let state = state_response.into_inner();
                println!(
                    "remediation invoked: cgroup={} measurement_count={}",
                    state.cgroup_path, state.measurement_count
                );
            }
            Err(status) => {
                println!("remediation failed: {}", status.message());
            }
        }
        break;
    }

    cancel.cancel();
    heartbeat_handle
        .await
        .map_err(|e| format!("heartbeat task join failed: {e}"))?;
    watcher_handle
        .await
        .map_err(|e| format!("watcher task join failed: {e}"))?;

    if !miss_seen {
        return Err("timed out waiting for heartbeat miss event".into());
    }

    Ok(())
}
