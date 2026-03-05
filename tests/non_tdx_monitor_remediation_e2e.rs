use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::tempdir;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tonic::Request;
use trustd::error::AgentError;
use trustd::event_bus::{ContainerEventKind, EventBus};
use trustd::proto;
use trustd::proto::trustd_server::Trustd;
use trustd::remediation::{ContainerRestarter, RestartResult};
use trustd::securityfs::{
    AttestationResponse, Attestor, ContainerRtmrState, Measurement, RtmrReader,
};
use trustd::service::TrustdService;
use trustd::state::StateManager;
use trustd::tdquote::QuoteProvider;
use trustd::watcher::MeasurementWatcher;

#[derive(Debug)]
struct FakeAttestor;

impl Attestor for FakeAttestor {
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
                file: "/usr/bin/tool".to_owned(),
            }],
        })
    }
}

#[derive(Debug, Default)]
struct FakeQuoter;

impl QuoteProvider for FakeQuoter {
    fn available(&self) -> bool {
        false
    }

    fn get_quote(&self, _report_data: &[u8]) -> Result<Vec<u8>, AgentError> {
        Err(AgentError::Unavailable(
            "quote generation is disabled in non-tdx test".to_owned(),
        ))
    }
}

#[derive(Debug, Default)]
struct RecordingRestarter {
    calls: Mutex<Vec<String>>,
}

impl RecordingRestarter {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("restarter lock should not be poisoned")
            .clone()
    }
}

impl ContainerRestarter for RecordingRestarter {
    fn restart(&self, cgroup_path: &str) -> Result<RestartResult, AgentError> {
        self.calls
            .lock()
            .expect("restarter lock should not be poisoned")
            .push(cgroup_path.to_owned());
        Ok(RestartResult {
            cgroup_path: cgroup_path.to_owned(),
            signaled_pids: 1,
            force_killed_pids: 0,
        })
    }
}

#[derive(Debug)]
struct UserspaceFileReader {
    path: PathBuf,
    last_snapshot: Mutex<Option<String>>,
}

impl UserspaceFileReader {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
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

fn write_rtmr_state(
    path: &Path,
    cgroup_path: &str,
    rtmr3: &str,
    initial_rtmr3: &str,
    count: i64,
    marker: &str,
) {
    let payload = format!("{cgroup_path}\t{rtmr3}\t{initial_rtmr3}\t{count}\n# {marker}\n");
    std::fs::write(path, payload).expect("rtmr fixture write should succeed");
}

async fn recv_kind(
    rx: &mut tokio::sync::broadcast::Receiver<trustd::event_bus::ContainerEvent>,
    expected: ContainerEventKind,
) -> trustd::event_bus::ContainerEvent {
    let mut queue = VecDeque::new();

    for _ in 0..32 {
        let event = timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("event should arrive before timeout")
            .expect("event bus should remain open");
        if event.kind == expected {
            return event;
        }
        queue.push_back(event.kind);
    }

    panic!("did not receive expected event {expected:?}, saw {queue:?}");
}

#[tokio::test]
async fn monitor_and_remediation_work_end_to_end_without_tdx() {
    let cgroup = "/kubepods.slice/pod-a/container-b";
    let dir = tempdir().expect("temp dir should exist");
    let rtmr_path = dir.path().join("container_rtmr");
    write_rtmr_state(&rtmr_path, cgroup, "rtmr-1", "initial-1", 1, "seed");

    let state = Arc::new(StateManager::new());
    let events = EventBus::new(64);
    let reader = Arc::new(UserspaceFileReader::new(&rtmr_path));
    let restarter = Arc::new(RecordingRestarter::default());

    let service = TrustdService::new(
        Arc::new(FakeAttestor),
        Arc::new(FakeQuoter),
        restarter.clone(),
        Arc::clone(&state),
        events.clone(),
        "test-version",
    );

    let cancel = CancellationToken::new();
    let watcher = MeasurementWatcher::new(reader, Arc::clone(&state), events.clone(), 100);
    let watcher_handle = tokio::spawn(watcher.run(cancel.clone()));

    let mut rx = events.subscribe();
    let new_event = recv_kind(&mut rx, ContainerEventKind::New).await;
    assert_eq!(new_event.cgroup_path, cgroup);

    service
        .start_heartbeat_monitor(Request::new(proto::HeartbeatMonitorRequest {
            cgroup_path: cgroup.to_owned(),
            timeout_seconds: 1,
        }))
        .await
        .expect("monitor start should succeed");

    service
        .report_heartbeat(Request::new(proto::HeartbeatReportRequest {
            cgroup_path: cgroup.to_owned(),
        }))
        .await
        .expect("heartbeat report should succeed");
    let hb_event = recv_kind(&mut rx, ContainerEventKind::Heartbeat).await;
    assert_eq!(hb_event.cgroup_path, cgroup);

    let miss_event = recv_kind(&mut rx, ContainerEventKind::HeartbeatMiss).await;
    assert_eq!(miss_event.cgroup_path, cgroup);

    service
        .restart_container(Request::new(proto::GetContainerStateRequest {
            cgroup_path: cgroup.to_owned(),
        }))
        .await
        .expect("restart should succeed");

    assert_eq!(restarter.calls(), vec![cgroup.to_owned()]);

    cancel.cancel();
    watcher_handle
        .await
        .expect("watcher task should stop cleanly");
}
