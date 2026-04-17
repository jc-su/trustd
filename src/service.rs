use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_stream::try_stream;
use base64::Engine;
use futures_core::Stream;
use tonic::{Request, Response, Status};

use crate::error::AgentError;
use crate::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use crate::proto;
use crate::remediation::ContainerRestarter;
use crate::securityfs::Attestor;
use crate::spec_store::SpecStore;
use crate::state::StateManager;
use crate::tdquote::QuoteProvider;

/// Build an AttestWorkloadResponse bundle for the given workload.
///
/// Shared between the gRPC `attest_workload` handler and the Unix-socket
/// JSON RPC path so both ingress surfaces produce byte-identical evidence
/// bundles. Kept out of the service impl so it can be called without a
/// tonic Request wrapper.
pub fn build_attest_bundle<Q: QuoteProvider + ?Sized>(
    spec_store: &SpecStore,
    quoter: &Q,
    workload_id: &str,
    nonce_hex: &str,
    peer_pk: &[u8],
) -> Result<proto::AttestWorkloadResponse, Status> {
    use sha2::{Digest, Sha384};

    if workload_id.is_empty() {
        return Err(Status::invalid_argument("workload_id is required"));
    }
    if nonce_hex.is_empty() {
        return Err(Status::invalid_argument("nonce_hex is required"));
    }
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|_| Status::invalid_argument("nonce_hex must be valid hex"))?;

    // workload_id → current cgroup via the spec store. Reject unknown
    // workloads fail-closed (trustd never produces evidence for
    // workloads it didn't start).
    if spec_store.get_by_name(workload_id).is_none() {
        return Err(Status::not_found(format!(
            "workload_id '{}' not registered with trustd",
            workload_id
        )));
    }
    let cgroup = spec_store.cgroup_for_name(workload_id).ok_or_else(|| {
        Status::failed_precondition(
            "workload has no associated cgroup yet (container may not have started)",
        )
    })?;

    // Read the kernel's per-container JSON log. Filename: strip leading
    // slash and replace internal slashes with underscores; see
    // DEVELOPER_GUIDE_CONTAINER_RTMR3.md and ima_container.c.
    let mangled = cgroup.trim_start_matches('/').replace('/', "_");
    let log_path =
        std::path::Path::new("/sys/kernel/security/ima/container_rtmr").join(&mangled);
    let event_log = std::fs::read(&log_path).map_err(|e| {
        Status::internal(format!(
            "failed to read per-container event log at {}: {}",
            log_path.display(),
            e
        ))
    })?;

    // report_data binds the quote to (nonce, peer_pk). 64 bytes:
    //   first  32 = SHA384(nonce)[..32]
    //   second 32 = SHA384(peer_pk)[..32] if peer_pk present, else 0s
    let mut report_data = [0_u8; 64];
    let nonce_hash = Sha384::digest(&nonce_bytes);
    report_data[..32].copy_from_slice(&nonce_hash[..32]);
    if !peer_pk.is_empty() {
        let pk_hash = Sha384::digest(peer_pk);
        report_data[32..].copy_from_slice(&pk_hash[..32]);
    }

    if !quoter.available() {
        return Err(Status::unavailable(
            "TDX quote provider is not available on this host",
        ));
    }
    let td_quote = quoter
        .get_quote(&report_data)
        .map_err(|e| Status::internal(format!("TDX_CMD_GET_QUOTE failed: {}", e)))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(proto::AttestWorkloadResponse {
        workload_id: workload_id.to_owned(),
        cgroup_path: cgroup,
        nonce_hex: nonce_hex.to_owned(),
        td_quote,
        event_log,
        report_data_hex: hex::encode(report_data),
        timestamp,
    })
}

#[derive(Debug)]
pub struct TrustdService<A, Q>
where
    A: Attestor,
    Q: QuoteProvider,
{
    attestor: Arc<A>,
    quoter: Arc<Q>,
    restarter: Arc<dyn ContainerRestarter>,
    state: Arc<StateManager>,
    events: EventBus,
    version: Arc<str>,
    started_at: Instant,
    // Lifecycle extensions (None = legacy mode, no container management).
    lifecycle: Option<Arc<crate::lifecycle::LifecycleManager>>,
    spec_store: Arc<crate::spec_store::SpecStore>,
}

impl<A, Q> Clone for TrustdService<A, Q>
where
    A: Attestor,
    Q: QuoteProvider,
{
    fn clone(&self) -> Self {
        Self {
            attestor: Arc::clone(&self.attestor),
            quoter: Arc::clone(&self.quoter),
            restarter: Arc::clone(&self.restarter),
            state: Arc::clone(&self.state),
            events: self.events.clone(),
            version: Arc::clone(&self.version),
            started_at: self.started_at,
            lifecycle: self.lifecycle.clone(),
            spec_store: Arc::clone(&self.spec_store),
        }
    }
}

impl<A, Q> TrustdService<A, Q>
where
    A: Attestor,
    Q: QuoteProvider,
{
    pub fn new(
        attestor: Arc<A>,
        quoter: Arc<Q>,
        restarter: Arc<dyn ContainerRestarter>,
        state: Arc<StateManager>,
        events: EventBus,
        version: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            attestor,
            quoter,
            restarter,
            state,
            events,
            version: version.into(),
            started_at: Instant::now(),
            lifecycle: None,
            spec_store: Arc::new(crate::spec_store::SpecStore::new()),
        }
    }

    /// Inject the lifecycle manager after construction (called from main.rs
    /// once the DockerRuntime is ready).
    pub fn set_lifecycle(
        &mut self,
        lifecycle: Arc<crate::lifecycle::LifecycleManager>,
        spec_store: Arc<crate::spec_store::SpecStore>,
    ) {
        self.lifecycle = Some(lifecycle);
        self.spec_store = spec_store;
    }

    pub fn event_bus(&self) -> EventBus {
        self.events.clone()
    }

    pub fn state_manager(&self) -> Arc<StateManager> {
        Arc::clone(&self.state)
    }

    pub fn publish_event(&self, event: ContainerEvent) {
        self.events.publish(event);
    }

    pub fn quoter(&self) -> &Arc<Q> {
        &self.quoter
    }

    pub fn spec_store(&self) -> Arc<crate::spec_store::SpecStore> {
        Arc::clone(&self.spec_store)
    }

    pub fn restarter(&self) -> &Arc<dyn ContainerRestarter> {
        &self.restarter
    }

    pub fn version_str(&self) -> &str {
        &self.version
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    fn status_for_error(error: AgentError, context: &str) -> Status {
        match error {
            AgentError::InvalidInput(message) => Status::invalid_argument(message),
            AgentError::Unavailable(message) => Status::unavailable(message),
            AgentError::Io { .. } | AgentError::Parse(_) | AgentError::Internal(_) => {
                Status::internal(format!("{context}: {error}"))
            }
        }
    }
}

#[tonic::async_trait]
impl<A, Q> proto::trustd_server::Trustd for TrustdService<A, Q>
where
    A: Attestor + 'static,
    Q: QuoteProvider + 'static,
{
    /// Canonical attestation RPC for a workload identified by its stable
    /// name. Bundles:
    ///   - TD quote with report_data = SHA384(nonce) || SHA384(peer_pk)
    ///   - Kernel's per-container event log (single JSON object)
    ///   - workload_id + cgroup (audit)
    ///
    /// Does no measurement interpretation — the verifier receives the raw
    /// event log and replays it against its reference values. This matches
    /// the current kernel design where HW RTMR[3] is a shared interleaved
    /// chain and per-container replay against it is not possible.
    async fn attest_workload(
        &self,
        request: Request<proto::AttestWorkloadRequest>,
    ) -> Result<Response<proto::AttestWorkloadResponse>, Status> {
        let request = request.into_inner();
        let bundle = build_attest_bundle(
            self.spec_store.as_ref(),
            self.quoter.as_ref(),
            &request.workload_id,
            &request.nonce_hex,
            &request.peer_pk,
        )?;
        Ok(Response::new(bundle))
    }

    async fn list_containers(
        &self,
        _request: Request<proto::ListContainersRequest>,
    ) -> Result<Response<proto::ListContainersResponse>, Status> {
        let containers = self
            .state
            .list()
            .into_iter()
            .map(|state| proto::ContainerState {
                cgroup_path: state.cgroup_path,
                rtmr3: state.rtmr3,
                initial_rtmr3: state.initial_rtmr3,
                measurement_count: state.measurement_count,
                last_heartbeat: state.last_heartbeat.map_or(0, unix_seconds),
                heartbeat_count: state.heartbeat_count,
                heartbeat_monitoring: state.heartbeat_monitoring,
                // Lifecycle fields (default: unmanaged).
                phase: 0,
                container_name: String::new(),
                container_id: String::new(),
            })
            .collect();

        Ok(Response::new(proto::ListContainersResponse { containers }))
    }

    async fn get_container_state(
        &self,
        request: Request<proto::GetContainerStateRequest>,
    ) -> Result<Response<proto::ContainerState>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path is required"));
        }

        let Some(state) = self.state.get(&request.cgroup_path) else {
            return Err(Status::not_found(format!(
                "container {} not found",
                request.cgroup_path
            )));
        };

        Ok(Response::new(proto::ContainerState {
            cgroup_path: state.cgroup_path,
            rtmr3: state.rtmr3,
            initial_rtmr3: state.initial_rtmr3,
            measurement_count: state.measurement_count,
            last_heartbeat: state.last_heartbeat.map_or(0, unix_seconds),
            heartbeat_count: state.heartbeat_count,
            heartbeat_monitoring: state.heartbeat_monitoring,
                // Lifecycle fields (default: unmanaged).
                phase: 0,
                container_name: String::new(),
                container_id: String::new(),
        }))
    }

    type WatchContainerEventsStream =
        Pin<Box<dyn Stream<Item = Result<proto::ContainerEvent, Status>> + Send + 'static>>;

    async fn watch_container_events(
        &self,
        request: Request<proto::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchContainerEventsStream>, Status> {
        let request = request.into_inner();
        let allowed_types = if request.event_types.is_empty() {
            None
        } else {
            Some(request.event_types.into_iter().collect::<HashSet<i32>>())
        };
        let cgroup_filter = if request.cgroup_path.is_empty() {
            None
        } else {
            Some(request.cgroup_path)
        };

        let mut rx = self.events.subscribe();
        let stream = try_stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if !matches_filter(&event, allowed_types.as_ref(), cgroup_filter.as_deref()) {
                            continue;
                        }
                        yield to_proto_event(event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_td_quote(
        &self,
        request: Request<proto::GetTdQuoteRequest>,
    ) -> Result<Response<proto::GetTdQuoteResponse>, Status> {
        if !self.quoter.available() {
            return Err(Status::unavailable(
                "TDX quotes are unavailable on this host",
            ));
        }

        let request = request.into_inner();
        let mut report_data = request.report_data;

        if report_data.len() != 64
            && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&report_data)
            && decoded.len() == 64
        {
            report_data = decoded;
        }

        if report_data.len() != 64 {
            return Err(Status::invalid_argument(
                "report_data must be exactly 64 bytes",
            ));
        }

        let quote = self
            .quoter
            .get_quote(&report_data)
            .map_err(|error| Self::status_for_error(error, "quote generation failed"))?;

        Ok(Response::new(proto::GetTdQuoteResponse { td_quote: quote }))
    }

    async fn ping(
        &self,
        _request: Request<proto::PingRequest>,
    ) -> Result<Response<proto::PingResponse>, Status> {
        Ok(Response::new(proto::PingResponse {
            version: self.version.to_string(),
            uptime_seconds: self.started_at.elapsed().as_secs() as i64,
            containers_tracked: self.state.count() as i64,
        }))
    }

    async fn start_heartbeat_monitor(
        &self,
        request: Request<proto::HeartbeatMonitorRequest>,
    ) -> Result<Response<proto::HeartbeatMonitorResponse>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path is required"));
        }

        self.state
            .start_heartbeat_monitor(&request.cgroup_path, request.timeout_seconds);

        Ok(Response::new(proto::HeartbeatMonitorResponse {}))
    }

    async fn stop_heartbeat_monitor(
        &self,
        request: Request<proto::HeartbeatMonitorStopRequest>,
    ) -> Result<Response<proto::HeartbeatMonitorStopResponse>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path is required"));
        }

        self.state.stop_heartbeat_monitor(&request.cgroup_path);

        Ok(Response::new(proto::HeartbeatMonitorStopResponse {}))
    }

    async fn report_heartbeat(
        &self,
        request: Request<proto::HeartbeatReportRequest>,
    ) -> Result<Response<proto::HeartbeatReportResponse>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path is required"));
        }

        self.state.record_heartbeat(&request.cgroup_path);
        if let Some(state) = self.state.get(&request.cgroup_path) {
            let mut event = ContainerEvent::new(ContainerEventKind::Heartbeat, state.cgroup_path);
            if !state.rtmr3.is_empty() {
                event.rtmr3 = Some(state.rtmr3);
            }
            event.measurement_count = Some(state.measurement_count);
            self.publish_event(event);
        }

        Ok(Response::new(proto::HeartbeatReportResponse {}))
    }

    async fn restart_container(
        &self,
        request: Request<proto::GetContainerStateRequest>,
    ) -> Result<Response<proto::ContainerState>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path is required"));
        }

        let cgroup_path = request.cgroup_path.clone();
        self.publish_event(remediation_lifecycle_event(
            &cgroup_path,
            "remediation_begin",
            None,
        ));
        self.state.reset_for_remediation(&cgroup_path);

        let cgroup_path = request.cgroup_path.clone();
        let restarter = Arc::clone(&self.restarter);
        let restart = tokio::task::spawn_blocking(move || restarter.restart(&cgroup_path))
            .await
            .map_err(|error| Status::internal(format!("restart join error: {error}")))?
            .map_err(|error| {
                self.publish_event(remediation_lifecycle_event(
                    &request.cgroup_path,
                    "remediation_failed",
                    Some(format!("restart failed: {error}")),
                ));
                Self::status_for_error(error, "restart failed")
            })?;

        self.publish_event(remediation_lifecycle_event(
            &request.cgroup_path,
            "remediation_done",
            None,
        ));

        tracing::info!(
            cgroup_path = %restart.cgroup_path,
            signaled_pids = restart.signaled_pids,
            force_killed_pids = restart.force_killed_pids,
            "container restart requested"
        );

        let state = self.state.get(&request.cgroup_path);
        Ok(Response::new(match state {
            Some(state) => proto::ContainerState {
                cgroup_path: state.cgroup_path,
                rtmr3: state.rtmr3,
                initial_rtmr3: state.initial_rtmr3,
                measurement_count: state.measurement_count,
                last_heartbeat: state.last_heartbeat.map_or(0, unix_seconds),
                heartbeat_count: state.heartbeat_count,
                heartbeat_monitoring: state.heartbeat_monitoring,
                // Lifecycle fields (default: unmanaged).
                phase: 0,
                container_name: String::new(),
                container_id: String::new(),
            },
            None => proto::ContainerState {
                cgroup_path: request.cgroup_path,
                ..proto::ContainerState::default()
            },
        }))
    }

    // ---- Container lifecycle RPCs ----

    async fn start_container(
        &self,
        request: Request<proto::StartContainerRequest>,
    ) -> Result<Response<proto::StartContainerResponse>, Status> {
        let lm = self.lifecycle.as_ref()
            .ok_or_else(|| Status::unavailable("lifecycle manager not initialized (Docker may not be available in this guest)"))?;

        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        if req.image.is_empty() {
            return Err(Status::invalid_argument("image is required"));
        }

        let req_name = req.name.clone();
        let spec = crate::runtime::ContainerSpec {
            name: req.name,
            image: req.image,
            env: req.env,
            ports: req.ports,
            network_host: req.network_host,
            labels: req.labels,
            ready_marker: if req.ready_marker.is_empty() {
                "TRUSTWEAVE_READY".into()
            } else {
                req.ready_marker
            },
        };

        match lm.start_container(spec).await {
            Ok(result) => {
                let phase_state = self.state.get_by_name(&req_name);
                Ok(Response::new(proto::StartContainerResponse {
                    cgroup_path: result.cgroup_path,
                    container_id: result.container_id,
                    started: true,
                    error: String::new(),
                    phase: phase_state.map_or(0, |s| s.phase.to_proto()),
                }))
            }
            Err(e) => Ok(Response::new(proto::StartContainerResponse {
                cgroup_path: String::new(),
                container_id: String::new(),
                started: false,
                error: e.to_string(),
                phase: crate::lifecycle::Phase::Failed.to_proto(),
            })),
        }
    }

    async fn stop_container(
        &self,
        request: Request<proto::StopContainerRequest>,
    ) -> Result<Response<proto::StopContainerResponse>, Status> {
        let lm = self.lifecycle.as_ref()
            .ok_or_else(|| Status::unavailable("lifecycle manager not initialized"))?;

        let req = request.into_inner();
        let name = if !req.name.is_empty() {
            req.name
        } else if !req.cgroup_path.is_empty() {
            self.spec_store
                .name_for_cgroup(&req.cgroup_path)
                .ok_or_else(|| Status::not_found("no lifecycle-managed container at that cgroup"))?
        } else {
            return Err(Status::invalid_argument("name or cgroup_path is required"));
        };

        let timeout = if req.timeout_seconds > 0 {
            req.timeout_seconds as u32
        } else {
            10
        };

        match lm.stop_container(&name, timeout).await {
            Ok(()) => Ok(Response::new(proto::StopContainerResponse {
                stopped: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(proto::StopContainerResponse {
                stopped: false,
                error: e.to_string(),
            })),
        }
    }

    async fn list_running_containers(
        &self,
        _request: Request<proto::ListRunningRequest>,
    ) -> Result<Response<proto::ListRunningResponse>, Status> {
        let containers = self.spec_store.all().into_iter().map(|(spec, cgroup)| {
            let phase_state = self.state.get_by_name(&spec.name);
            proto::ManagedContainer {
                name: spec.name,
                image: spec.image,
                cgroup_path: cgroup,
                container_id: String::new(),
                phase: phase_state.map_or(0, |s| s.phase.to_proto()),
                started_at: 0,
                ports: spec.ports,
            }
        }).collect();

        Ok(Response::new(proto::ListRunningResponse { containers }))
    }
}

fn remediation_lifecycle_event(
    cgroup_path: &str,
    phase: &str,
    detail: Option<String>,
) -> ContainerEvent {
    let kind = match phase {
        "remediation_begin" => ContainerEventKind::AttestBegin,
        _ => ContainerEventKind::AttestEnd,
    };
    let mut event = ContainerEvent::new(kind, cgroup_path.to_owned());
    let mut text = format!("{phase} action=restart");
    if let Some(extra) = detail
        && !extra.is_empty()
    {
        text.push(' ');
        text.push_str("message=");
        text.push_str(extra.as_str());
    }
    event.detail = Some(text);
    event
}

fn matches_filter(
    event: &ContainerEvent,
    allowed_types: Option<&HashSet<i32>>,
    cgroup_filter: Option<&str>,
) -> bool {
    if let Some(types) = allowed_types {
        let kind = map_event_kind(event.kind) as i32;
        if !types.contains(&kind) {
            return false;
        }
    }

    if let Some(filter) = cgroup_filter {
        return event.cgroup_path == filter;
    }

    true
}

fn to_proto_event(event: ContainerEvent) -> proto::ContainerEvent {
    proto::ContainerEvent {
        event_type: map_event_kind(event.kind) as i32,
        cgroup_path: event.cgroup_path,
        timestamp: unix_seconds(event.timestamp),
        digest: event.digest.unwrap_or_default(),
        filename: event.filename.unwrap_or_default(),
        detail: event.detail.unwrap_or_default(),
        rtmr3: event.rtmr3.unwrap_or_default(),
        measurement_count: event.measurement_count.unwrap_or_default(),
        // Lifecycle fields:
        phase: event
            .phase
            .map(|p| p.to_proto())
            .unwrap_or(0),
        container_name: event.container_name.unwrap_or_default(),
    }
}

fn map_event_kind(kind: ContainerEventKind) -> proto::EventType {
    match kind {
        ContainerEventKind::New => proto::EventType::New,
        ContainerEventKind::Measurement => proto::EventType::Measurement,
        ContainerEventKind::Heartbeat => proto::EventType::Heartbeat,
        ContainerEventKind::HeartbeatMiss => proto::EventType::HeartbeatMiss,
        ContainerEventKind::Removed => proto::EventType::Removed,
        ContainerEventKind::AttestBegin => proto::EventType::AttestBegin,
        ContainerEventKind::AttestEnd => proto::EventType::AttestEnd,
        ContainerEventKind::Ready => proto::EventType::Ready,
        ContainerEventKind::PhaseChange => proto::EventType::PhaseChange,
    }
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::proto::trustd_server::Trustd;
    use crate::remediation::{ContainerRestarter, RestartResult};
    use crate::securityfs::{AttestationResponse, Measurement};

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
                count: 4,
                nonce: nonce_hex.to_owned(),
                report_data: "ab".repeat(48),
                timestamp: 5,
                measurements: vec![Measurement {
                    digest: "digest".to_owned(),
                    file: "/file".to_owned(),
                }],
            })
        }
    }

    #[derive(Debug, Default)]
    struct FakeQuoter {
        pub available: bool,
        pub last_request: Mutex<Option<Vec<u8>>>,
    }

    impl QuoteProvider for FakeQuoter {
        fn available(&self) -> bool {
            self.available
        }

        fn get_quote(&self, report_data: &[u8]) -> Result<Vec<u8>, AgentError> {
            *self
                .last_request
                .lock()
                .expect("quoter lock should not be poisoned") = Some(report_data.to_vec());
            Ok(vec![9, 9, 9])
        }
    }

    #[derive(Debug, Default)]
    struct FakeRestarter {
        calls: Mutex<Vec<String>>,
    }

    impl ContainerRestarter for FakeRestarter {
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

    #[tokio::test]
    async fn get_td_quote_accepts_base64_payload() {
        let quoter = Arc::new(FakeQuoter {
            available: true,
            ..FakeQuoter::default()
        });
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            quoter,
            Arc::new(FakeRestarter::default()),
            Arc::new(StateManager::new()),
            EventBus::new(8),
            "test",
        );

        let payload = base64::engine::general_purpose::STANDARD.encode([7_u8; 64]);
        let response = service
            .get_td_quote(Request::new(proto::GetTdQuoteRequest {
                report_data: payload.into_bytes(),
            }))
            .await
            .expect("quote request should succeed")
            .into_inner();

        assert_eq!(response.td_quote, vec![9, 9, 9]);
    }

    #[test]
    fn filter_matches_type_and_cgroup() {
        let event = ContainerEvent::new(ContainerEventKind::Measurement, "cg1");
        let mut allowed = HashSet::new();
        allowed.insert(proto::EventType::Measurement as i32);

        assert!(matches_filter(&event, Some(&allowed), Some("cg1")));
        assert!(!matches_filter(&event, Some(&allowed), Some("cg2")));
    }

    #[tokio::test]
    async fn report_heartbeat_records_state_and_emits_event() {
        let state = Arc::new(StateManager::new());
        state.update_from_securityfs("cg1", "rtmr", "init", 3);
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::new(FakeQuoter::default()),
            Arc::new(FakeRestarter::default()),
            Arc::clone(&state),
            EventBus::new(8),
            "test",
        );
        let mut rx = service.event_bus().subscribe();

        service
            .report_heartbeat(Request::new(proto::HeartbeatReportRequest {
                cgroup_path: "cg1".to_owned(),
            }))
            .await
            .expect("report heartbeat should succeed");

        let hb = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("heartbeat event should arrive")
            .expect("event stream should be open");
        assert_eq!(hb.kind, ContainerEventKind::Heartbeat);
        assert_eq!(hb.cgroup_path, "cg1");

        let current = state.get("cg1").expect("state should exist");
        assert_eq!(current.heartbeat_count, 1);
        assert!(current.last_heartbeat.is_some());
    }

    #[tokio::test]
    async fn report_heartbeat_requires_cgroup_path() {
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::new(FakeQuoter::default()),
            Arc::new(FakeRestarter::default()),
            Arc::new(StateManager::new()),
            EventBus::new(8),
            "test",
        );

        let err = service
            .report_heartbeat(Request::new(proto::HeartbeatReportRequest::default()))
            .await
            .expect_err("empty request should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn restart_container_invokes_restarter() {
        let restarter = Arc::new(FakeRestarter::default());
        let restarter_trait: Arc<dyn ContainerRestarter> = restarter.clone();
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::new(FakeQuoter::default()),
            restarter_trait,
            Arc::new(StateManager::new()),
            EventBus::new(8),
            "test",
        );

        let _ = service
            .restart_container(Request::new(proto::GetContainerStateRequest {
                cgroup_path: "cg1".to_owned(),
            }))
            .await
            .expect("restart should succeed");

        let calls = restarter
            .calls
            .lock()
            .expect("restarter lock should not be poisoned")
            .clone();
        assert_eq!(calls, vec!["cg1".to_owned()]);
    }

    #[tokio::test]
    async fn restart_container_resets_state_and_emits_lifecycle_events() {
        let state = Arc::new(StateManager::new());
        state.update_from_securityfs("cg1", "rtmr", "init", 3);

        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::new(FakeQuoter::default()),
            Arc::new(FakeRestarter::default()),
            Arc::clone(&state),
            EventBus::new(8),
            "test",
        );
        let mut rx = service.event_bus().subscribe();

        let response = service
            .restart_container(Request::new(proto::GetContainerStateRequest {
                cgroup_path: "cg1".to_owned(),
            }))
            .await
            .expect("restart should succeed")
            .into_inner();

        assert_eq!(response.measurement_count, 0);

        let begin = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("begin event should arrive")
            .expect("event stream should be open");
        let end = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("end event should arrive")
            .expect("event stream should be open");

        assert_eq!(begin.kind, ContainerEventKind::AttestBegin);
        assert_eq!(
            begin.detail.as_deref(),
            Some("remediation_begin action=restart")
        );
        assert_eq!(end.kind, ContainerEventKind::AttestEnd);
        assert_eq!(
            end.detail.as_deref(),
            Some("remediation_done action=restart")
        );

        let post = state.get("cg1").expect("state should exist");
        assert!(post.pending_rebootstrap);
        assert_eq!(post.measurement_count, 0);
    }

    #[tokio::test]
    async fn restart_container_requires_cgroup_path() {
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::new(FakeQuoter::default()),
            Arc::new(FakeRestarter::default()),
            Arc::new(StateManager::new()),
            EventBus::new(8),
            "test",
        );

        let err = service
            .restart_container(Request::new(proto::GetContainerStateRequest::default()))
            .await
            .expect_err("empty request should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
