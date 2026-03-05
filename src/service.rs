use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_stream::try_stream;
use base64::Engine;
use futures_core::Stream;
use tonic::{Request, Response, Status};
use tracing::warn;

use crate::error::AgentError;
use crate::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use crate::proto;
use crate::remediation::ContainerRestarter;
use crate::securityfs::Attestor;
use crate::state::StateManager;
use crate::tdquote::QuoteProvider;

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
        }
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
    async fn attest_container(
        &self,
        request: Request<proto::AttestContainerRequest>,
    ) -> Result<Response<proto::AttestContainerResponse>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path is required"));
        }
        if request.nonce_hex.is_empty() {
            return Err(Status::invalid_argument("nonce_hex is required"));
        }
        if hex::decode(&request.nonce_hex).is_err() {
            return Err(Status::invalid_argument("nonce_hex must be valid hex"));
        }

        self.publish_event(ContainerEvent::new(
            ContainerEventKind::AttestBegin,
            request.cgroup_path.clone(),
        ));

        let kernel = self
            .attestor
            .attest(&request.cgroup_path, &request.nonce_hex)
            .map_err(|error| Self::status_for_error(error, "attestation failed"))?;

        let mut response = proto::AttestContainerResponse {
            cgroup_path: kernel.cgroup_path.clone(),
            rtmr3: kernel.rtmr3.clone(),
            initial_rtmr3: kernel.initial_rtmr3,
            measurement_count: kernel.count,
            measurements: kernel
                .measurements
                .into_iter()
                .map(|measurement| proto::ContainerMeasurement {
                    digest: measurement.digest,
                    file: measurement.file,
                })
                .collect(),
            report_data: kernel.report_data.clone(),
            nonce: kernel.nonce,
            td_quote: Vec::new(),
            timestamp: kernel.timestamp,
        };

        if request.include_td_quote && self.quoter.available() {
            match hex::decode(&kernel.report_data) {
                Ok(report_data) => {
                    let mut padded = [0_u8; 64];
                    let copy_len = report_data.len().min(64);
                    padded[..copy_len].copy_from_slice(&report_data[..copy_len]);

                    match self.quoter.get_quote(&padded) {
                        Ok(quote) => response.td_quote = quote,
                        Err(error) => warn!(error = %error, "unable to produce TD quote"),
                    }
                }
                Err(error) => warn!(error = %error, "report_data is not valid hex; skipping quote"),
            }
        }

        self.publish_event(ContainerEvent::new(
            ContainerEventKind::AttestEnd,
            request.cgroup_path,
        ));

        Ok(Response::new(response))
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
            },
            None => proto::ContainerState {
                cgroup_path: request.cgroup_path,
                ..proto::ContainerState::default()
            },
        }))
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
    async fn attest_rejects_invalid_nonce_hex() {
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::new(FakeQuoter::default()),
            Arc::new(FakeRestarter::default()),
            Arc::new(StateManager::new()),
            EventBus::new(8),
            "test",
        );

        let err = service
            .attest_container(Request::new(proto::AttestContainerRequest {
                cgroup_path: "cg1".to_owned(),
                nonce_hex: "not-hex".to_owned(),
                include_td_quote: false,
            }))
            .await
            .expect_err("invalid nonce should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn attest_can_include_quote() {
        let quoter = Arc::new(FakeQuoter {
            available: true,
            ..FakeQuoter::default()
        });
        let service = TrustdService::new(
            Arc::new(FakeAttestor),
            Arc::clone(&quoter),
            Arc::new(FakeRestarter::default()),
            Arc::new(StateManager::new()),
            EventBus::new(8),
            "test",
        );

        let response = service
            .attest_container(Request::new(proto::AttestContainerRequest {
                cgroup_path: "cg1".to_owned(),
                nonce_hex: "ab".repeat(32),
                include_td_quote: true,
            }))
            .await
            .expect("attestation should succeed")
            .into_inner();

        assert_eq!(response.td_quote, vec![9, 9, 9]);
        assert_eq!(
            quoter
                .last_request
                .lock()
                .expect("quoter lock should not be poisoned")
                .as_ref()
                .expect("report data should be captured")
                .len(),
            64
        );
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
