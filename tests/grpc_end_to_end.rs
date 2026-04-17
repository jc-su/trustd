use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use trustd::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use trustd::proto;
use trustd::remediation::{ContainerRestarter, RestartResult};
use trustd::securityfs::{AttestationResponse, Attestor, Measurement};
use trustd::service::TrustdService;
use trustd::state::StateManager;
use trustd::tdquote::QuoteProvider;

#[derive(Debug)]
struct FakeAttestor;

impl Attestor for FakeAttestor {
    fn attest(
        &self,
        cgroup_path: &str,
        nonce_hex: &str,
    ) -> Result<AttestationResponse, trustd::error::AgentError> {
        Ok(AttestationResponse {
            cgroup_path: cgroup_path.to_owned(),
            initial_rtmr3: "initial".to_owned(),
            rtmr3: "rtmr".to_owned(),
            count: 2,
            nonce: nonce_hex.to_owned(),
            report_data: "ab".repeat(48),
            timestamp: 100,
            measurements: vec![Measurement {
                digest: "digest".to_owned(),
                file: "/bin/example".to_owned(),
            }],
        })
    }
}

#[derive(Debug)]
struct FakeQuoter {
    available: bool,
}

impl QuoteProvider for FakeQuoter {
    fn available(&self) -> bool {
        self.available
    }

    fn get_quote(&self, _report_data: &[u8]) -> Result<Vec<u8>, trustd::error::AgentError> {
        Ok(vec![1, 2, 3, 4])
    }
}

#[derive(Debug, Default)]
struct FakeRestarter;

impl ContainerRestarter for FakeRestarter {
    fn restart(&self, cgroup_path: &str) -> Result<RestartResult, trustd::error::AgentError> {
        Ok(RestartResult {
            cgroup_path: cgroup_path.to_owned(),
            signaled_pids: 1,
            force_killed_pids: 0,
        })
    }
}

async fn spawn_server(
    service: TrustdService<FakeAttestor, FakeQuoter>,
) -> (
    proto::trustd_client::TrustdClient<tonic::transport::Channel>,
    oneshot::Sender<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TCP listener should bind");
    let address = listener
        .local_addr()
        .expect("local addr should be available");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        Server::builder()
            .add_service(proto::trustd_server::TrustdServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should stop cleanly");
    });

    let endpoint = format!("http://{address}");
    let client = proto::trustd_client::TrustdClient::connect(endpoint)
        .await
        .expect("client should connect");

    (client, shutdown_tx)
}

#[tokio::test]
async fn ping_over_grpc() {
    let state = Arc::new(StateManager::new());
    state.update_from_securityfs("cg1", "rtmr", "initial", 2);

    let service = TrustdService::new(
        Arc::new(FakeAttestor),
        Arc::new(FakeQuoter { available: true }),
        Arc::new(FakeRestarter),
        state,
        EventBus::new(16),
        "test-version",
    );

    let (mut client, shutdown_tx) = spawn_server(service).await;

    let ping = client
        .ping(proto::PingRequest {})
        .await
        .expect("ping should succeed")
        .into_inner();
    assert_eq!(ping.version, "test-version");
    assert_eq!(ping.containers_tracked, 1);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn watch_events_stream_filters_by_type() {
    let service = TrustdService::new(
        Arc::new(FakeAttestor),
        Arc::new(FakeQuoter { available: true }),
        Arc::new(FakeRestarter),
        Arc::new(StateManager::new()),
        EventBus::new(16),
        "test-version",
    );
    let publisher = service.clone();

    let (mut client, shutdown_tx) = spawn_server(service).await;
    let response = client
        .watch_container_events(proto::WatchEventsRequest {
            event_types: vec![proto::EventType::Measurement as i32],
            cgroup_path: String::new(),
        })
        .await
        .expect("watch request should succeed");
    let mut stream = response.into_inner();

    publisher.publish_event(ContainerEvent::new(ContainerEventKind::New, "cg1"));
    publisher.publish_event(ContainerEvent::new(ContainerEventKind::Measurement, "cg1"));

    let event = timeout(Duration::from_secs(1), stream.message())
        .await
        .expect("event should arrive before timeout")
        .expect("stream should not fail")
        .expect("event should be present");

    assert_eq!(event.event_type, proto::EventType::Measurement as i32);
    assert_eq!(event.cgroup_path, "cg1");

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn restart_container_over_grpc() {
    let state = Arc::new(StateManager::new());
    state.update_from_securityfs("cg1", "rtmr", "initial", 2);

    let service = TrustdService::new(
        Arc::new(FakeAttestor),
        Arc::new(FakeQuoter { available: true }),
        Arc::new(FakeRestarter),
        state,
        EventBus::new(16),
        "test-version",
    );

    let (mut client, shutdown_tx) = spawn_server(service).await;
    let response = client
        .restart_container(proto::GetContainerStateRequest {
            cgroup_path: "cg1".to_owned(),
        })
        .await
        .expect("restart RPC should succeed")
        .into_inner();

    assert_eq!(response.cgroup_path, "cg1");
    assert_eq!(response.measurement_count, 0);

    let _ = shutdown_tx.send(());
}
