use std::error::Error;
#[cfg(feature = "vsock")]
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "vsock")]
use std::task::{Context, Poll};
use std::time::Duration;

use clap::Parser;
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::{info, warn};

use trustd::config::Config;
use trustd::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use trustd::lifecycle::{LifecycleManager, Phase};
use trustd::liveness::{CgroupProcessProbe, SelfHeartbeatReporter};
use trustd::proto;
use trustd::remediation::CgroupProcessRestarter;
use trustd::runtime::DockerRuntime;
use trustd::securityfs::{Attestor, KernelSecurityFsAttestor, KernelSecurityFsReader};
use trustd::service::TrustdService;
use trustd::spec_store::SpecStore;
use trustd::state::StateManager;
use trustd::config::QuoteBackend;
use trustd::tdquote::{DynQuoter, QuoteProvider, TsmQuoter};
use trustd::unix_rpc;
use trustd::vsock_quote::{TDX_GUEST_DEVICE, VsockQuoter};
use trustd::watcher::MeasurementWatcher;

#[cfg(not(feature = "vsock"))]
compile_error!("trustd must be built with the `vsock` feature enabled");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    let config = Config::parse();

    info!(version = env!("CARGO_PKG_VERSION"), "trustd starting");

    let state = Arc::new(StateManager::new());
    let events = EventBus::new(1024);
    let attestor = Arc::new(KernelSecurityFsAttestor::new(config.attest_path.clone()));
    let reader = Arc::new(KernelSecurityFsReader::new(config.rtmr_path.clone()));
    // Backend selection — `Tsm` keeps the configfs-tsm path (1-sec kernel
    // poll, ≈1024 ms/quote) so existing v1 baselines remain reproducible.
    // `Vsock` switches to the AF_VSOCK QGS path documented in the Intel
    // TDX DCAP Quote Library API spec (≈3-6 ms/quote, no kernel poll).
    // `Auto` prefers vsock when /dev/tdx_guest is present.
    let quoter = Arc::new(match config.quote_backend {
        QuoteBackend::Tsm => DynQuoter::Tsm(TsmQuoter::new(config.tsm_path.clone())),
        QuoteBackend::Vsock => DynQuoter::Vsock(VsockQuoter::new(
            config.qgs_vsock_cid,
            config.qgs_vsock_port,
        )),
        QuoteBackend::Auto => {
            if std::path::Path::new(TDX_GUEST_DEVICE).exists() {
                info!(
                    cid = config.qgs_vsock_cid,
                    port = config.qgs_vsock_port,
                    "quote backend: vsock-direct (auto-selected; /dev/tdx_guest present)"
                );
                DynQuoter::Vsock(VsockQuoter::new(
                    config.qgs_vsock_cid,
                    config.qgs_vsock_port,
                ))
            } else {
                info!(
                    path = %config.tsm_path.display(),
                    "quote backend: TSM configfs (auto-selected; /dev/tdx_guest missing)"
                );
                DynQuoter::Tsm(TsmQuoter::new(config.tsm_path.clone()))
            }
        }
    });
    let restarter = Arc::new(CgroupProcessRestarter::default());

    let mut service = TrustdService::new(
        attestor,
        quoter,
        restarter,
        Arc::clone(&state),
        events.clone(),
        env!("CARGO_PKG_VERSION"),
    );

    // Wire up the container lifecycle manager. Without this the
    // StartContainer / StopContainer RPCs return UNAVAILABLE with
    // "lifecycle manager not initialized", and every call from
    // virt-handler fails. DockerRuntime::new() opens a bollard client
    // against /var/run/docker.sock — if Docker isn't running (or the
    // socket isn't there yet), we surface a warning and keep the
    // attestation/measurement path alive, but RPCs will still fail
    // until an operator restarts trustd.
    match DockerRuntime::new() {
        Ok(runtime) => {
            let spec_store = Arc::new(SpecStore::new());
            let state_for_phase = Arc::clone(&state);
            let lifecycle = Arc::new(LifecycleManager::new(
                Arc::new(runtime),
                Arc::clone(&spec_store),
                Arc::new(events.clone()),
                Box::new(move |name, phase, cgroup| {
                    state_for_phase.set_phase(name, phase, cgroup);
                }),
            ));
            service.set_lifecycle(lifecycle, spec_store);
            info!("lifecycle manager initialized (bollard → /var/run/docker.sock)");
        }
        Err(e) => {
            warn!(error = %e, "DockerRuntime init failed — StartContainer/StopContainer RPCs will be Unavailable");
        }
    }

    let cancel = CancellationToken::new();
    // Watcher spawn is gated on MeasurementMode. `Off` leaves it unspawned so
    // trustd only runs the lifecycle surface (StartContainer/StopContainer +
    // attestation RPCs on demand). That's the "lifecycle-only" mode used by
    // cold-start / runtime-QPS benchmarks to isolate the cost of measurement
    // and remediation from the cost of the container lifecycle itself.
    let (watcher_handle, drift_detector_handle) = if config.measurement_mode.watcher_enabled() {
        info!(
            mode = ?config.measurement_mode,
            "measurement watcher enabled"
        );
        let watcher = MeasurementWatcher::new(
            reader,
            Arc::clone(&state),
            events.clone(),
            config.poll_timeout_ms,
        );
        let watcher_h = tokio::spawn(watcher.run(cancel.clone()));
        let drift_h = tokio::spawn(run_drift_detector(
            events.clone(),
            Arc::clone(&state),
            cancel.clone(),
        ));
        (Some(watcher_h), Some(drift_h))
    } else {
        info!("measurement watcher disabled (measurement_mode=Off)");
        (None, None)
    };
    let self_heartbeat_handle = if config.self_heartbeat_enabled {
        let interval = Duration::from_secs(config.self_heartbeat_interval_seconds.max(1));
        info!(
            interval_seconds = interval.as_secs(),
            auto_monitor = config.self_heartbeat_auto_monitor,
            monitor_timeout_seconds = config.self_heartbeat_timeout_seconds,
            cgroup_root = %config.cgroup_root_path.display(),
            "self-heartbeat reporter enabled"
        );
        let probe = Arc::new(CgroupProcessProbe::new(config.cgroup_root_path.clone()));
        let reporter = SelfHeartbeatReporter::new(
            probe,
            Arc::clone(&state),
            events.clone(),
            interval,
            config.self_heartbeat_auto_monitor,
            config.self_heartbeat_timeout_seconds,
        );
        Some(tokio::spawn(reporter.run(cancel.clone())))
    } else {
        None
    };

    let grpc_service = proto::trustd_server::TrustdServer::new(service.clone());

    // Spawn Unix socket listener alongside vsock
    let unix_handle = tokio::spawn(serve_unix(
        service,
        config.unix_socket_path.clone(),
        cancel.clone(),
    ));

    let serve_result = serve_vsock(grpc_service, config.vsock_port, cancel.clone()).await;

    if let Err(error) = serve_result {
        warn!(error = %error, "server exited with error");
    }

    cancel.cancel();
    if let Some(handle) = watcher_handle {
        handle.await.map_err(Box::<dyn Error>::from)?;
    }
    if let Some(handle) = drift_detector_handle {
        handle.await.map_err(Box::<dyn Error>::from)?;
    }
    if let Some(handle) = self_heartbeat_handle {
        handle.await.map_err(Box::<dyn Error>::from)?;
    }
    unix_handle.await.map_err(Box::<dyn Error>::from)?;

    Ok(())
}

/// Promotes `Trusted → Untrusted` when the watcher reports a post-attest
/// measurement delta. This is the "event log drifted while we thought the
/// workload was trusted" signal — it does not itself remediate; it flips
/// Phase and republishes a `PhaseChange` event so virt-handler's
/// `SubscribeEvents` stream sees it and runs policy (Alert / Restart / Kill).
///
/// Only Measurement events count as drift. HeartbeatMiss is a separate
/// liveness signal with different semantics.
async fn run_drift_detector(
    events: EventBus,
    state: Arc<trustd::state::StateManager>,
    cancel: CancellationToken,
) {
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = events.subscribe();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            recv = rx.recv() => match recv {
                Err(RecvError::Closed) => return,
                Err(RecvError::Lagged(skipped)) => {
                    warn!(skipped, "drift detector lagged on event bus");
                    continue;
                }
                Ok(event) => {
                    if event.kind != ContainerEventKind::Measurement {
                        continue;
                    }
                    let Some(prev) = state.get(&event.cgroup_path) else { continue };
                    if prev.phase != Phase::Trusted {
                        continue;
                    }
                    if prev.container_name.is_empty() {
                        warn!(
                            cgroup = %event.cgroup_path,
                            "drift on unmanaged container; cannot transition phase"
                        );
                        continue;
                    }
                    state.set_phase(&prev.container_name, Phase::Untrusted, &event.cgroup_path);
                    let mut out = ContainerEvent::new(
                        ContainerEventKind::PhaseChange,
                        event.cgroup_path.clone(),
                    );
                    out.container_name = Some(prev.container_name.clone());
                    out.phase = Some(Phase::Untrusted);
                    out.detail = event.detail.clone();
                    events.publish(out);
                    info!(
                        container = %prev.container_name,
                        cgroup = %event.cgroup_path,
                        count = ?event.measurement_count,
                        "phase Trusted → Untrusted (measurement drift)"
                    );
                }
            }
        }
    }
}

async fn serve_unix<A, Q>(
    service: TrustdService<A, Q>,
    socket_path: std::path::PathBuf,
    cancel: CancellationToken,
) where
    A: Attestor + 'static,
    Q: QuoteProvider + 'static,
{
    // Remove stale socket file if it exists
    if socket_path.exists() {
        if let Err(e) = std::fs::remove_file(&socket_path) {
            warn!(error = %e, path = %socket_path.display(), "failed to remove stale socket");
            return;
        }
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, path = %socket_path.display(), "failed to bind unix socket");
            return;
        }
    };

    // Set permissions to 0o660 so container processes can connect
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        if let Err(e) = std::fs::set_permissions(&socket_path, perms) {
            warn!(error = %e, "failed to set socket permissions");
        }
    }

    info!(path = %socket_path.display(), "listening on Unix socket");

    let state = service.state_manager();
    let quoter = Arc::clone(service.quoter());
    let restarter = Arc::clone(service.restarter());
    let spec_store = service.spec_store();
    let version = Arc::from(service.version_str());
    let started_at = service.started_at();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        let quoter = Arc::clone(&quoter);
                        let restarter = Arc::clone(&restarter);
                        let spec_store = Arc::clone(&spec_store);
                        let version = Arc::clone(&version);
                        tokio::spawn(unix_rpc::handle_connection(
                            stream, state, quoter, restarter, spec_store, version, started_at,
                        ));
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to accept unix connection");
                    }
                }
            }
            _ = cancel.cancelled() => {
                break;
            }
        }
    }

    // Clean up socket file
    let _ = std::fs::remove_file(&socket_path);
    info!("unix socket listener stopped");
}

async fn shutdown_signal(cancel: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term_signal = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term_signal.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    cancel.cancel();
    info!("shutdown signal received");
}

#[cfg(feature = "vsock")]
async fn serve_vsock<A, Q>(
    service: proto::trustd_server::TrustdServer<TrustdService<A, Q>>,
    port: u32,
    cancel: CancellationToken,
) -> Result<(), Box<dyn Error>>
where
    A: Attestor + 'static,
    Q: QuoteProvider + 'static,
{
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_stream::StreamExt;
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
    use tonic::transport::server::Connected;

    struct ConnectedVsockStream(tokio_vsock::VsockStream);

    impl Connected for ConnectedVsockStream {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    impl AsyncRead for ConnectedVsockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ConnectedVsockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
    info!(port, "listening on VSOCK");
    let incoming = listener
        .incoming()
        .map(|result| result.map(ConnectedVsockStream));

    Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, shutdown_signal(cancel))
        .await
        .map_err(Box::<dyn Error>::from)
}

#[cfg(not(feature = "vsock"))]
async fn serve_vsock<A, Q>(
    _service: proto::trustd_server::TrustdServer<TrustdService<A, Q>>,
    _port: u32,
    _cancel: CancellationToken,
) -> Result<(), Box<dyn Error>>
where
    A: Attestor + 'static,
    Q: QuoteProvider + 'static,
{
    Err("vsock support is required for trustd".into())
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}
