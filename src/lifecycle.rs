//! Container lifecycle manager.
//!
//! Coordinates container creation, readiness detection, and enhanced
//! remediation (recreate-from-spec) using the [`ContainerRuntime`] trait
//! and the [`SpecStore`].
//!
//! The lifecycle manager is the implementation behind the `StartContainer`,
//! `StopContainer`, and enhanced `RestartContainer` gRPC handlers. It also
//! spawns a per-container log watcher task that detects the
//! `[TRUSTWEAVE_READY]` marker and transitions the container to the READY
//! phase.
//!
//! # State machine
//!
//! ```text
//!          StartContainer
//!               │
//!               ▼
//!           ┌────────┐
//!           │PENDING │
//!           └───┬────┘
//!     create+start ok │          create/start fail
//!               ▼                        ▼
//!          ┌─────────┐            ┌──────────┐
//!          │ RUNNING │            │  FAILED  │
//!          └────┬────┘            └──────────┘
//!    [READY] marker │
//!               ▼
//!          ┌─────────┐
//!          │  READY  │
//!    ┌─────└────┬────┘
//!    │    attest ok │      attest fail
//!    │          ▼               ▼
//!    │     ┌─────────┐    ┌───────────┐
//!    │     │ TRUSTED │    │ UNTRUSTED │
//!    │     └────┬────┘    └─────┬─────┘
//!    │          │ secfs change  │ remediate
//!    │          ▼               ▼
//!    │     ┌───────────┐  ┌────────────┐
//!    │     │ UNTRUSTED │  │REMEDIATING │
//!    │     └─────┬─────┘  └──────┬─────┘
//!    │           │ remediate     │ new container starts
//!    │           ▼               ▼
//!    │     ┌────────────┐  ┌─────────┐
//!    │     │REMEDIATING │  │ RUNNING │ ← cycle continues
//!    │     └────────────┘  └─────────┘
//!    │
//!    │  StopContainer
//!    └──▶ ┌─────────┐
//!         │ STOPPED │
//!         └─────────┘
//! ```
//!
//! Phase transitions are validated: illegal transitions are logged and
//! rejected (e.g., STOPPED → RUNNING is not allowed without a new
//! StartContainer call).

use crate::event_bus::EventBus;
use crate::runtime::{ContainerRuntime, ContainerSpec, RuntimeError, StartResult};
use crate::spec_store::SpecStore;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Container phase — mirrors the proto `ContainerPhase` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Unmanaged,
    Pending,
    Running,
    Ready,
    Trusted,
    Untrusted,
    Remediating,
    Stopped,
    Failed,
}

impl Phase {
    /// Check whether transitioning from `self` to `target` is legal.
    pub fn can_transition_to(self, target: Phase) -> bool {
        use Phase::*;
        matches!(
            (self, target),
            (Pending, Running)
                | (Pending, Failed)
                | (Running, Ready)
                | (Running, Failed)
                | (Running, Stopped)
                | (Ready, Trusted)
                | (Ready, Untrusted)
                | (Ready, Stopped)
                | (Trusted, Untrusted)
                | (Trusted, Stopped)
                | (Untrusted, Remediating)
                | (Untrusted, Stopped)
                | (Remediating, Running)
                | (Remediating, Failed)
                | (Remediating, Stopped)
                // Unmanaged containers (not started by trustd) can only be
                // observed, not lifecycle-managed.
                | (Unmanaged, Unmanaged)
        )
    }

    pub fn to_proto(self) -> i32 {
        match self {
            Phase::Unmanaged => 0,
            Phase::Pending => 1,
            Phase::Running => 2,
            Phase::Ready => 3,
            Phase::Trusted => 4,
            Phase::Untrusted => 5,
            Phase::Remediating => 6,
            Phase::Stopped => 7,
            Phase::Failed => 8,
        }
    }
}

/// Manages the lifecycle of containers inside the CVM.
pub struct LifecycleManager {
    runtime: Arc<dyn ContainerRuntime>,
    spec_store: Arc<SpecStore>,
    event_bus: Arc<EventBus>,
    /// Callback to update the phase in the state manager. We take a closure
    /// rather than importing `StateManager` directly to keep the dependency
    /// unidirectional (lifecycle → state, never state → lifecycle).
    set_phase: Box<dyn Fn(&str, Phase, &str) + Send + Sync>,
}

impl LifecycleManager {
    pub fn new(
        runtime: Arc<dyn ContainerRuntime>,
        spec_store: Arc<SpecStore>,
        event_bus: Arc<EventBus>,
        set_phase: Box<dyn Fn(&str, Phase, &str) + Send + Sync>,
    ) -> Self {
        Self {
            runtime,
            spec_store,
            event_bus,
            set_phase,
        }
    }

    /// Start a container from a spec.
    pub async fn start_container(&self, spec: ContainerSpec) -> Result<StartResult, RuntimeError> {
        info!(container = %spec.name, image = %spec.image, "starting container");
        (self.set_phase)(&spec.name, Phase::Pending, "");

        let result = self.runtime.create_and_start(&spec).await;

        match &result {
            Ok(r) => {
                info!(
                    container = %spec.name,
                    id = %r.container_id,
                    cgroup = %r.cgroup_path,
                    "container running"
                );
                self.spec_store
                    .insert(spec.clone(), &r.cgroup_path, &r.container_id);
                (self.set_phase)(&spec.name, Phase::Running, &r.cgroup_path);

                // Spawn a log watcher to detect [TRUSTWEAVE_READY].
                let since = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
                    - 5; // look back 5s in case the marker was emitted fast
                self.spawn_ready_watcher(spec.name.clone(), spec.ready_marker.clone(), since);
            }
            Err(e) => {
                error!(container = %spec.name, error = %e, "start failed");
                (self.set_phase)(&spec.name, Phase::Failed, "");
            }
        }

        result
    }

    /// Stop and remove a container.
    pub async fn stop_container(&self, name: &str, timeout_secs: u32) -> Result<(), RuntimeError> {
        info!(container = %name, "stopping container");
        self.runtime.stop_and_remove(name, timeout_secs).await?;
        self.spec_store.remove(name);
        (self.set_phase)(name, Phase::Stopped, "");
        Ok(())
    }

    /// Enhanced remediation: stop + remove + recreate from the stored spec.
    /// Returns the new `StartResult` or an error if recreation fails.
    pub async fn remediate_recreate(
        &self,
        name: &str,
    ) -> Result<StartResult, RuntimeError> {
        let spec = self
            .spec_store
            .get_by_name(name)
            .ok_or_else(|| RuntimeError::Create(format!("no stored spec for {name}")))?;

        info!(container = %name, "remediating: stop + remove + recreate");
        (self.set_phase)(name, Phase::Remediating, "");

        // Stop the old container.
        if let Err(e) = self.runtime.stop_and_remove(name, 10).await {
            warn!(container = %name, error = %e, "stop during remediation (continuing)");
        }

        // Start a fresh one from the stored spec.
        let result = self.runtime.create_and_start(&spec).await;
        match &result {
            Ok(r) => {
                self.spec_store
                    .update_cgroup(name, &r.cgroup_path, &r.container_id);
                (self.set_phase)(name, Phase::Running, &r.cgroup_path);

                let since = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
                    - 5;
                self.spawn_ready_watcher(spec.name.clone(), spec.ready_marker.clone(), since);
            }
            Err(e) => {
                error!(container = %name, error = %e, "recreate failed");
                (self.set_phase)(name, Phase::Failed, "");
            }
        }
        result
    }

    /// Spawn a tokio task that tails the container's stdout via the
    /// runtime's log stream, looking for the ready marker. When found,
    /// transitions the container to Phase::Ready and emits EVENT_TYPE_READY.
    fn spawn_ready_watcher(&self, name: String, marker: String, since: i64) {
        let runtime = Arc::clone(&self.runtime);
        let event_bus = Arc::clone(&self.event_bus);
        let set_phase = {
            // We can't move `self.set_phase` into the spawned task (it's
            // behind a &self). Instead, clone the name and emit the phase
            // change via the event bus; the service layer listens and
            // updates the state manager.
            let name = name.clone();
            let bus = Arc::clone(&self.event_bus);
            move |phase: Phase| {
                let mut ev = crate::event_bus::ContainerEvent::new(
                    crate::event_bus::ContainerEventKind::PhaseChange,
                    "",
                );
                ev.container_name = Some(name.clone());
                ev.phase = Some(phase);
                bus.publish(ev);
            }
        };

        tokio::spawn(async move {
            let rx = match runtime.stream_logs(&name, since).await {
                Ok(rx) => rx,
                Err(e) => {
                    warn!(container = %name, error = %e, "log stream failed, skipping ready detection");
                    return;
                }
            };
            let mut rx = rx;
            while let Some(line) = rx.recv().await {
                if line.contains(&marker) {
                    info!(container = %name, "ready marker detected");
                    set_phase(Phase::Ready);
                    let mut ev = crate::event_bus::ContainerEvent::new(
                        crate::event_bus::ContainerEventKind::Ready,
                        "",
                    );
                    ev.container_name = Some(name.clone());
                    ev.phase = Some(Phase::Ready);
                    event_bus.publish(ev);
                    return;
                }
            }
            warn!(container = %name, "log stream ended without ready marker");
        });
    }
}

impl std::fmt::Debug for LifecycleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleManager").finish()
    }
}
