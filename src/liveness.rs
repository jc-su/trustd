use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::error::AgentError;
use crate::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use crate::state::StateManager;

pub trait LivenessProbe: Send + Sync {
    fn is_alive(&self, cgroup_path: &str) -> Result<bool, AgentError>;
}

#[derive(Debug, Clone)]
pub struct CgroupProcessProbe {
    cgroup_root: PathBuf,
}

impl CgroupProcessProbe {
    pub fn new(cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
        }
    }

    fn cgroup_dir(&self, cgroup_path: &str) -> PathBuf {
        self.cgroup_root.join(cgroup_path.trim_start_matches('/'))
    }

    fn has_processes(path: &Path) -> Result<Option<bool>, AgentError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let alive = contents.lines().any(|line| !line.trim().is_empty());
                Ok(Some(alive))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AgentError::io(path.to_path_buf(), error)),
        }
    }
}

impl LivenessProbe for CgroupProcessProbe {
    fn is_alive(&self, cgroup_path: &str) -> Result<bool, AgentError> {
        let dir = self.cgroup_dir(cgroup_path);

        let cgroup_procs = dir.join("cgroup.procs");
        if let Some(alive) = Self::has_processes(&cgroup_procs)? {
            return Ok(alive);
        }

        let tasks = dir.join("tasks");
        if let Some(alive) = Self::has_processes(&tasks)? {
            return Ok(alive);
        }

        Ok(false)
    }
}

#[derive(Debug)]
pub struct SelfHeartbeatReporter<P>
where
    P: LivenessProbe,
{
    probe: Arc<P>,
    state: Arc<StateManager>,
    events: EventBus,
    interval: Duration,
    auto_start_monitor: bool,
    monitor_timeout_seconds: u32,
}

impl<P> SelfHeartbeatReporter<P>
where
    P: LivenessProbe,
{
    pub fn new(
        probe: Arc<P>,
        state: Arc<StateManager>,
        events: EventBus,
        interval: Duration,
        auto_start_monitor: bool,
        monitor_timeout_seconds: u32,
    ) -> Self {
        Self {
            probe,
            state,
            events,
            interval,
            auto_start_monitor,
            monitor_timeout_seconds,
        }
    }

    pub async fn run(self, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = ticker.tick() => self.scan_once(),
            }
        }
    }

    fn scan_once(&self) {
        for snapshot in self.state.list() {
            if self.auto_start_monitor && !snapshot.heartbeat_monitoring {
                self.state
                    .start_heartbeat_monitor(&snapshot.cgroup_path, self.monitor_timeout_seconds);
            }

            if !self.state.is_monitored(&snapshot.cgroup_path) {
                continue;
            }

            match self.probe.is_alive(&snapshot.cgroup_path) {
                Ok(true) => {
                    self.state.record_heartbeat(&snapshot.cgroup_path);
                    if let Some(state) = self.state.get(&snapshot.cgroup_path) {
                        let mut event =
                            ContainerEvent::new(ContainerEventKind::Heartbeat, state.cgroup_path);
                        if !state.rtmr3.is_empty() {
                            event.rtmr3 = Some(state.rtmr3);
                        }
                        event.measurement_count = Some(state.measurement_count);
                        self.events.publish(event);
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(
                        error = %error,
                        cgroup_path = %snapshot.cgroup_path,
                        "self-heartbeat liveness probe failed"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use tempfile::tempdir;
    use tokio::time::timeout;

    use super::*;

    #[derive(Debug)]
    struct FakeProbe {
        alive: bool,
        calls: Mutex<Vec<String>>,
    }

    impl FakeProbe {
        fn new(alive: bool) -> Self {
            Self {
                alive,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl LivenessProbe for FakeProbe {
        fn is_alive(&self, cgroup_path: &str) -> Result<bool, AgentError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(cgroup_path.to_owned());
            Ok(self.alive)
        }
    }

    #[test]
    fn cgroup_process_probe_reads_cgroup_procs() {
        let dir = tempdir().expect("tempdir should be created");
        let cgroup = dir.path().join("demo.scope");
        std::fs::create_dir_all(&cgroup).expect("cgroup dir should be created");
        std::fs::write(cgroup.join("cgroup.procs"), "1234\n").expect("cgroup.procs should write");

        let probe = CgroupProcessProbe::new(dir.path());
        let alive = probe
            .is_alive("/demo.scope")
            .expect("probe should succeed for cgroup.procs");
        assert!(alive);
    }

    #[test]
    fn cgroup_process_probe_falls_back_to_tasks() {
        let dir = tempdir().expect("tempdir should be created");
        let cgroup = dir.path().join("demo.scope");
        std::fs::create_dir_all(&cgroup).expect("cgroup dir should be created");
        std::fs::write(cgroup.join("tasks"), "4321\n").expect("tasks should write");

        let probe = CgroupProcessProbe::new(dir.path());
        let alive = probe
            .is_alive("/demo.scope")
            .expect("probe should succeed for tasks");
        assert!(alive);
    }

    #[tokio::test]
    async fn self_heartbeat_reports_when_alive() {
        let state = Arc::new(StateManager::new());
        state.update_from_securityfs("/cg1", "rtmr", "init", 1);
        state.start_heartbeat_monitor("/cg1", 30);
        let events = EventBus::new(8);
        let probe = Arc::new(FakeProbe::new(true));
        let reporter = SelfHeartbeatReporter::new(
            Arc::clone(&probe),
            Arc::clone(&state),
            events.clone(),
            Duration::from_millis(5),
            false,
            30,
        );
        let cancel = CancellationToken::new();
        let mut rx = events.subscribe();

        let handle = tokio::spawn(reporter.run(cancel.clone()));
        let event = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("heartbeat event should arrive")
            .expect("event channel should remain open");
        cancel.cancel();
        handle.await.expect("reporter should stop cleanly");

        assert_eq!(event.kind, ContainerEventKind::Heartbeat);
        assert_eq!(event.cgroup_path, "/cg1");
        assert!(
            state
                .get("/cg1")
                .expect("state should exist")
                .heartbeat_count
                > 0
        );
        assert_eq!(probe.calls(), vec!["/cg1".to_owned()]);
    }

    #[test]
    fn self_heartbeat_auto_starts_monitor() {
        let state = Arc::new(StateManager::new());
        state.update_from_securityfs("/cg1", "rtmr", "init", 1);
        let events = EventBus::new(8);
        let probe = Arc::new(FakeProbe::new(true));
        let reporter = SelfHeartbeatReporter::new(
            probe,
            Arc::clone(&state),
            events,
            Duration::from_secs(1),
            true,
            77,
        );

        reporter.scan_once();
        let snapshot = state.get("/cg1").expect("state should exist");
        assert!(snapshot.heartbeat_monitoring);
        assert_eq!(snapshot.heartbeat_timeout_seconds, 77);
        assert_eq!(snapshot.heartbeat_count, 1);
    }
}
