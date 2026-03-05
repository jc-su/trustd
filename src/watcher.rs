use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::error::{AgentError, Result};
use crate::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use crate::securityfs::{ContainerRtmrState, RtmrReader};
use crate::state::StateManager;

/// Poll-based watcher that keeps state in sync with kernel securityfs events.
#[derive(Debug)]
pub struct MeasurementWatcher<R>
where
    R: RtmrReader,
{
    reader: Arc<R>,
    state: Arc<StateManager>,
    events: EventBus,
    poll_timeout_ms: i32,
    error_backoff: Duration,
}

impl<R> MeasurementWatcher<R>
where
    R: RtmrReader + 'static,
{
    pub fn new(
        reader: Arc<R>,
        state: Arc<StateManager>,
        events: EventBus,
        poll_timeout_ms: i32,
    ) -> Self {
        Self {
            reader,
            state,
            events,
            poll_timeout_ms,
            error_backoff: Duration::from_secs(1),
        }
    }

    pub async fn run(self, cancel: CancellationToken) {
        let mut known: HashMap<String, i64> = HashMap::new();

        loop {
            if cancel.is_cancelled() {
                return;
            }

            let maybe_states =
                match wait_and_read_all(Arc::clone(&self.reader), self.poll_timeout_ms).await {
                    Ok(states) => states,
                    Err(error) => {
                        warn!(error = %error, "securityfs wait failed");
                        if cancelled_sleep(cancel.clone(), self.error_backoff).await {
                            return;
                        }
                        continue;
                    }
                };

            let states = match maybe_states {
                Some(states) => states,
                None => match read_all(Arc::clone(&self.reader)).await {
                    Ok(states) => states,
                    Err(error) => {
                        warn!(error = %error, "securityfs refresh read failed");
                        if cancelled_sleep(cancel.clone(), self.error_backoff).await {
                            return;
                        }
                        continue;
                    }
                },
            };

            let mut current = HashMap::with_capacity(states.len());

            for state in states {
                current.insert(state.cgroup_path.clone(), state.count);

                self.state.update_from_securityfs(
                    &state.cgroup_path,
                    &state.rtmr3,
                    &state.initial_rtmr3,
                    state.count,
                );

                match known.get(&state.cgroup_path).copied() {
                    None => {
                        let mut event =
                            ContainerEvent::new(ContainerEventKind::New, state.cgroup_path);
                        event.rtmr3 = Some(state.rtmr3);
                        event.measurement_count = Some(state.count);
                        self.events.publish(event);
                    }
                    Some(previous_count) if previous_count != state.count => {
                        let mut event =
                            ContainerEvent::new(ContainerEventKind::Measurement, state.cgroup_path);
                        event.rtmr3 = Some(state.rtmr3);
                        event.measurement_count = Some(state.count);
                        event.detail = Some(format!("count {previous_count} -> {}", state.count));
                        self.events.publish(event);
                    }
                    Some(_) => {}
                }
            }

            for cgroup in known.keys() {
                if current.contains_key(cgroup) {
                    continue;
                }

                self.state.remove(cgroup);
                self.events
                    .publish(ContainerEvent::new(ContainerEventKind::Removed, cgroup));
            }

            for cgroup in self.state.poll_heartbeat_misses(SystemTime::now()) {
                self.events.publish(ContainerEvent::new(
                    ContainerEventKind::HeartbeatMiss,
                    cgroup,
                ));
            }

            known = current;
        }
    }
}

async fn wait_and_read_all<R>(
    reader: Arc<R>,
    timeout_ms: i32,
) -> Result<Option<Vec<ContainerRtmrState>>>
where
    R: RtmrReader + 'static,
{
    tokio::task::spawn_blocking(move || reader.wait_and_read_all(timeout_ms))
        .await
        .map_err(|error| AgentError::Internal(format!("watcher join error: {error}")))?
}

async fn read_all<R>(reader: Arc<R>) -> Result<Vec<ContainerRtmrState>>
where
    R: RtmrReader + 'static,
{
    tokio::task::spawn_blocking(move || reader.read_all())
        .await
        .map_err(|error| AgentError::Internal(format!("watcher join error: {error}")))?
}

async fn cancelled_sleep(cancel: CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use tokio::time::{Duration, timeout};
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[derive(Debug)]
    struct FakeReader {
        wait_results: Mutex<VecDeque<Result<Option<Vec<ContainerRtmrState>>>>>,
        read_results: Mutex<VecDeque<Result<Vec<ContainerRtmrState>>>>,
    }

    impl FakeReader {
        fn new(
            wait_results: Vec<Result<Option<Vec<ContainerRtmrState>>>>,
            read_results: Vec<Result<Vec<ContainerRtmrState>>>,
        ) -> Self {
            Self {
                wait_results: Mutex::new(VecDeque::from(wait_results)),
                read_results: Mutex::new(VecDeque::from(read_results)),
            }
        }
    }

    impl RtmrReader for FakeReader {
        fn read_all(&self) -> Result<Vec<ContainerRtmrState>> {
            self.read_results
                .lock()
                .expect("read queue lock poisoned")
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
        }

        fn wait_and_read_all(&self, _timeout_ms: i32) -> Result<Option<Vec<ContainerRtmrState>>> {
            self.wait_results
                .lock()
                .expect("wait queue lock poisoned")
                .pop_front()
                .unwrap_or(Ok(None))
        }
    }

    fn state(cgroup_path: &str, count: i64) -> ContainerRtmrState {
        ContainerRtmrState {
            cgroup_path: cgroup_path.to_owned(),
            initial_rtmr3: "init".to_owned(),
            rtmr3: format!("rtmr-{count}"),
            count,
        }
    }

    #[tokio::test]
    async fn watcher_emits_new_and_measurement_events() {
        let reader = Arc::new(FakeReader::new(
            vec![
                Ok(Some(vec![state("cg1", 1)])),
                Ok(Some(vec![state("cg1", 2)])),
            ],
            vec![Ok(Vec::new())],
        ));
        let state_manager = Arc::new(StateManager::new());
        let bus = EventBus::new(16);
        let cancel = CancellationToken::new();

        let watcher = MeasurementWatcher::new(reader, Arc::clone(&state_manager), bus.clone(), 10);
        let handle = tokio::spawn(watcher.run(cancel.clone()));

        let mut rx = bus.subscribe();
        let first = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("first event should arrive")
            .expect("event channel should remain open");
        let second = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("second event should arrive")
            .expect("event channel should remain open");

        assert_eq!(first.kind, ContainerEventKind::New);
        assert_eq!(second.kind, ContainerEventKind::Measurement);
        assert_eq!(
            state_manager
                .get("cg1")
                .expect("state should exist")
                .measurement_count,
            2
        );

        cancel.cancel();
        handle.await.expect("watcher should stop cleanly");
    }

    #[tokio::test]
    async fn watcher_emits_removed_event() {
        let reader = Arc::new(FakeReader::new(
            vec![Ok(Some(vec![state("cg1", 1)])), Ok(Some(Vec::new()))],
            vec![Ok(Vec::new())],
        ));
        let state_manager = Arc::new(StateManager::new());
        let bus = EventBus::new(16);
        let cancel = CancellationToken::new();

        let watcher = MeasurementWatcher::new(reader, Arc::clone(&state_manager), bus.clone(), 10);
        let handle = tokio::spawn(watcher.run(cancel.clone()));

        let mut rx = bus.subscribe();
        let _ = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("new event should arrive");

        let removed = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("removed event should arrive")
            .expect("event channel should remain open");
        assert_eq!(removed.kind, ContainerEventKind::Removed);

        cancel.cancel();
        handle.await.expect("watcher should stop cleanly");
    }
}
