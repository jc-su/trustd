use std::time::SystemTime;

use tokio::sync::broadcast;

/// Agent event categories mapped to protobuf event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerEventKind {
    New,
    Measurement,
    Heartbeat,
    HeartbeatMiss,
    Removed,
    AttestBegin,
    AttestEnd,
    // Lifecycle events (emitted by the lifecycle manager, not the kernel):
    Ready,
    PhaseChange,
}

/// Runtime event emitted by the watcher, service, and lifecycle manager.
#[derive(Debug, Clone)]
pub struct ContainerEvent {
    pub kind: ContainerEventKind,
    pub cgroup_path: String,
    pub timestamp: SystemTime,
    pub digest: Option<String>,
    pub filename: Option<String>,
    pub detail: Option<String>,
    pub rtmr3: Option<String>,
    pub measurement_count: Option<i64>,
    // Lifecycle fields (populated only for Ready / PhaseChange events):
    pub container_name: Option<String>,
    pub phase: Option<crate::lifecycle::Phase>,
}

impl ContainerEvent {
    pub fn new(kind: ContainerEventKind, cgroup_path: impl Into<String>) -> Self {
        Self {
            kind,
            cgroup_path: cgroup_path.into(),
            timestamp: SystemTime::now(),
            digest: None,
            filename: None,
            detail: None,
            rtmr3: None,
            measurement_count: None,
            container_name: None,
            phase: None,
        }
    }
}

/// Broadcast-based event bus used by gRPC stream subscribers.
///
/// # Examples
///
/// ```
/// use trustd::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
///
/// let bus = EventBus::new(8);
/// bus.publish(ContainerEvent::new(ContainerEventKind::New, "/kubepods/pod1"));
/// let _subscriber = bus.subscribe();
/// ```
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<ContainerEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    pub fn publish(&self, event: ContainerEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ContainerEvent> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(128)
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainerEvent, ContainerEventKind, EventBus};

    #[tokio::test]
    async fn publish_and_receive_event() {
        let bus = EventBus::new(4);
        let mut rx = bus.subscribe();

        bus.publish(ContainerEvent::new(ContainerEventKind::New, "cg1"));

        let event = rx.recv().await.expect("event should arrive");
        assert_eq!(event.kind, ContainerEventKind::New);
        assert_eq!(event.cgroup_path, "cg1");
    }
}
