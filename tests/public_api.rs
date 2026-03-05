use trustd::event_bus::{ContainerEvent, ContainerEventKind, EventBus};
use trustd::state::StateManager;

#[test]
fn state_manager_public_api_roundtrip() {
    let manager = StateManager::new();

    manager.update_from_securityfs("/kubepods/pod-1", "rtmr", "initial", 3);
    manager.record_heartbeat("/kubepods/pod-1");
    manager.start_heartbeat_monitor("/kubepods/pod-1", 20);

    let state = manager
        .get("/kubepods/pod-1")
        .expect("container state should exist");

    assert_eq!(state.measurement_count, 3);
    assert_eq!(state.heartbeat_count, 1);
    assert!(state.heartbeat_monitoring);
}

#[tokio::test]
async fn event_bus_public_api_broadcasts() {
    let bus = EventBus::new(8);
    let mut rx = bus.subscribe();

    bus.publish(ContainerEvent::new(
        ContainerEventKind::Measurement,
        "/kubepods/pod-2",
    ));

    let event = rx.recv().await.expect("event should be received");
    assert_eq!(event.kind, ContainerEventKind::Measurement);
    assert_eq!(event.cgroup_path, "/kubepods/pod-2");
}
