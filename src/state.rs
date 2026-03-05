use std::collections::HashMap;
use std::sync::RwLock;
use std::time::SystemTime;

const DEFAULT_HEARTBEAT_TIMEOUT_SECONDS: u32 = 90;

/// In-memory snapshot of one tracked container.
#[derive(Debug, Clone)]
pub struct ContainerState {
    pub cgroup_path: String,
    pub rtmr3: String,
    pub initial_rtmr3: String,
    pub measurement_count: i64,
    pub pending_rebootstrap: bool,
    pub last_heartbeat: Option<SystemTime>,
    pub heartbeat_count: i64,
    pub last_updated: SystemTime,
    pub heartbeat_monitoring: bool,
    pub heartbeat_timeout_seconds: u32,
    heartbeat_monitor_started_at: Option<SystemTime>,
    heartbeat_miss_active: bool,
}

impl ContainerState {
    fn new(cgroup_path: impl Into<String>) -> Self {
        Self {
            cgroup_path: cgroup_path.into(),
            rtmr3: String::new(),
            initial_rtmr3: String::new(),
            measurement_count: 0,
            pending_rebootstrap: false,
            last_heartbeat: None,
            heartbeat_count: 0,
            last_updated: SystemTime::now(),
            heartbeat_monitoring: false,
            heartbeat_timeout_seconds: DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
            heartbeat_monitor_started_at: None,
            heartbeat_miss_active: false,
        }
    }
}

/// Thread-safe cache for container attestation state.
///
/// # Examples
///
/// ```
/// use trustd::state::StateManager;
///
/// let manager = StateManager::new();
/// manager.update_from_securityfs("/kubepods/pod1", "rtmr", "initial", 7);
/// manager.record_heartbeat("/kubepods/pod1");
///
/// let pod = manager.get("/kubepods/pod1").expect("state should exist");
/// assert_eq!(pod.measurement_count, 7);
/// assert_eq!(manager.count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct StateManager {
    containers: RwLock<HashMap<String, ContainerState>>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
        }
    }

    pub fn update_from_securityfs(
        &self,
        cgroup_path: &str,
        rtmr3: &str,
        initial_rtmr3: &str,
        count: i64,
    ) {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on update");

        let state = guard
            .entry(cgroup_path.to_owned())
            .or_insert_with(|| ContainerState::new(cgroup_path));

        state.rtmr3 = rtmr3.to_owned();
        state.initial_rtmr3 = initial_rtmr3.to_owned();
        state.measurement_count = count;
        state.pending_rebootstrap = false;
        state.last_updated = SystemTime::now();
    }

    pub fn record_heartbeat(&self, cgroup_path: &str) {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on heartbeat");

        let state = guard
            .entry(cgroup_path.to_owned())
            .or_insert_with(|| ContainerState::new(cgroup_path));

        state.last_heartbeat = Some(SystemTime::now());
        state.heartbeat_count += 1;
        if state.heartbeat_monitor_started_at.is_none() {
            state.heartbeat_monitor_started_at = state.last_heartbeat;
        }
        state.heartbeat_miss_active = false;
        state.last_updated = SystemTime::now();
    }

    pub fn remove(&self, cgroup_path: &str) {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on remove");
        guard.remove(cgroup_path);
    }

    pub fn reset_for_remediation(&self, cgroup_path: &str) {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on remediation reset");

        let state = guard
            .entry(cgroup_path.to_owned())
            .or_insert_with(|| ContainerState::new(cgroup_path));

        state.rtmr3.clear();
        state.initial_rtmr3.clear();
        state.measurement_count = 0;
        state.pending_rebootstrap = true;
        state.last_heartbeat = None;
        state.heartbeat_count = 0;
        state.heartbeat_miss_active = false;
        if state.heartbeat_monitoring {
            state.heartbeat_monitor_started_at = Some(SystemTime::now());
        } else {
            state.heartbeat_monitor_started_at = None;
        }
        state.last_updated = SystemTime::now();
    }

    pub fn list(&self) -> Vec<ContainerState> {
        let guard = self
            .containers
            .read()
            .expect("state manager lock poisoned on list");

        let mut items: Vec<_> = guard.values().cloned().collect();
        items.sort_unstable_by(|a, b| a.cgroup_path.cmp(&b.cgroup_path));
        items
    }

    pub fn get(&self, cgroup_path: &str) -> Option<ContainerState> {
        self.containers
            .read()
            .expect("state manager lock poisoned on get")
            .get(cgroup_path)
            .cloned()
    }

    pub fn count(&self) -> usize {
        self.containers
            .read()
            .expect("state manager lock poisoned on count")
            .len()
    }

    pub fn start_heartbeat_monitor(&self, cgroup_path: &str, timeout_seconds: u32) {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on monitor start");

        let state = guard
            .entry(cgroup_path.to_owned())
            .or_insert_with(|| ContainerState::new(cgroup_path));

        state.heartbeat_monitoring = true;
        state.heartbeat_timeout_seconds = if timeout_seconds == 0 {
            DEFAULT_HEARTBEAT_TIMEOUT_SECONDS
        } else {
            timeout_seconds
        };
        state.heartbeat_monitor_started_at = Some(SystemTime::now());
        state.heartbeat_miss_active = false;
        state.last_updated = SystemTime::now();
    }

    pub fn stop_heartbeat_monitor(&self, cgroup_path: &str) {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on monitor stop");

        if let Some(state) = guard.get_mut(cgroup_path) {
            state.heartbeat_monitoring = false;
            state.heartbeat_monitor_started_at = None;
            state.heartbeat_miss_active = false;
            state.last_updated = SystemTime::now();
        }
    }

    pub fn is_monitored(&self, cgroup_path: &str) -> bool {
        self.containers
            .read()
            .expect("state manager lock poisoned on monitor check")
            .get(cgroup_path)
            .is_some_and(|state| state.heartbeat_monitoring)
    }

    pub fn poll_heartbeat_misses(&self, now: SystemTime) -> Vec<String> {
        let mut guard = self
            .containers
            .write()
            .expect("state manager lock poisoned on heartbeat miss poll");

        let mut misses = Vec::new();
        for (cgroup, state) in guard.iter_mut() {
            if !state.heartbeat_monitoring || state.heartbeat_miss_active {
                continue;
            }

            let Some(anchor) = state.last_heartbeat.or(state.heartbeat_monitor_started_at) else {
                continue;
            };
            let Ok(elapsed) = now.duration_since(anchor) else {
                continue;
            };
            if elapsed.as_secs() < u64::from(state.heartbeat_timeout_seconds) {
                continue;
            }

            state.heartbeat_miss_active = true;
            misses.push(cgroup.clone());
        }

        misses
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::StateManager;

    #[test]
    fn update_and_get_roundtrip() {
        let manager = StateManager::new();
        manager.update_from_securityfs("cg1", "rtmr", "init", 5);

        let state = manager.get("cg1").expect("state should exist");
        assert_eq!(state.cgroup_path, "cg1");
        assert_eq!(state.rtmr3, "rtmr");
        assert_eq!(state.initial_rtmr3, "init");
        assert_eq!(state.measurement_count, 5);
        assert!(!state.pending_rebootstrap);
    }

    #[test]
    fn heartbeat_increments_counter() {
        let manager = StateManager::new();
        manager.record_heartbeat("cg1");
        manager.record_heartbeat("cg1");

        let state = manager.get("cg1").expect("state should exist");
        assert_eq!(state.heartbeat_count, 2);
        assert!(state.last_heartbeat.is_some());
    }

    #[test]
    fn monitor_toggle_works() {
        let manager = StateManager::new();
        manager.start_heartbeat_monitor("cg1", 0);
        assert!(manager.is_monitored("cg1"));

        manager.stop_heartbeat_monitor("cg1");
        assert!(!manager.is_monitored("cg1"));
    }

    #[test]
    fn heartbeat_miss_detected_once_until_next_heartbeat() {
        let manager = StateManager::new();
        manager.start_heartbeat_monitor("cg1", 1);
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let misses = manager.poll_heartbeat_misses(SystemTime::now());
        assert_eq!(misses, vec!["cg1"]);

        let second = manager.poll_heartbeat_misses(SystemTime::now());
        assert!(second.is_empty());

        manager.record_heartbeat("cg1");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let after_hb = manager.poll_heartbeat_misses(SystemTime::now());
        assert_eq!(after_hb, vec!["cg1"]);
    }

    #[test]
    fn remove_deletes_state() {
        let manager = StateManager::new();
        manager.update_from_securityfs("cg1", "rtmr", "init", 1);
        assert_eq!(manager.count(), 1);

        manager.remove("cg1");
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn remediation_reset_clears_runtime_state_and_sets_pending() {
        let manager = StateManager::new();
        manager.update_from_securityfs("cg1", "rtmr", "init", 9);
        manager.record_heartbeat("cg1");
        manager.start_heartbeat_monitor("cg1", 1);

        manager.reset_for_remediation("cg1");
        let reset = manager.get("cg1").expect("state should exist");
        assert_eq!(reset.rtmr3, "");
        assert_eq!(reset.initial_rtmr3, "");
        assert_eq!(reset.measurement_count, 0);
        assert!(reset.pending_rebootstrap);
        assert!(reset.last_heartbeat.is_none());
        assert_eq!(reset.heartbeat_count, 0);

        manager.update_from_securityfs("cg1", "rtmr-new", "init-new", 2);
        let refreshed = manager.get("cg1").expect("state should exist");
        assert!(!refreshed.pending_rebootstrap);
        assert_eq!(refreshed.rtmr3, "rtmr-new");
        assert_eq!(refreshed.initial_rtmr3, "init-new");
        assert_eq!(refreshed.measurement_count, 2);
    }
}
