//! In-memory store for container specs.
//!
//! When trustd starts a container via [`StartContainer`], the original
//! request is stored here. If remediation later needs to recreate the
//! container from scratch (RECREATE mode), it pulls the spec from this
//! store, stops the current container, and starts a fresh one from the
//! same inputs.

use crate::runtime::ContainerSpec;
use std::collections::HashMap;
use std::sync::RwLock;

/// Thread-safe spec store. Keyed by container name.
#[derive(Debug)]
pub struct SpecStore {

    by_name: RwLock<HashMap<String, StoredSpec>>,
}

#[derive(Debug)]
struct StoredSpec {
    spec: ContainerSpec,
    cgroup_path: String,
    container_id: String,
}

impl SpecStore {
    pub fn new() -> Self {
        Self {
            by_name: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a new spec (called after StartContainer succeeds).
    pub fn insert(&self, spec: ContainerSpec, cgroup_path: &str, container_id: &str) {
        let mut map = self.by_name.write().unwrap();
        map.insert(
            spec.name.clone(),
            StoredSpec {
                spec,
                cgroup_path: cgroup_path.to_string(),
                container_id: container_id.to_string(),
            },
        );
    }

    /// Get the spec by container name.
    pub fn get_by_name(&self, name: &str) -> Option<ContainerSpec> {
        self.by_name.read().unwrap().get(name).map(|s| s.spec.clone())
    }

    /// Get the spec by cgroup path (used by the remediation path, which
    /// is keyed by cgroup from the securityfs watcher).
    pub fn get_by_cgroup(&self, cgroup: &str) -> Option<ContainerSpec> {
        self.by_name
            .read()
            .unwrap()
            .values()
            .find(|s| s.cgroup_path == cgroup)
            .map(|s| s.spec.clone())
    }

    /// Look up the container name for a cgroup path.
    pub fn name_for_cgroup(&self, cgroup: &str) -> Option<String> {
        self.by_name
            .read()
            .unwrap()
            .values()
            .find(|s| s.cgroup_path == cgroup)
            .map(|s| s.spec.name.clone())
    }

    /// Look up the current cgroup path for a stable workload name.
    /// Returns None if the workload isn't registered or hasn't been
    /// assigned a cgroup yet (e.g., before the first StartContainer
    /// completed). Canonical accessor for AttestWorkload: trustd keeps
    /// the workload_id stable across restarts while the cgroup path
    /// rotates each time Docker assigns a new container ID.
    pub fn cgroup_for_name(&self, name: &str) -> Option<String> {
        self.by_name
            .read()
            .unwrap()
            .get(name)
            .map(|s| s.cgroup_path.clone())
            .filter(|p| !p.is_empty())
    }

    /// Update the cgroup path after a container is recreated (the new
    /// container gets a different cgroup than the old one).
    pub fn update_cgroup(&self, name: &str, new_cgroup: &str, new_id: &str) {
        if let Some(s) = self.by_name.write().unwrap().get_mut(name) {
            s.cgroup_path = new_cgroup.to_string();
            s.container_id = new_id.to_string();
        }
    }

    /// Remove a spec (called after StopContainer).
    pub fn remove(&self, name: &str) {
        self.by_name.write().unwrap().remove(name);
    }

    /// Return all stored specs with their cgroup paths.
    pub fn all(&self) -> Vec<(ContainerSpec, String)> {
        self.by_name
            .read()
            .unwrap()
            .values()
            .map(|s| (s.spec.clone(), s.cgroup_path.clone()))
            .collect()
    }

    /// Number of stored specs.
    pub fn len(&self) -> usize {
        self.by_name.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
