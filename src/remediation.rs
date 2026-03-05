use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use crate::error::{AgentError, Result};

pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const DEFAULT_TERM_GRACE: Duration = Duration::from_secs(2);
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartResult {
    pub cgroup_path: String,
    pub signaled_pids: i64,
    pub force_killed_pids: i64,
}

pub trait ContainerRestarter: Send + Sync + std::fmt::Debug {
    fn restart(&self, cgroup_path: &str) -> Result<RestartResult>;
}

#[derive(Debug, Clone)]
pub struct CgroupProcessRestarter {
    cgroup_root: PathBuf,
    term_grace: Duration,
    poll_interval: Duration,
}

impl CgroupProcessRestarter {
    pub fn new(cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            term_grace: DEFAULT_TERM_GRACE,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    pub fn with_timing(mut self, term_grace: Duration, poll_interval: Duration) -> Self {
        self.term_grace = term_grace.max(Duration::from_millis(1));
        self.poll_interval = poll_interval.max(Duration::from_millis(1));
        self
    }

    fn cgroup_procs_path(&self, cgroup_path: &str) -> Result<PathBuf> {
        let relative = sanitize_cgroup_path(cgroup_path)?;
        let procs = self.cgroup_root.join(&relative).join("cgroup.procs");
        if procs.exists() {
            return Ok(procs);
        }

        let tasks = self.cgroup_root.join(relative).join("tasks");
        if tasks.exists() {
            return Ok(tasks);
        }

        Err(AgentError::Unavailable(format!(
            "container cgroup does not exist: {cgroup_path}"
        )))
    }

    fn read_pids(&self, cgroup_path: &str) -> Result<Vec<i32>> {
        let path = self.cgroup_procs_path(cgroup_path)?;
        read_pid_file(path.as_path())
    }
}

impl Default for CgroupProcessRestarter {
    fn default() -> Self {
        Self::new(DEFAULT_CGROUP_ROOT)
    }
}

impl ContainerRestarter for CgroupProcessRestarter {
    fn restart(&self, cgroup_path: &str) -> Result<RestartResult> {
        let mut pids = self.read_pids(cgroup_path)?;
        pids.sort_unstable();
        pids.dedup();

        if pids.is_empty() {
            return Err(AgentError::Unavailable(format!(
                "no running process in cgroup {cgroup_path}"
            )));
        }

        let mut signaled = 0_i64;
        for pid in &pids {
            if send_signal(*pid, Signal::SIGTERM)? {
                signaled += 1;
            }
        }

        let tracked: HashSet<i32> = pids.into_iter().collect();
        let deadline = Instant::now() + self.term_grace;

        loop {
            let current = match self.read_pids(cgroup_path) {
                Ok(current) => current,
                Err(AgentError::Unavailable(_)) => Vec::new(),
                Err(error) => return Err(error),
            };

            let alive: Vec<i32> = current
                .into_iter()
                .filter(|pid| tracked.contains(pid))
                .collect();
            if alive.is_empty() {
                return Ok(RestartResult {
                    cgroup_path: cgroup_path.to_owned(),
                    signaled_pids: signaled,
                    force_killed_pids: 0,
                });
            }

            if Instant::now() >= deadline {
                let mut force_killed = 0_i64;
                for pid in alive {
                    if send_signal(pid, Signal::SIGKILL)? {
                        force_killed += 1;
                    }
                }

                return Ok(RestartResult {
                    cgroup_path: cgroup_path.to_owned(),
                    signaled_pids: signaled,
                    force_killed_pids: force_killed,
                });
            }

            thread::sleep(self.poll_interval);
        }
    }
}

fn sanitize_cgroup_path(cgroup_path: &str) -> Result<PathBuf> {
    if cgroup_path.trim().is_empty() {
        return Err(AgentError::InvalidInput(
            "cgroup_path is required".to_owned(),
        ));
    }

    let mut clean = PathBuf::new();
    for component in Path::new(cgroup_path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(segment) => clean.push(segment),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(AgentError::InvalidInput(format!(
                    "invalid cgroup_path: {cgroup_path}"
                )));
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err(AgentError::InvalidInput(format!(
            "invalid cgroup_path: {cgroup_path}"
        )));
    }

    Ok(clean)
}

fn read_pid_file(path: &Path) -> Result<Vec<i32>> {
    let content = fs::read_to_string(path).map_err(|error| AgentError::io(path, error))?;
    parse_pid_lines(content.as_str())
}

fn parse_pid_lines(content: &str) -> Result<Vec<i32>> {
    let mut pids = Vec::new();
    for raw in content.lines() {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }

        let pid = value
            .parse::<i32>()
            .map_err(|error| AgentError::Parse(format!("invalid pid value {value}: {error}")))?;
        if pid <= 0 {
            return Err(AgentError::Parse(format!(
                "invalid pid value {value}: pid must be positive"
            )));
        }
        pids.push(pid);
    }
    Ok(pids)
}

fn send_signal(pid: i32, signal: Signal) -> Result<bool> {
    match kill(Pid::from_raw(pid), signal) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(AgentError::Internal(format!(
            "failed to send {signal:?} to pid {pid}: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{parse_pid_lines, sanitize_cgroup_path};

    #[test]
    fn sanitize_cgroup_path_rejects_parent_traversal() {
        let err = sanitize_cgroup_path("../escape").expect_err("path must be rejected");
        assert!(err.to_string().contains("invalid cgroup_path"));
    }

    #[test]
    fn sanitize_cgroup_path_normalizes_rooted_path() {
        let path = sanitize_cgroup_path("/kubepods.slice/pod123").expect("path should parse");
        assert_eq!(path.to_string_lossy(), "kubepods.slice/pod123");
    }

    #[test]
    fn parse_pid_lines_accepts_valid_input() {
        let parsed = parse_pid_lines("123\n456\n").expect("pid list should parse");
        assert_eq!(parsed, vec![123, 456]);
    }

    #[test]
    fn parse_pid_lines_rejects_non_numeric_input() {
        let err = parse_pid_lines("abc\n").expect_err("input should fail");
        assert!(err.to_string().contains("invalid pid value"));
    }

    #[test]
    fn parse_pid_file_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir should exist");
        let file = dir.path().join("cgroup.procs");
        fs::write(&file, "7\n8\n").expect("write should succeed");
        let parsed = super::read_pid_file(&file).expect("file should parse");
        assert_eq!(parsed, vec![7, 8]);
    }
}
