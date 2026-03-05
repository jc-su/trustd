use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use serde::Deserialize;

use crate::error::{AgentError, Result};

pub const DEFAULT_ATTEST_PATH: &str = "/sys/kernel/security/ima/container_attest";
pub const DEFAULT_RTMR_PATH: &str = "/sys/kernel/security/ima/container_rtmr";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub digest: String,
    pub file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationResponse {
    pub cgroup_path: String,
    pub initial_rtmr3: String,
    pub rtmr3: String,
    pub count: i64,
    pub nonce: String,
    pub report_data: String,
    pub timestamp: i64,
    pub measurements: Vec<Measurement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRtmrState {
    pub cgroup_path: String,
    pub initial_rtmr3: String,
    pub rtmr3: String,
    pub count: i64,
}

pub trait Attestor: Send + Sync {
    fn attest(&self, cgroup_path: &str, nonce_hex: &str) -> Result<AttestationResponse>;
}

pub trait RtmrReader: Send + Sync {
    fn read_all(&self) -> Result<Vec<ContainerRtmrState>>;
    fn wait_and_read_all(&self, timeout_ms: i32) -> Result<Option<Vec<ContainerRtmrState>>>;
    fn read_one(&self, cgroup_path: &str) -> Result<Option<ContainerRtmrState>> {
        Ok(self
            .read_all()?
            .into_iter()
            .find(|state| state.cgroup_path == cgroup_path))
    }
}

#[derive(Debug)]
pub struct KernelSecurityFsAttestor {
    attest_path: PathBuf,
    lock: Mutex<()>,
}

impl KernelSecurityFsAttestor {
    pub fn new(attest_path: impl Into<PathBuf>) -> Self {
        Self {
            attest_path: attest_path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn attest_path(&self) -> &Path {
        &self.attest_path
    }
}

impl Default for KernelSecurityFsAttestor {
    fn default() -> Self {
        Self::new(DEFAULT_ATTEST_PATH)
    }
}

impl Attestor for KernelSecurityFsAttestor {
    fn attest(&self, cgroup_path: &str, nonce_hex: &str) -> Result<AttestationResponse> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AgentError::Internal("attestor lock poisoned".to_owned()))?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.attest_path)
            .map_err(|source| AgentError::io(self.attest_path.clone(), source))?;

        let command = format!("attest {cgroup_path} {nonce_hex}");
        file.write_all(command.as_bytes())
            .map_err(|source| AgentError::io(self.attest_path.clone(), source))?;

        parse_attestation_reader(BufReader::new(file), &self.attest_path)
    }
}

#[derive(Debug)]
pub struct KernelSecurityFsReader {
    rtmr_path: PathBuf,
}

impl KernelSecurityFsReader {
    pub fn new(rtmr_path: impl Into<PathBuf>) -> Self {
        Self {
            rtmr_path: rtmr_path.into(),
        }
    }

    pub fn rtmr_path(&self) -> &Path {
        &self.rtmr_path
    }
}

impl Default for KernelSecurityFsReader {
    fn default() -> Self {
        Self::new(DEFAULT_RTMR_PATH)
    }
}

impl RtmrReader for KernelSecurityFsReader {
    fn read_all(&self) -> Result<Vec<ContainerRtmrState>> {
        let file = File::open(&self.rtmr_path)
            .map_err(|source| AgentError::io(self.rtmr_path.clone(), source))?;

        parse_rtmr_reader(BufReader::new(file), &self.rtmr_path)
    }

    fn wait_and_read_all(&self, timeout_ms: i32) -> Result<Option<Vec<ContainerRtmrState>>> {
        let file = File::open(&self.rtmr_path)
            .map_err(|source| AgentError::io(self.rtmr_path.clone(), source))?;

        let timeout = if timeout_ms <= 0 {
            PollTimeout::NONE
        } else {
            PollTimeout::from(u16::try_from(timeout_ms).unwrap_or(u16::MAX))
        };
        let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut fds, timeout)
            .map_err(|error| AgentError::Internal(format!("poll failed: {error}")))?;

        if ready == 0 {
            return Ok(None);
        }

        parse_rtmr_reader(BufReader::new(file), &self.rtmr_path).map(Some)
    }
}

fn parse_attestation_reader<R: BufRead>(reader: R, path: &Path) -> Result<AttestationResponse> {
    let mut response = AttestationResponse::default();

    for line in reader.lines() {
        let line = line.map_err(|source| AgentError::io(path.to_path_buf(), source))?;
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        match key {
            "CGROUP" => response.cgroup_path = value.to_owned(),
            "INITIAL_RTMR3" => response.initial_rtmr3 = value.to_owned(),
            "RTMR3" => response.rtmr3 = value.to_owned(),
            "COUNT" => response.count = value.parse::<i64>().unwrap_or_default(),
            "NONCE" => response.nonce = value.to_owned(),
            "REPORTDATA" => response.report_data = value.to_owned(),
            "TIMESTAMP" => response.timestamp = value.parse::<i64>().unwrap_or_default(),
            "MEASUREMENT" => {
                if let Some((digest, file)) = value.split_once(' ') {
                    response.measurements.push(Measurement {
                        digest: digest.to_owned(),
                        file: file.to_owned(),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(response)
}

fn parse_rtmr_reader<R: BufRead>(reader: R, path: &Path) -> Result<Vec<ContainerRtmrState>> {
    let mut states = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|source| AgentError::io(path.to_path_buf(), source))?;

        if let Some(state) = parse_rtmr_state_line(&line) {
            states.push(state);
        }
    }

    Ok(states)
}

fn parse_rtmr_state_line(line: &str) -> Option<ContainerRtmrState> {
    if line.is_empty() {
        return None;
    }

    parse_json_rtmr_state_line(line).or_else(|| parse_tab_rtmr_state_line(line))
}

#[derive(Debug, Deserialize)]
struct JsonRtmrStateLine {
    cgroup: String,
    rtmr3: String,
    initial_rtmr3: String,
    count: i64,
}

fn parse_json_rtmr_state_line(line: &str) -> Option<ContainerRtmrState> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return None;
    }

    let parsed: JsonRtmrStateLine = serde_json::from_str(trimmed).ok()?;
    Some(ContainerRtmrState {
        cgroup_path: parsed.cgroup,
        rtmr3: parsed.rtmr3,
        initial_rtmr3: parsed.initial_rtmr3,
        count: parsed.count,
    })
}

fn parse_tab_rtmr_state_line(line: &str) -> Option<ContainerRtmrState> {
    let mut fields = line.split('\t');
    let cgroup_path = fields.next()?;
    let rtmr3 = fields.next()?;
    let initial_rtmr3 = fields.next()?;
    let count = fields.next()?.parse::<i64>().unwrap_or_default();

    Some(ContainerRtmrState {
        cgroup_path: cgroup_path.to_owned(),
        rtmr3: rtmr3.to_owned(),
        initial_rtmr3: initial_rtmr3.to_owned(),
        count,
    })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Cursor;

    use super::{
        AttestationResponse, Measurement, parse_attestation_reader, parse_rtmr_reader,
        parse_rtmr_state_line,
    };

    #[test]
    fn parse_attestation_response_collects_fields() {
        let data = r#"CGROUP:/kubepods/pod-a
INITIAL_RTMR3:aaa
RTMR3:bbb
COUNT:7
NONCE:deadbeef
REPORTDATA:feedface
TIMESTAMP:42
MEASUREMENT:d1 /usr/bin/a
MEASUREMENT:d2 /etc/b
"#;

        let parsed = parse_attestation_reader(Cursor::new(data), std::path::Path::new("dummy"))
            .expect("parser should succeed");

        assert_eq!(
            parsed,
            AttestationResponse {
                cgroup_path: "/kubepods/pod-a".to_owned(),
                initial_rtmr3: "aaa".to_owned(),
                rtmr3: "bbb".to_owned(),
                count: 7,
                nonce: "deadbeef".to_owned(),
                report_data: "feedface".to_owned(),
                timestamp: 42,
                measurements: vec![
                    Measurement {
                        digest: "d1".to_owned(),
                        file: "/usr/bin/a".to_owned(),
                    },
                    Measurement {
                        digest: "d2".to_owned(),
                        file: "/etc/b".to_owned(),
                    },
                ],
            }
        );
    }

    #[test]
    fn parse_rtmr_line_reads_expected_fields() {
        let line = "/kubepods/pod-a\trtmr\tinitial\t9";
        let parsed = parse_rtmr_state_line(line).expect("line should parse");

        assert_eq!(parsed.cgroup_path, "/kubepods/pod-a");
        assert_eq!(parsed.rtmr3, "rtmr");
        assert_eq!(parsed.initial_rtmr3, "initial");
        assert_eq!(parsed.count, 9);
    }

    #[test]
    fn parse_json_rtmr_line_reads_expected_fields() {
        let line =
            r#"{"cgroup":"/kubepods/pod-a","rtmr3":"rtmr","initial_rtmr3":"initial","count":9}"#;
        let parsed = parse_rtmr_state_line(line).expect("line should parse");

        assert_eq!(parsed.cgroup_path, "/kubepods/pod-a");
        assert_eq!(parsed.rtmr3, "rtmr");
        assert_eq!(parsed.initial_rtmr3, "initial");
        assert_eq!(parsed.count, 9);
    }

    #[test]
    fn parse_rtmr_reader_skips_invalid_rows() {
        let data = "\ninvalid\n/a\tb\tc\t1\n{\"cgroup\":\"/b\",\"rtmr3\":\"x\",\"initial_rtmr3\":\"y\",\"count\":2}\n";
        let parsed = parse_rtmr_reader(Cursor::new(data), std::path::Path::new("dummy"))
            .expect("parser should succeed");

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].cgroup_path, "/a");
        assert_eq!(parsed[1].cgroup_path, "/b");
    }

    #[test]
    fn parse_rtmr_line_rejects_missing_fields() {
        assert!(parse_rtmr_state_line("a\tb\tc").is_none());
    }

    #[test]
    fn parse_count_defaults_to_zero() {
        let line = "/a\tb\tc\tnot-a-number";
        let parsed = parse_rtmr_state_line(line).expect("line should parse");
        assert_eq!(parsed.count, 0);
    }

    #[test]
    fn parse_empty_attestation_is_default() {
        let parsed = parse_attestation_reader(Cursor::new(""), std::path::Path::new("dummy"))
            .expect("parser should succeed");
        assert_eq!(parsed, AttestationResponse::default());
    }

    #[test]
    fn parser_ignores_unknown_attestation_keys() {
        let data = "UNKNOWN:value\nCGROUP:/ok\n";
        let parsed = parse_attestation_reader(Cursor::new(data), std::path::Path::new("dummy"))
            .expect("parser should succeed");
        assert_eq!(parsed.cgroup_path, "/ok");
    }

    #[test]
    fn parser_keeps_measurement_paths_with_spaces() {
        let data = "MEASUREMENT:abc /path with spaces\n";
        let parsed = parse_attestation_reader(Cursor::new(data), std::path::Path::new("dummy"))
            .expect("parser should succeed");

        assert_eq!(parsed.measurements[0].file, "/path with spaces");
    }

    #[test]
    fn io_error_is_mapped_with_path_context() {
        struct ErrReader;

        impl std::io::Read for ErrReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("boom"))
            }
        }

        impl std::io::BufRead for ErrReader {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                Err(io::Error::other("boom"))
            }

            fn consume(&mut self, _amt: usize) {}
        }

        let err = parse_attestation_reader(ErrReader, std::path::Path::new("/tmp/x"))
            .expect_err("error should be returned");
        assert!(format!("{err}").contains("/tmp/x"));
    }
}
