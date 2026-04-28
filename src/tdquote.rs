use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{AgentError, Result};
use crate::vsock_quote::VsockQuoter;

// Linux 6.6+ kernel exposes the TSM configfs report dir at
// "/sys/kernel/config/tsm/report". Pre-merge dev kernels used the flat
// "tsm_report" directory; our 6.6.63+ guest uses the modern path.
pub const DEFAULT_TSM_BASE_PATH: &str = "/sys/kernel/config/tsm/report";
pub const REPORT_NAME: &str = "trustd";

pub trait QuoteProvider: Send + Sync {
    fn available(&self) -> bool;
    fn get_quote(&self, report_data: &[u8]) -> Result<Vec<u8>>;
}

/// Static-dispatch wrapper over the two concrete quote backends.
///
/// trustd's pipeline (`service.rs`, `unix_rpc.rs`, `main.rs`) is generic
/// over `Q: QuoteProvider + 'static`. We want to pick the backend at
/// runtime from `--quote-backend`, but generic monomorphization needs a
/// single concrete type. An enum with a `QuoteProvider` impl that branches
/// on the variant gives us runtime selection without converting every
/// call site to `Arc<dyn QuoteProvider>` (which would force `?Sized`
/// bounds on a dozen signatures).
#[derive(Debug)]
pub enum DynQuoter {
    Tsm(TsmQuoter),
    Vsock(VsockQuoter),
}

impl QuoteProvider for DynQuoter {
    fn available(&self) -> bool {
        match self {
            DynQuoter::Tsm(q) => q.available(),
            DynQuoter::Vsock(q) => q.available(),
        }
    }

    fn get_quote(&self, report_data: &[u8]) -> Result<Vec<u8>> {
        match self {
            DynQuoter::Tsm(q) => q.get_quote(report_data),
            DynQuoter::Vsock(q) => q.get_quote(report_data),
        }
    }
}

#[derive(Debug)]
pub struct TsmQuoter {
    base_path: PathBuf,
    lock: Mutex<()>,
}

impl TsmQuoter {
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn report_dir(&self) -> PathBuf {
        self.base_path.join(REPORT_NAME)
    }

    fn ensure_report_dir(&self) -> Result<PathBuf> {
        let report_dir = self.report_dir();
        fs::create_dir_all(&report_dir)
            .map_err(|source| AgentError::io(report_dir.clone(), source))?;
        Ok(report_dir)
    }
}

impl Default for TsmQuoter {
    fn default() -> Self {
        Self::new(DEFAULT_TSM_BASE_PATH)
    }
}

impl QuoteProvider for TsmQuoter {
    fn available(&self) -> bool {
        self.ensure_report_dir().is_ok()
    }

    fn get_quote(&self, report_data: &[u8]) -> Result<Vec<u8>> {
        if report_data.len() != 64 {
            return Err(AgentError::InvalidInput(format!(
                "report_data must be 64 bytes, got {}",
                report_data.len()
            )));
        }

        let _guard = self
            .lock
            .lock()
            .map_err(|_| AgentError::Internal("quote lock poisoned".to_owned()))?;

        let report_dir = self.ensure_report_dir()?;
        let inblob_path = report_dir.join("inblob");
        let outblob_path = report_dir.join("outblob");

        fs::write(&inblob_path, report_data)
            .map_err(|source| AgentError::io(inblob_path.clone(), source))?;

        let quote =
            fs::read(&outblob_path).map_err(|source| AgentError::io(outblob_path, source))?;
        if quote.is_empty() {
            return Err(AgentError::Unavailable("empty quote returned".to_owned()));
        }

        Ok(quote)
    }
}

pub fn is_report_data_len_valid(report_data: &[u8]) -> bool {
    report_data.len() == 64
}

pub fn report_paths(base_path: impl AsRef<Path>) -> (PathBuf, PathBuf) {
    let report_dir = base_path.as_ref().join(REPORT_NAME);
    (report_dir.join("inblob"), report_dir.join("outblob"))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{QuoteProvider, TsmQuoter, is_report_data_len_valid, report_paths};

    #[test]
    fn report_data_len_validation() {
        assert!(!is_report_data_len_valid(&[]));
        assert!(is_report_data_len_valid(&[0_u8; 64]));
    }

    #[test]
    fn available_creates_report_directory() {
        let dir = tempdir().expect("tempdir should be created");
        let quoter = TsmQuoter::new(dir.path());

        assert!(quoter.available());
        assert!(quoter.report_dir().exists());
    }

    #[test]
    fn get_quote_roundtrip() {
        let dir = tempdir().expect("tempdir should be created");
        let quoter = TsmQuoter::new(dir.path());

        let report_dir = quoter.report_dir();
        std::fs::create_dir_all(&report_dir).expect("report directory should be created");
        std::fs::write(report_dir.join("outblob"), [1_u8, 2, 3])
            .expect("outblob should be written");

        let quote = quoter
            .get_quote(&[0_u8; 64])
            .expect("quote should be returned");
        assert_eq!(quote, vec![1, 2, 3]);

        let inblob = std::fs::read(report_dir.join("inblob")).expect("inblob should be readable");
        assert_eq!(inblob.len(), 64);
    }

    #[test]
    fn get_quote_requires_64_bytes() {
        let dir = tempdir().expect("tempdir should be created");
        let quoter = TsmQuoter::new(dir.path());

        let err = quoter
            .get_quote(&[0_u8; 63])
            .expect_err("short report data should fail");
        assert!(format!("{err}").contains("64 bytes"));
    }

    #[test]
    fn report_paths_are_stable() {
        let dir = tempdir().expect("tempdir should be created");
        let (inblob, outblob) = report_paths(dir.path());

        assert!(inblob.ends_with("trustd/inblob"));
        assert!(outblob.ends_with("trustd/outblob"));
    }
}
