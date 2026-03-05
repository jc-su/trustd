use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Error type used across the agent.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("io failure on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parse failure: {0}")]
    Parse(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("resource unavailable: {0}")]
    Unavailable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;

impl AgentError {
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
