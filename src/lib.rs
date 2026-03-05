#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod config;
pub mod error;
pub mod event_bus;
pub mod liveness;
pub mod remediation;
pub mod securityfs;
pub mod service;
pub mod state;
pub mod tdquote;
pub mod unix_rpc;
pub mod watcher;

pub mod proto {
    tonic::include_proto!("trustd.v1");
}
