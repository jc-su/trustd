// Crate is unsafe-free outside of `vsock_quote`, which needs `unsafe` to invoke
// the kernel `TDX_CMD_GET_REPORT0` ioctl on `/dev/tdx_guest`. Module-level
// `#![allow(unsafe_code)]` keeps that one call site explicit while every
// other module remains under the `deny` lint.
#![deny(unsafe_code)]
#![warn(clippy::all)]

pub mod config;
pub mod error;
pub mod event_bus;
pub mod lifecycle;
pub mod liveness;
pub mod remediation;
pub mod runtime;
pub mod securityfs;
pub mod service;
pub mod spec_store;
pub mod state;
pub mod tdquote;
pub mod unix_rpc;
pub mod vsock_quote;
pub mod watcher;

pub mod proto {
    tonic::include_proto!("trustd.v1");
}
