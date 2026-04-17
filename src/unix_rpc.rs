//! JSON-over-Unix-socket RPC handler for in-VM clients (e.g. MCP Server).
//!
//! Protocol: newline-delimited JSON. Each request is a single line, each response
//! is a single line.
//!
//! Supported methods:
//! - `GetContainerState` — returns cached container state from StateManager
//! - `GetTDQuote` — generates a TDX quote via TSM configfs
//! - `Ping` — returns version, uptime, and container count
//! - `RestartContainer` — restart a container via cgroup SIGTERM/SIGKILL
//! - `AttestWorkload` — produces an AttestWorkloadResponse bundle (quote +
//!   per-container event log + report_data) for a stable workload_id. This
//!   is the canonical attestation call used by in-guest relying parties
//!   (e.g. the MCP fork) that cannot read securityfs directly.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, warn};

use crate::remediation::ContainerRestarter;
use crate::service::build_attest_bundle;
use crate::spec_store::SpecStore;
use crate::state::StateManager;
use crate::tdquote::QuoteProvider;

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl JsonRpcResponse {
    fn success(result: serde_json::Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(message.into()),
        }
    }
}

pub async fn handle_connection<Q: QuoteProvider>(
    stream: UnixStream,
    state: Arc<StateManager>,
    quoter: Arc<Q>,
    restarter: Arc<dyn ContainerRestarter>,
    spec_store: Arc<SpecStore>,
    version: Arc<str>,
    started_at: Instant,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(request) => dispatch(
                &request,
                &state,
                quoter.as_ref(),
                restarter.as_ref(),
                spec_store.as_ref(),
                &version,
                started_at,
            ),
            Err(e) => JsonRpcResponse::error(format!("invalid JSON: {e}")),
        };

        let mut out = match serde_json::to_vec(&response) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = %e, "failed to serialize response");
                break;
            }
        };
        out.push(b'\n');

        if writer.write_all(&out).await.is_err() {
            break;
        }
    }

    debug!("unix rpc connection closed");
}

fn dispatch<Q: QuoteProvider>(
    request: &JsonRpcRequest,
    state: &StateManager,
    quoter: &Q,
    restarter: &dyn ContainerRestarter,
    spec_store: &SpecStore,
    version: &str,
    started_at: Instant,
) -> JsonRpcResponse {
    match request.method.as_str() {
        "GetContainerState" => handle_get_container_state(request, state),
        "GetTDQuote" => handle_get_td_quote(request, quoter),
        "RestartContainer" => handle_restart_container(request, restarter),
        "AttestWorkload" => handle_attest_workload(request, spec_store, quoter),
        "Ping" => handle_ping(state, version, started_at),
        other => JsonRpcResponse::error(format!("unknown method: {other}")),
    }
}

fn handle_attest_workload<Q: QuoteProvider>(
    request: &JsonRpcRequest,
    spec_store: &SpecStore,
    quoter: &Q,
) -> JsonRpcResponse {
    let workload_id = match request.params.get("workload_id").and_then(|v| v.as_str()) {
        Some(w) if !w.is_empty() => w,
        _ => return JsonRpcResponse::error("workload_id is required"),
    };
    let nonce_hex = match request.params.get("nonce_hex").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => return JsonRpcResponse::error("nonce_hex is required"),
    };
    // peer_pk is optional. Accept either raw base64 string or an empty/missing
    // field. When present, decoded bytes are hashed into report_data by the
    // shared bundle builder.
    let peer_pk_b64 = request
        .params
        .get("peer_pk")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let peer_pk = if peer_pk_b64.is_empty() {
        Vec::new()
    } else {
        match base64::engine::general_purpose::STANDARD.decode(peer_pk_b64) {
            Ok(b) => b,
            Err(e) => return JsonRpcResponse::error(format!("peer_pk base64 decode: {e}")),
        }
    };

    let bundle = match build_attest_bundle(spec_store, quoter, workload_id, nonce_hex, &peer_pk) {
        Ok(b) => b,
        Err(status) => return JsonRpcResponse::error(status.message().to_owned()),
    };

    let result = serde_json::json!({
        "workload_id": bundle.workload_id,
        "cgroup_path": bundle.cgroup_path,
        "nonce_hex": bundle.nonce_hex,
        "td_quote": base64::engine::general_purpose::STANDARD.encode(&bundle.td_quote),
        "event_log": base64::engine::general_purpose::STANDARD.encode(&bundle.event_log),
        "report_data_hex": bundle.report_data_hex,
        "timestamp": bundle.timestamp,
    });
    JsonRpcResponse::success(result)
}

fn handle_get_container_state(request: &JsonRpcRequest, state: &StateManager) -> JsonRpcResponse {
    let cgroup_path = request.params.get("cgroup_path").and_then(|v| v.as_str());

    let Some(cgroup_path) = cgroup_path else {
        return JsonRpcResponse::error("missing required param: cgroup_path");
    };

    if cgroup_path.is_empty() {
        return JsonRpcResponse::error("cgroup_path must not be empty");
    }

    let Some(container) = state.get(cgroup_path) else {
        return JsonRpcResponse::error(format!("container not found: {cgroup_path}"));
    };

    JsonRpcResponse::success(serde_json::json!({
        "cgroup_path": container.cgroup_path,
        "rtmr3": container.rtmr3,
        "initial_rtmr3": container.initial_rtmr3,
        "measurement_count": container.measurement_count,
    }))
}

fn handle_get_td_quote<Q: QuoteProvider>(request: &JsonRpcRequest, quoter: &Q) -> JsonRpcResponse {
    if !quoter.available() {
        return JsonRpcResponse::error("TDX quotes are unavailable on this host");
    }

    let Some(report_data_value) = request.params.get("report_data") else {
        return JsonRpcResponse::error("missing required param: report_data");
    };

    let Some(report_data_b64) = report_data_value.as_str() else {
        return JsonRpcResponse::error("report_data must be a base64 string");
    };

    let report_data = match base64::engine::general_purpose::STANDARD.decode(report_data_b64) {
        Ok(data) => data,
        Err(e) => return JsonRpcResponse::error(format!("invalid base64 in report_data: {e}")),
    };

    if report_data.len() != 64 {
        return JsonRpcResponse::error(format!(
            "report_data must be exactly 64 bytes, got {}",
            report_data.len()
        ));
    }

    match quoter.get_quote(&report_data) {
        Ok(quote) => {
            let td_quote = base64::engine::general_purpose::STANDARD.encode(&quote);
            JsonRpcResponse::success(serde_json::json!({ "td_quote": td_quote }))
        }
        Err(e) => JsonRpcResponse::error(format!("quote generation failed: {e}")),
    }
}

fn handle_ping(state: &StateManager, version: &str, started_at: Instant) -> JsonRpcResponse {
    JsonRpcResponse::success(serde_json::json!({
        "version": version,
        "uptime_seconds": started_at.elapsed().as_secs(),
        "containers_tracked": state.count(),
    }))
}

fn handle_restart_container(
    request: &JsonRpcRequest,
    restarter: &dyn ContainerRestarter,
) -> JsonRpcResponse {
    let cgroup_path = request.params.get("cgroup_path").and_then(|v| v.as_str());

    let Some(cgroup_path) = cgroup_path else {
        return JsonRpcResponse::error("missing required param: cgroup_path");
    };

    if cgroup_path.is_empty() {
        return JsonRpcResponse::error("cgroup_path must not be empty");
    }

    match restarter.restart(cgroup_path) {
        Ok(result) => JsonRpcResponse::success(serde_json::json!({
            "cgroup_path": result.cgroup_path,
            "signaled_pids": result.signaled_pids,
            "force_killed_pids": result.force_killed_pids,
        })),
        Err(e) => JsonRpcResponse::error(format!("restart failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::error::AgentError;
    use crate::remediation::RestartResult;

    #[derive(Debug, Default)]
    struct FakeQuoter {
        available: bool,
    }

    impl QuoteProvider for FakeQuoter {
        fn available(&self) -> bool {
            self.available
        }

        fn get_quote(&self, report_data: &[u8]) -> Result<Vec<u8>, AgentError> {
            Ok(report_data[..4].to_vec())
        }
    }

    #[derive(Debug, Default)]
    struct FakeRestarter {
        calls: Mutex<Vec<String>>,
    }

    impl ContainerRestarter for FakeRestarter {
        fn restart(&self, cgroup_path: &str) -> Result<RestartResult, AgentError> {
            self.calls
                .lock()
                .expect("restarter lock should not be poisoned")
                .push(cgroup_path.to_owned());
            Ok(RestartResult {
                cgroup_path: cgroup_path.to_owned(),
                signaled_pids: 2,
                force_killed_pids: 0,
            })
        }
    }

    fn make_state() -> Arc<StateManager> {
        let state = Arc::new(StateManager::new());
        state.update_from_securityfs("/docker/abc", "rtmr3_hex", "initial_hex", 5);
        state
    }

    #[test]
    fn get_container_state_returns_data() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "GetContainerState".to_owned(),
            params: serde_json::json!({"cgroup_path": "/docker/abc"}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(result["cgroup_path"], "/docker/abc");
        assert_eq!(result["rtmr3"], "rtmr3_hex");
        assert_eq!(result["initial_rtmr3"], "initial_hex");
        assert_eq!(result["measurement_count"], 5);
    }

    #[test]
    fn get_container_state_not_found() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "GetContainerState".to_owned(),
            params: serde_json::json!({"cgroup_path": "/docker/xyz"}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("not found"));
    }

    #[test]
    fn get_container_state_missing_param() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "GetContainerState".to_owned(),
            params: serde_json::json!({}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("cgroup_path"));
    }

    #[test]
    fn get_td_quote_success() {
        let state = make_state();
        let report_data = [7_u8; 64];
        let b64 = base64::engine::general_purpose::STANDARD.encode(report_data);
        let request = JsonRpcRequest {
            method: "GetTDQuote".to_owned(),
            params: serde_json::json!({"report_data": b64}),
        };

        let quoter = FakeQuoter { available: true };
        let response = dispatch(
            &request,
            &state,
            &quoter,
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(response.ok);
        let result = response.result.unwrap();
        assert!(result["td_quote"].is_string());
    }

    #[test]
    fn get_td_quote_unavailable() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "GetTDQuote".to_owned(),
            params: serde_json::json!({"report_data": "AAAA"}),
        };

        let quoter = FakeQuoter { available: false };
        let response = dispatch(
            &request,
            &state,
            &quoter,
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("unavailable"));
    }

    #[test]
    fn get_td_quote_wrong_size() {
        let state = make_state();
        let short_data = [0_u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(short_data);
        let request = JsonRpcRequest {
            method: "GetTDQuote".to_owned(),
            params: serde_json::json!({"report_data": b64}),
        };

        let quoter = FakeQuoter { available: true };
        let response = dispatch(
            &request,
            &state,
            &quoter,
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("64 bytes"));
    }

    #[test]
    fn ping_returns_info() {
        let state = make_state();
        let started = Instant::now();
        let request = JsonRpcRequest {
            method: "Ping".to_owned(),
            params: serde_json::json!({}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            started,
        );

        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(result["version"], "0.1.0");
        assert_eq!(result["containers_tracked"], 1);
    }

    #[test]
    fn restart_container_success() {
        let state = make_state();
        let restarter = FakeRestarter::default();
        let request = JsonRpcRequest {
            method: "RestartContainer".to_owned(),
            params: serde_json::json!({"cgroup_path": "/docker/abc"}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &restarter,
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(result["cgroup_path"], "/docker/abc");
        assert_eq!(result["signaled_pids"], 2);
        assert_eq!(result["force_killed_pids"], 0);

        let calls = restarter.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["/docker/abc".to_owned()]);
    }

    #[test]
    fn restart_container_missing_param() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "RestartContainer".to_owned(),
            params: serde_json::json!({}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("cgroup_path"));
    }

    #[test]
    fn restart_container_empty_path() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "RestartContainer".to_owned(),
            params: serde_json::json!({"cgroup_path": ""}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("must not be empty"));
    }

    #[test]
    fn unknown_method_returns_error() {
        let state = make_state();
        let request = JsonRpcRequest {
            method: "NoSuchMethod".to_owned(),
            params: serde_json::json!({}),
        };

        let response = dispatch(
            &request,
            &state,
            &FakeQuoter::default(),
            &FakeRestarter::default(),
            &SpecStore::new(),
            "0.1.0",
            Instant::now(),
        );

        assert!(!response.ok);
        assert!(response.error.unwrap().contains("unknown method"));
    }

    #[test]
    fn invalid_json_handled() {
        let bad_json = "not valid json at all";
        let result = serde_json::from_str::<JsonRpcRequest>(bad_json);
        assert!(result.is_err());
    }
}
