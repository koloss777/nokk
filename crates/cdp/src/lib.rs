//! Chrome DevTools Protocol wire format.
//!
//! Puppeteer/Playwright drive a browser by exchanging JSON messages over a
//! WebSocket. Phase 5 stands up the actual server (`/json`, `/json/version`,
//! per-target WebSockets) and implements the `Target`, `Page`, `Runtime`,
//! `DOM`, `Network`, `Fetch` and `Input` domains. This crate defines the
//! message envelope those domains share, kept dependency-light so it can be
//! fuzzed and round-trip-tested on its own.
//!
//! CDP framing:
//! - A client sends a **command**: `{ id, method, params, sessionId? }`.
//! - The server replies with a **result** `{ id, result, sessionId? }` or an
//!   **error** `{ id, error: { code, message }, sessionId? }`, echoing `id`.
//! - The server also emits unsolicited **events**: `{ method, params, sessionId? }`
//!   (no `id`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod server;
pub use server::{serve, ServerConfig};

/// A command sent by a CDP client, e.g. `Page.navigate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: i64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    /// Present once the client has attached to a target's session.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionId")]
    pub session_id: Option<String>,
}

/// An error object inside a failed command response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// A reply to a [`Command`], echoing its `id`. Exactly one of `result`/`error`
/// is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CdpError>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionId")]
    pub session_id: Option<String>,
}

impl Response {
    pub fn ok(id: i64, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
            session_id: None,
        }
    }

    pub fn err(id: i64, code: i64, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(CdpError {
                code,
                message: message.into(),
                data: None,
            }),
            session_id: None,
        }
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

/// An unsolicited event emitted by the server, e.g. `Page.loadEventFired`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sessionId")]
    pub session_id: Option<String>,
}

impl Event {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            method: method.into(),
            params,
            session_id: None,
        }
    }
}

/// The `<domain>.<member>` split of a CDP method name.
pub fn split_method(method: &str) -> Option<(&str, &str)> {
    method.split_once('.')
}

#[derive(Debug, thiserror::Error)]
pub enum CdpProtocolError {
    #[error("malformed CDP message: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("method `{0}` is not implemented")]
    MethodNotFound(String),
}

/// Standard CDP error code for an unknown method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Standard CDP error code for invalid params.
pub const INVALID_PARAMS: i64 = -32602;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn command_round_trips() {
        let raw = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://a.co"}}"#;
        let cmd: Command = serde_json::from_str(raw).unwrap();
        assert_eq!(cmd.id, 1);
        assert_eq!(cmd.method, "Page.navigate");
        assert_eq!(cmd.params["url"], "https://a.co");
        assert!(cmd.session_id.is_none());
    }

    #[test]
    fn ok_response_omits_error_and_null_session() {
        let resp = Response::ok(7, json!({"frameId": "F1"}));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains(r#""id":7"#));
        assert!(s.contains(r#""frameId":"F1""#));
        assert!(!s.contains("error"));
        assert!(!s.contains("sessionId"));
    }

    #[test]
    fn event_has_no_id_field() {
        let ev = Event::new("Page.loadEventFired", json!({"timestamp": 1.0}));
        let s = serde_json::to_string(&ev).unwrap();
        assert!(!s.contains(r#""id""#));
        assert!(s.contains("Page.loadEventFired"));
    }

    #[test]
    fn method_splits_into_domain_and_member() {
        assert_eq!(
            split_method("Runtime.evaluate"),
            Some(("Runtime", "evaluate"))
        );
        assert_eq!(split_method("bogus"), None);
    }
}
