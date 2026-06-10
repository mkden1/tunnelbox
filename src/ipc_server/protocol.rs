use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Inbound commands (GUI → daemon) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Command {
    pub id: String,
    pub cmd: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    TunnelConnect,
    TunnelDisconnect,
    TunnelStatus,
    ProfileList,
    ProfileCreate,
    ProfileDelete,
    ProfileUpdate,
    AppBind,
    AppUnbind,
    AppLaunch,
    DaemonStatus,
}

// ── Outbound responses (daemon → GUI) ────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: String,          // echoes the command UUID
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn success(id: impl Into<String>, payload: impl Serialize) -> Self {
        Self {
            id: id.into(),
            ok: true,
            payload: Some(serde_json::to_value(payload).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }

    pub fn error(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: false,
            payload: None,
            error: Some(message.into()),
        }
    }
}

// ── Payload types returned in responses ──────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TunnelStatusPayload {
    pub tunnels: HashMap<String, bool>,
}

#[derive(Debug, Serialize)]
pub struct DaemonStatusPayload {
    pub version: String,
    pub wintun_loaded: bool,
}