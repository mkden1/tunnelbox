use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};

use super::protocol::{Command, CommandKind, DaemonStatusPayload, Response, TunnelStatusPayload};
use crate::config_store::{AppEntry, ConfigStore, Profile};
use crate::tunnel_manager::TunnelManager;


pub struct Handler {
    pub tunnel_manager: Arc<Mutex<TunnelManager>>,
}

impl Handler {
    pub fn new(tunnel_manager: Arc<Mutex<TunnelManager>>) -> Self {
        Self { tunnel_manager }
    }

    pub fn handle(&self, command: Command) -> Response {
        let id = command.id.clone();
        let cmd: CommandKind = match serde_json::from_value(
            serde_json::Value::String(command.cmd.clone())
        ) {
            Ok(c) => c,
            Err(_) => return Response::error(id, format!("Unknown command: {}", command.cmd)),
        };

        match self.dispatch(id.clone(), cmd, command.payload) {
            Ok(payload) => Response::success(id, payload),
            Err(e) => Response::error(id, e.to_string()),
        }
    }

    fn dispatch(&self, _id: String, cmd: CommandKind, payload: serde_json::Value) -> Result<serde_json::Value> {
        match cmd {
            CommandKind::TunnelConnect => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?
                    .to_string();
                let profile = ConfigStore::get(&profile_id)?;
                self.tunnel_manager.lock().unwrap().connect(&profile)?;
                Ok(serde_json::json!({ "connected": true }))
            }

            CommandKind::TunnelDisconnect => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?
                    .to_string();
                self.tunnel_manager.lock().unwrap().disconnect(&profile_id)?;
                Ok(serde_json::json!({ "connected": false }))
            }

            CommandKind::TunnelStatus => {
                let status = self.tunnel_manager.lock().unwrap().status();
                Ok(serde_json::to_value(TunnelStatusPayload { tunnels: status })?)
            }

            CommandKind::ProfileList => {
                let profiles = ConfigStore::load_all()?;
                Ok(serde_json::to_value(profiles)?)
            }

            CommandKind::ProfileCreate => {
                let name = payload["name"].as_str()
                    .ok_or_else(|| anyhow!("Missing name"))?;
                let profile = ConfigStore::create(name)?;
                Ok(serde_json::to_value(profile)?)
            }

            CommandKind::ProfileDelete => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?
                    .to_string();
                ConfigStore::delete(&profile_id)?;
                Ok(serde_json::json!({ "deleted": true }))
            }

            CommandKind::ProfileUpdate => {
                let profile: Profile = serde_json::from_value(payload)?;
                ConfigStore::update(&profile)?;
                Ok(serde_json::to_value(profile)?)
            }

            CommandKind::AppBind => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?.to_string();
                let exe_path = payload["exe_path"].as_str()
                    .ok_or_else(|| anyhow!("Missing exe_path"))?.to_string();
                let mut profile = ConfigStore::get(&profile_id)?;
                if !profile.apps.iter().any(|a| a.exe == exe_path) {
                    profile.apps.push(AppEntry { exe: exe_path, enabled: true });
                    ConfigStore::update(&profile)?;
                }
                Ok(serde_json::json!({ "bound": true }))
            }

            CommandKind::AppUnbind => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?.to_string();
                let exe_path = payload["exe_path"].as_str()
                    .ok_or_else(|| anyhow!("Missing exe_path"))?.to_string();
                let mut profile = ConfigStore::get(&profile_id)?;
                profile.apps.retain(|a| a.exe != exe_path);
                ConfigStore::update(&profile)?;
                Ok(serde_json::json!({ "unbound": true }))
            }

            CommandKind::AppLaunch => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?.to_string();
                let exe_path = payload["exe_path"].as_str()
                    .ok_or_else(|| anyhow!("Missing exe_path"))?.to_string();
                let args: Vec<String> = payload["args"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();

                let pid = self.tunnel_manager
                    .lock().unwrap()
                    .launch(&profile_id, &exe_path, &args)?;

                Ok(serde_json::json!({ "launched": true, "pid": pid }))
            }

            CommandKind::WireguardImport => {
                let profile_id = payload["profile_id"].as_str()
                    .ok_or_else(|| anyhow!("Missing profile_id"))?.to_string();
                let contents = payload["contents"].as_str()
                    .ok_or_else(|| anyhow!("Missing contents"))?.to_string();
                ConfigStore::import_wireguard_conf(&profile_id, &contents)?;
                Ok(serde_json::json!({ "imported": true }))
            }

            CommandKind::DaemonStatus => {
                Ok(serde_json::to_value(DaemonStatusPayload {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    wintun_loaded: true,
                })?)
            }
        }
    }
}