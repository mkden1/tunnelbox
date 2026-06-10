use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Unique identifier — used as the directory name under profiles/
    pub id: String,

    /// Display name shown in the GUI
    pub name: String,

    /// Apps assigned to this profile
    pub apps: Vec<AppEntry>,

    /// Automatically connect this profile on daemon startup
    #[serde(default)]
    pub auto_connect: bool,

    /// Block traffic if the tunnel drops unexpectedly
    #[serde(default = "default_true")]
    pub kill_switch: bool,

    /// How DNS is handled for this profile
    #[serde(default)]
    pub dns_mode: DnsMode,

    /// Profile connection state — not persisted, runtime only
    #[serde(skip)]
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEntry {
    /// Full path to the executable
    pub exe: String,

    /// Whether this app is actively bound to the tunnel
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Use the DNS server specified in wireguard.conf
    #[default]
    Tunnel,
    /// Use a custom DNS server
    Custom(String),
    /// Use the system default (not recommended — leak risk)
    System,
}

impl Profile {
    /// Creates a new profile with a generated ID and sensible defaults.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            apps: Vec::new(),
            auto_connect: false,
            kill_switch: true,
            dns_mode: DnsMode::Tunnel,
            connected: false,
        }
    }

    /// Loads a profile from its directory.
    pub fn load(id: &str) -> Result<Self> {
        let path = paths::profile_json_path(id)?;
        let json = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read profile {id}: {e}"))?;
        let profile: Profile = serde_json::from_str(&json)
            .map_err(|e| anyhow!("Failed to parse profile {id}: {e}"))?;
        Ok(profile)
    }

    /// Saves a profile to its directory, creating the directory if needed.
    pub fn save(&self) -> Result<()> {
        let dir = paths::profile_dir(&self.id)?;
        std::fs::create_dir_all(&dir)?;

        let path = paths::profile_json_path(&self.id)?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)
            .map_err(|e| anyhow!("Failed to save profile {}: {e}", self.id))?;
        Ok(())
    }

    /// Deletes a profile directory and all its contents.
    pub fn delete(id: &str) -> Result<()> {
        let dir = paths::profile_dir(id)?;
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| anyhow!("Failed to delete profile {id}: {e}"))?;
        }
        Ok(())
    }

    /// Returns the path to this profile's wireguard.conf file.
    pub fn wireguard_conf_path(&self) -> Result<std::path::PathBuf> {
        paths::wireguard_conf_path(&self.id)
    }

    /// Returns true if the wireguard.conf file exists for this profile.
    pub fn has_wireguard_conf(&self) -> Result<bool> {
        Ok(paths::wireguard_conf_path(&self.id)?.exists())
    }

    /// Saves a WireGuard .conf file for this profile.
    /// The raw contents are stored unmodified.
    pub fn save_wireguard_conf(&self, contents: &str) -> Result<()> {
        let dir = paths::profile_dir(&self.id)?;
        std::fs::create_dir_all(&dir)?;
        let path = paths::wireguard_conf_path(&self.id)?;
        std::fs::write(&path, contents)
            .map_err(|e| anyhow!("Failed to save wireguard.conf for {}: {e}", self.id))?;
        Ok(())
    }

    /// Reads the raw WireGuard .conf contents for this profile.
    pub fn read_wireguard_conf(&self) -> Result<String> {
        let path = paths::wireguard_conf_path(&self.id)?;
        std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read wireguard.conf for {}: {e}", self.id))
    }
}

fn default_true() -> bool {
    true
}