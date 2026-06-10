use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// Returns the root data directory: %APPDATA%\Tunnelbox
pub fn data_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not resolve %APPDATA%"))?;
    Ok(base.join("Tunnelbox"))
}

/// Returns the profiles directory: %APPDATA%\Tunnelbox\profiles
pub fn profiles_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("profiles"))
}

/// Returns the directory for a specific profile: %APPDATA%\Tunnelbox\profiles\<id>
pub fn profile_dir(id: &str) -> Result<PathBuf> {
    Ok(profiles_dir()?.join(id))
}

/// Returns the path to a profile's metadata file
pub fn profile_json_path(id: &str) -> Result<PathBuf> {
    Ok(profile_dir(id)?.join("profile.json"))
}

/// Returns the path to a profile's WireGuard config file
pub fn wireguard_conf_path(id: &str) -> Result<PathBuf> {
    Ok(profile_dir(id)?.join("wireguard.conf"))
}

/// Returns the path to the app-wide settings file
pub fn settings_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("settings.json"))
}

/// Returns the path to the daemon log file
pub fn log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("tunnelbox.log"))
}

/// Ensures the full directory structure exists, creating it if needed.
pub fn ensure_dirs() -> Result<()> {
    std::fs::create_dir_all(profiles_dir()?)?;
    Ok(())
}