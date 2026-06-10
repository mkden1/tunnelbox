use anyhow::{anyhow, Result};
use configparser::ini::Ini;

#[derive(Debug, Clone)]
pub struct WgConfig {
    pub private_key: String,
    pub address: String,
    pub dns: Option<String>,
    pub peer_public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
}

impl WgConfig {
    pub fn from_str(contents: &str) -> Result<Self> {
        let mut conf = Ini::new();
        conf.read(contents.to_string())
            .map_err(|e| anyhow!("Failed to parse WireGuard config: {}", e))?;

        let sections = conf
            .get_map()
            .ok_or_else(|| anyhow!("Config not loaded"))?;

        let interface = sections
            .get("interface")
            .ok_or_else(|| anyhow!("Missing [Interface] section"))?;

        let peer = sections
            .get("peer")
            .ok_or_else(|| anyhow!("Missing [Peer] section"))?;

        let private_key = interface
            .get("privatekey")
            .and_then(|v| v.clone())
            .ok_or_else(|| anyhow!("Missing PrivateKey"))?;

        let address = interface
            .get("address")
            .and_then(|v| v.clone())
            .ok_or_else(|| anyhow!("Missing Address"))?;

        let peer_public_key = peer
            .get("publickey")
            .and_then(|v| v.clone())
            .ok_or_else(|| anyhow!("Missing peer PublicKey"))?;

        let endpoint = peer
            .get("endpoint")
            .and_then(|v| v.clone())
            .ok_or_else(|| anyhow!("Missing Endpoint"))?;

        let allowed_ips = peer
            .get("allowedips")
            .and_then(|v| v.clone())
            .ok_or_else(|| anyhow!("Missing AllowedIPs"))?;

        let dns = interface.get("dns").and_then(|v| v.clone());

        Ok(WgConfig {
            private_key,
            address,
            dns,
            peer_public_key,
            endpoint,
            allowed_ips,
        })
    }
}