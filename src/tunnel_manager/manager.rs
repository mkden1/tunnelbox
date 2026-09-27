use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use super::wg_config::WgConfig;
use crate::config_store::Profile;
use crate::divert_engine::{DivertEngine, DivertParams};
use crate::job_tracker::{job_object_name, JobTracker};

/// State of a single tunnel session.
pub enum TunnelState {
    Connected { tunnel_ip: Ipv4Addr },
    Disconnected,
}

/// Everything needed to run a tunnel for one profile.
struct TunnelEntry {
    state: TunnelState,
    /// The WinDivert capture/NAT/WireGuard engine; None once disconnected.
    engine: Option<DivertEngine>,
}

pub struct TunnelManager {
    tunnels: HashMap<String, TunnelEntry>,
    jobs: JobTracker,
}

impl TunnelManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            tunnels: HashMap::new(),
            jobs: JobTracker::new(),
        })
    }

    /// Connects a tunnel for the given profile: parses the WireGuard config,
    /// creates the profile's Job Object, and starts the WinDivert engine that
    /// tunnels every packet from processes launched into that job.
    pub fn connect(&mut self, profile: &Profile) -> Result<()> {
        if self.is_connected(&profile.id) {
            return Err(anyhow!("Profile {} is already connected", profile.id));
        }

        let conf_contents = profile.read_wireguard_conf()?;
        let wg_conf = WgConfig::from_str(&conf_contents)?;

        let endpoint: SocketAddr = wg_conf.endpoint.parse()?;
        let tunnel_ip = parse_first_ipv4(&wg_conf.address)?;

        // The job must exist before the engine's PID refresher polls it.
        self.jobs.create_job(&profile.id)?;

        let params = DivertParams {
            private_key: wg_conf.private_key,
            peer_public_key: wg_conf.peer_public_key,
            endpoint,
            tunnel_ip,
            job_name: job_object_name(&profile.id),
        };

        let engine = match DivertEngine::start(params) {
            Ok(e) => e,
            Err(e) => {
                // Roll back the job so a failed connect leaves no residue.
                self.jobs.remove_job(&profile.id);
                return Err(e);
            }
        };

        self.tunnels.insert(
            profile.id.clone(),
            TunnelEntry {
                state: TunnelState::Connected { tunnel_ip },
                engine: Some(engine),
            },
        );

        tracing::info!("Profile {} connected (tunnel IP {})", profile.id, tunnel_ip);
        Ok(())
    }

    /// Disconnects a tunnel: stops the engine and destroys the Job Object,
    /// killing every process launched under this profile.
    pub fn disconnect(&mut self, profile_id: &str) -> Result<()> {
        let entry = self
            .tunnels
            .get_mut(profile_id)
            .ok_or_else(|| anyhow!("Profile {} is not connected", profile_id))?;

        if let Some(mut engine) = entry.engine.take() {
            engine.stop();
        }
        entry.state = TunnelState::Disconnected;

        // Remove the Job Object — kills all processes launched under this profile.
        self.jobs.remove_job(profile_id);

        tracing::info!("Profile {} disconnected", profile_id);
        Ok(())
    }

    /// Returns true if the profile has an active tunnel.
    pub fn is_connected(&self, profile_id: &str) -> bool {
        self.tunnels
            .get(profile_id)
            .map(|e| matches!(e.state, TunnelState::Connected { .. }))
            .unwrap_or(false)
    }

    /// Returns the connection status of all known profiles.
    pub fn status(&self) -> HashMap<String, bool> {
        self.tunnels
            .iter()
            .map(|(id, entry)| (id.clone(), matches!(entry.state, TunnelState::Connected { .. })))
            .collect()
    }

    /// Launches an exe inside the profile's Job Object. This is the only way to
    /// tunnel an app — the process is in the job (and therefore a WinDivert flow
    /// target) before it makes any network call.
    pub fn launch(&mut self, profile_id: &str, exe_path: &str, args: &[String]) -> Result<u32> {
        if !self.is_connected(profile_id) {
            anyhow::bail!("Profile {} is not connected", profile_id);
        }
        self.jobs.launch(profile_id, exe_path, args)
    }
}

/// Parses the first IPv4 address out of a WireGuard `Address = ...` value.
fn parse_first_ipv4(address: &str) -> Result<Ipv4Addr> {
    address
        .split(',')
        .map(|s| s.trim())
        .find(|s| !s.contains(':'))
        .ok_or_else(|| anyhow!("No IPv4 address in WireGuard config"))?
        .split('/')
        .next()
        .ok_or_else(|| anyhow!("Invalid address format"))?
        .parse()
        .map_err(|e| anyhow!("Invalid IPv4 address: {e}"))
}
