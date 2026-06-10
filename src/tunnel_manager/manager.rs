use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use super::wg_config::WgConfig;
use super::wg_session::WgSession;
use super::wintun_iface::WintunInterface;
use crate::config_store::Profile;
use crate::wfp_manager::WfpManager;
use crate::job_tracker::JobTracker;

/// State of a single tunnel session
pub enum TunnelState {
    Connected {
        luid: u64,
        iface_index: u32,
        wintun_ip: String,
    },
    Disconnected,
    Error(String),
}

/// Everything needed to run a tunnel for one profile
struct TunnelEntry {
    state: TunnelState,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
}

pub struct TunnelManager {
    tunnels: HashMap<String, TunnelEntry>,
    wfp: WfpManager,
    jobs: JobTracker,
    real_luid: u64,
}

impl TunnelManager {
    pub fn new(real_luid: u64) -> Result<Self> {
        Ok(Self {
            tunnels: HashMap::new(),
            wfp: WfpManager::new()?,
            jobs: JobTracker::new(),
            real_luid,
        })
    }

    /// Connects a tunnel for the given profile.
    /// Parses the WireGuard config, brings up the Wintun adapter,
    /// performs the handshake, and starts the packet loop thread.
    pub fn connect(&mut self, profile: &Profile) -> Result<()> {
        if let Some(entry) = self.tunnels.get(&profile.id) {
            if matches!(entry.state, TunnelState::Connected { .. }) {
                return Err(anyhow!("Profile {} is already connected", profile.id));
            }
        }

        // Read and parse the WireGuard config
        let conf_contents = profile.read_wireguard_conf()?;
        let wg_conf = WgConfig::from_str(&conf_contents)?;

        // Bring up WireGuard session before adding routes
        let endpoint: std::net::SocketAddr = wg_conf.endpoint.parse()?;
        let mut session = WgSession::new(
            &wg_conf.private_key,
            &wg_conf.peer_public_key,
            endpoint,
        )?;

        session.send_handshake()?;
        std::thread::sleep(std::time::Duration::from_millis(800));

        // Bring up Wintun adapter
        let adapter_name = format!("Tunnelbox-{}", &profile.id[..8]);
        let mut iface = WintunInterface::new(&adapter_name)?;
        iface.set_ip(&wg_conf.address)?;


        // Start SOCKS5 proxy bound to Wintun IP
        let wintun_ip: std::net::Ipv4Addr = wg_conf.address
            .split(',')
            .map(|s| s.trim())
            .find(|s| !s.contains(':'))
            .ok_or_else(|| anyhow!("No IPv4 address"))?
            .split('/')
            .next()
            .ok_or_else(|| anyhow!("Invalid address"))?
            .parse()?;



        let peer_ip = wg_conf.endpoint
            .split(':')
            .next()
            .ok_or_else(|| anyhow!("Invalid endpoint"))?
            .to_string();

        iface.set_routes(&wg_conf.allowed_ips, &peer_ip)?;

        let iface_index = iface.get_adapter_index()?;
        let luid = iface.get_luid();

        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_clone = cancel.clone();


        let profile_id_clone = profile.id.clone();
        thread::spawn(move || {
            if let Err(e) = session.run_loop_divert(iface, cancel_clone) {
                tracing::error!("Packet loop error for {}: {}", profile_id_clone, e);
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(200));

        let proxy = crate::dns_proxy::Socks5Proxy::new(wintun_ip, 1080);
        std::thread::spawn(move || {
            if let Err(e) = proxy.run() {
                tracing::error!("SOCKS5 proxy error: {e}");
            }
        });

        let wintun_ip = wg_conf.address
            .split(',')
            .map(|s| s.trim())
            .find(|s| !s.contains(':'))
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();

        self.tunnels.insert(
            profile.id.clone(),
            TunnelEntry {
                state: TunnelState::Connected { luid, iface_index, wintun_ip },
                cancel: Some(cancel),
            },
        );

        tracing::info!("Profile {} connected", profile.id);

        // Install WFP filters for all enabled apps in this profile
        let enabled_apps: Vec<String> = profile.apps
            .iter()
            .filter(|a| a.enabled)
            .map(|a| a.exe.clone())
            .collect();

        if !enabled_apps.is_empty() {
            self.wfp.install_profile_filters(
                &profile.id,
                &enabled_apps,
                luid,
                self.real_luid,
            )?;
        }

        // Create Job Object for this profile
        self.jobs.create_job(&profile.id)?;

        Ok(())
    }

    /// Disconnects a tunnel for the given profile.
    /// Dropping the WintunInterface destroys the adapter and cleans up routes.
    pub fn disconnect(&mut self, profile_id: &str) -> Result<()> {
        let entry = self.tunnels.get_mut(profile_id)
            .ok_or_else(|| anyhow!("Profile {} is not connected", profile_id))?;

        if let Some(cancel) = &entry.cancel {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        entry.cancel = None;
        entry.state = TunnelState::Disconnected;

        tracing::info!("Profile {} disconnected", profile_id);

        self.wfp.remove_profile_filters(profile_id)?;

        // Remove Job Object — kills all processes launched under this profile
        self.jobs.remove_job(profile_id);

        Ok(())
    }

    /// Returns the tunnel LUID for a connected profile, if any.
    pub fn get_luid(&self, profile_id: &str) -> Option<u64> {
        self.tunnels.get(profile_id).and_then(|e| {
            if let TunnelState::Connected { luid, .. } = e.state {
                Some(luid)
            } else {
                None
            }
        })
    }

    /// Returns true if the profile has an active tunnel.
    pub fn is_connected(&self, profile_id: &str) -> bool {
        self.tunnels.get(profile_id)
            .map(|e| matches!(e.state, TunnelState::Connected { .. }))
            .unwrap_or(false)
    }

    /// Returns the connection status of all known profiles.
    pub fn status(&self) -> HashMap<String, bool> {
        self.tunnels
            .iter()
            .map(|(id, entry)| {
                (id.clone(), matches!(entry.state, TunnelState::Connected { .. }))
            })
            .collect()
    }

    /// Launches an exe inside the profile's Job Object.
    /// This is the correct way to start a tunnelled app —
    /// the process is inside the job before any network activity occurs.
    pub fn launch(&mut self, profile_id: &str, exe_path: &str, args: &[String]) -> Result<u32> {
        if !self.is_connected(profile_id) {
            anyhow::bail!("Profile {} is not connected", profile_id);
        }

        let proxy_addr = self.tunnels.get(profile_id).and_then(|e| {
            if let TunnelState::Connected { wintun_ip, .. } = &e.state {
                Some(format!("socks5://{}:1080", wintun_ip))
            } else {
                None
            }
        });

        self.jobs.launch(profile_id, exe_path, args, proxy_addr.as_deref())
    }

    pub fn get_wintun_index(&self, profile_id: &str) -> Result<u32> {
        let entry = self.tunnels.get(profile_id)
            .ok_or_else(|| anyhow!("Profile {} not found", profile_id))?;
        match &entry.state {
            TunnelState::Connected { iface_index, .. } => Ok(*iface_index),
            _ => anyhow::bail!("Profile {} is not connected", profile_id),
        }
    }
}