use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Signals the WireGuard packet loop thread to stop
    cancel: Option<Arc<AtomicBool>>,
    /// Signals the SOCKS5 proxy thread to stop
    proxy_cancel: Option<Arc<AtomicBool>>,
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

        // Parse the Wintun IPv4 address for the SOCKS5 proxy bind address
        let wintun_ip: std::net::Ipv4Addr = wg_conf.address
            .split(',')
            .map(|s| s.trim())
            .find(|s| !s.contains(':'))
            .ok_or_else(|| anyhow!("No IPv4 address in WireGuard config"))?
            .split('/')
            .next()
            .ok_or_else(|| anyhow!("Invalid address format"))?
            .parse()?;

        let peer_ip = wg_conf.endpoint
            .split(':')
            .next()
            .ok_or_else(|| anyhow!("Invalid endpoint"))?
            .to_string();

        iface.set_routes(&wg_conf.allowed_ips, &peer_ip)?;

        let iface_index = iface.get_adapter_index()?;
        let luid = iface.get_luid();

        // ── WireGuard packet loop thread ──────────────────────────────────
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        let profile_id_clone = profile.id.clone();

        thread::spawn(move || {
            if let Err(e) = session.run_loop_divert(iface, cancel_clone) {
                tracing::error!("Packet loop error for {}: {}", profile_id_clone, e);
            }
        });

        // Brief pause to let the Wintun interface settle before binding the proxy
        std::thread::sleep(std::time::Duration::from_millis(200));

        // ── SOCKS5 proxy thread ───────────────────────────────────────────
        let proxy_cancel = Arc::new(AtomicBool::new(false));
        let proxy_cancel_clone = proxy_cancel.clone();

        let proxy = crate::dns_proxy::Socks5Proxy::new(wintun_ip, 1080);
        thread::spawn(move || {
            if let Err(e) = proxy.run(proxy_cancel_clone) {
                tracing::error!("SOCKS5 proxy error: {e}");
            }
        });

        let wintun_ip_str = wintun_ip.to_string();

        self.tunnels.insert(
            profile.id.clone(),
            TunnelEntry {
                state: TunnelState::Connected {
                    luid,
                    iface_index,
                    wintun_ip: wintun_ip_str,
                },
                cancel: Some(cancel),
                proxy_cancel: Some(proxy_cancel),
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
    /// Signals both the WireGuard loop and SOCKS5 proxy threads to stop,
    /// removes WFP filters, and destroys the Job Object (killing all
    /// processes that were launched under this profile).
    pub fn disconnect(&mut self, profile_id: &str) -> Result<()> {
        let entry = self.tunnels.get_mut(profile_id)
            .ok_or_else(|| anyhow!("Profile {} is not connected", profile_id))?;

        // Signal WireGuard loop to stop
        if let Some(cancel) = &entry.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        entry.cancel = None;

        // Signal SOCKS5 proxy to stop — it will exit within ~250 ms
        if let Some(proxy_cancel) = &entry.proxy_cancel {
            proxy_cancel.store(true, Ordering::Relaxed);
        }
        entry.proxy_cancel = None;

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