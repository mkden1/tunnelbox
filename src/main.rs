#![allow(dead_code)]
#![allow(unused_imports)]

mod config_store;
mod dns_proxy;
mod ipc_server;
mod job_tracker;
mod tunnel_manager;
mod wfp_manager;

use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            tracing_subscriber::EnvFilter::new("info,wfp=off")
        )
        .init();

    tracing::info!("tunnelbox-daemon starting");

    // Initialise config directory structure
    config_store::ConfigStore::init()?;
    tracing::info!("Config store initialised");

    // Resolve real network adapter LUID at startup
    // Used by WFP manager for per-app traffic blocking
    let real_luid = get_adapter_luid("Ethernet")?;
    tracing::info!("Real adapter LUID: {}", real_luid);

    // Initialise tunnel manager
    let tunnel_manager = Arc::new(Mutex::new(
        tunnel_manager::TunnelManager::new(real_luid)?,
    ));

    // Auto-connect profiles marked for auto-connect
    {
        let profiles = config_store::ConfigStore::load_all()?;
        let auto_connect: Vec<_> = profiles.into_iter()
            .filter(|p| p.auto_connect)
            .collect();

        if !auto_connect.is_empty() {
            let mut tm = tunnel_manager.lock().unwrap();
            for profile in auto_connect {
                tracing::info!("Auto-connecting profile: {}", profile.name);
                if let Err(e) = tm.connect(&profile) {
                    tracing::warn!("Failed to auto-connect {}: {}", profile.name, e);
                }
            }
        }
    }

    // Start IPC server — blocks until daemon exits
    let ipc_server = ipc_server::IpcServer::new(tunnel_manager.clone());
    tracing::info!("IPC server starting");
    ipc_server.run().await?;

    Ok(())
}

fn get_adapter_luid(adapter_name: &str) -> Result<u64> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let wide: Vec<u16> = OsStr::new(adapter_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut luid = NET_LUID_LH::default();
    unsafe {
        ConvertInterfaceAliasToLuid(
            windows::core::PCWSTR(wide.as_ptr()),
            &mut luid,
        )
    }
    .map_err(|e| anyhow!("Failed to resolve adapter '{}': {e}", adapter_name))?;

    Ok(unsafe { luid.Value })
}