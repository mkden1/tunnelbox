mod config_store;
mod divert;
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
        .with_max_level(tracing::Level::DEBUG)
        .init();

    config_store::ConfigStore::init()?;
    tracing::info!("Config store initialised");

    let real_luid = get_adapter_luid("Ethernet")?;
    tracing::info!("Real adapter LUID: {}", real_luid);

    let tunnel_manager = Arc::new(Mutex::new(
        tunnel_manager::TunnelManager::new(real_luid)?,
    ));

    // ── Integration test ─────────────────────────────────────────────────────
    let _profile_id = {
        let mut tm = tunnel_manager.lock().unwrap();

        let profile = match config_store::ConfigStore::load_all()?
            .into_iter()
            .find(|p| p.name == "integration-test")
        {
            Some(p) => p,
            None => {
                let conf_contents = std::fs::read_to_string("vpn.conf")?;
                let mut p = config_store::ConfigStore::create("integration-test")?;
                p.save_wireguard_conf(&conf_contents)?;
                p.apps.push(config_store::AppEntry {
                    exe: r"C:\Windows\System32\curl.exe".to_string(),
                    enabled: true,
                });
                config_store::ConfigStore::update(&p)?;
                p
            }
        };

        tm.connect(&profile)?;
        tracing::info!("Profile connected — waiting 2s for WinDivert to initialise");

        // Give the packet loop thread time to open its WinDivert handle
        // before launching curl
        std::thread::sleep(std::time::Duration::from_secs(5));

        let pid = tm.launch(
            &profile.id,
            r"C:\Windows\System32\curl.exe",
            &[
                "-4".to_string(),
                "--connect-timeout".to_string(),
                "30".to_string(),
                "-o".to_string(),
                "curl_output.txt".to_string(),
                "https://ifconfig.me".to_string(),
            ],
        )?;

        tracing::info!("Launched curl via Job Object, pid: {}", pid);

        profile.id
    };
    // ── End integration test ──────────────────────────────────────────────────

    // Wait for curl to complete
    std::thread::sleep(std::time::Duration::from_secs(30));

    let output = std::fs::read_to_string("curl_output.txt").unwrap_or_default();
    tracing::info!("curl result: {}", output.trim());

    let ipc_server = ipc_server::IpcServer::new(tunnel_manager.clone());
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