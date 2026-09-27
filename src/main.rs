#![allow(dead_code)]
#![allow(unused_imports)]

mod config_store;
mod divert_engine;
mod ipc_server;
mod job_tracker;
mod tunnel_manager;
mod windows_service;

use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex, OnceLock};

static TRACING_INIT: OnceLock<()> = OnceLock::new();

fn main() -> Result<()> {
    init_tracing();

    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str());

    match subcommand {
        Some("install") => {
            windows_service::install_service()?;
        }

        Some("uninstall") => {
            windows_service::uninstall_service()?;
        }

        Some("run") | None => {
            // "run" is an explicit direct-run flag for development/testing.
            // No argument means we were either launched by SCM or from a terminal.
            // Try to hand off to SCM first; if that fails it means we're not
            // running under SCM, so fall back to direct console mode.
            if subcommand == Some("run") || !try_run_as_service() {
                run_direct()?;
            }
        }

        Some(unknown) => {
            eprintln!("Unknown subcommand: '{}'", unknown);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Attempts to start as a Windows Service. Returns false if we're not running
/// under SCM (i.e. launched directly from a terminal), true if SCM took over.
fn try_run_as_service() -> bool {
    // service_dispatcher::start() will return an error immediately if this
    // process was not started by SCM. That's our signal to run directly.
    match windows_service::run_as_service() {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Runs the daemon directly in the current process — used during development
/// or when invoked with the explicit `run` subcommand.
fn run_direct() -> Result<()> {
    tracing::info!("tunnelbox-daemon starting (direct mode)");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        config_store::ConfigStore::init()?;
        tracing::info!("Config store initialised");

        let tunnel_manager = Arc::new(Mutex::new(
            tunnel_manager::TunnelManager::new()?,
        ));

        // Auto-connect profiles marked for auto-connect
        {
            let profiles = config_store::ConfigStore::load_all()?;
            let mut tm = tunnel_manager.lock().unwrap();
            for profile in profiles.into_iter().filter(|p| p.auto_connect) {
                tracing::info!("Auto-connecting profile: {}", profile.name);
                if let Err(e) = tm.connect(&profile) {
                    tracing::warn!("Failed to auto-connect {}: {}", profile.name, e);
                }
            }
        }

        let ipc_server = ipc_server::IpcServer::new(tunnel_manager.clone());
        tracing::info!("IPC server starting");
        ipc_server.run().await?;

        anyhow::Ok(())
    })
}

pub fn init_tracing() {
    TRACING_INIT.get_or_init(|| {
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::EnvFilter;

        let filter = EnvFilter::new("debug,wfp=off");

        let file_layer = (|| -> Option<_> {
            let log_path = crate::config_store::log_path().ok()?;
            let log_dir = log_path.parent()?;
            std::fs::create_dir_all(log_dir).ok()?;
            let log_file = log_path.file_name()?;
            let appender = tracing_appender::rolling::never(log_dir, log_file);
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            Box::leak(Box::new(guard));
            Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_ansi(false),
            )
        })();

        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(true);

        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(stderr_layer)
            .init();
    });
}


pub fn get_adapter_luid(adapter_name: &str) -> Result<u64> {
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

fn print_usage() {
    eprintln!("Usage: tunnelbox-daemon [SUBCOMMAND]");
    eprintln!();
    eprintln!("SUBCOMMANDS:");
    eprintln!("  install    Register as a Windows Service (requires Administrator)");
    eprintln!("  uninstall  Remove the Windows Service registration (requires Administrator)");
    eprintln!("  run        Run directly in the current console (development mode)");
    eprintln!("  <none>     Run directly or hand off to SCM if launched as a service");
}