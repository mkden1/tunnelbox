use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use windows_service::{
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::ipc_server::IpcServer;
use crate::tunnel_manager::TunnelManager;

const SERVICE_NAME: &str = "tunnelbox-daemon";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Called from main() when no subcommand is given and we detect we're under SCM.
/// Hands control to the service dispatcher — blocks until the service stops.
pub fn run_as_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, super::ffi_service_main)
        .map_err(|e| anyhow::anyhow!("Service dispatcher failed: {e}"))
}

/// The actual service logic, called by ffi_service_main on an SCM thread.
pub fn run_service(_arguments: Vec<OsString>) -> windows_service::Result<()> {
    // Channel used to receive the stop signal from the SCM control handler.
    // The handler closure runs on a separate SCM thread so we need this to
    // communicate back to the service work thread.
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report START_PENDING while we initialise
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    // Run the daemon initialisation. Any error here becomes a service failure.
    let result = init_and_run(status_handle.clone(), stop_rx);

    // Report STOPPED regardless of how we exited
    let exit_code = match &result {
        Ok(_) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };

    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    if let Err(e) = result {
        tracing::error!("Service stopped with error: {e}");
    }

    Ok(())
}

fn init_and_run(
    status_handle: service_control_handler::ServiceStatusHandle,
    stop_rx: std::sync::mpsc::Receiver<()>,
) -> Result<()> {
    // Build a tokio runtime manually — we can't use #[tokio::main] here
    // because we're already on an SCM-managed thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        crate::config_store::ConfigStore::init()?;

        let real_luid = crate::get_adapter_luid("Ethernet")?;
        tracing::info!("Real adapter LUID: {}", real_luid);

        let tunnel_manager = Arc::new(Mutex::new(TunnelManager::new(real_luid)?));

        // Auto-connect profiles
        {
            let profiles = crate::config_store::ConfigStore::load_all()?;
            let mut tm = tunnel_manager.lock().unwrap();
            for profile in profiles.into_iter().filter(|p| p.auto_connect) {
                tracing::info!("Auto-connecting profile: {}", profile.name);
                if let Err(e) = tm.connect(&profile) {
                    tracing::warn!("Failed to auto-connect {}: {}", profile.name, e);
                }
            }
        }

        // Now report RUNNING
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| anyhow::anyhow!("Failed to report Running status: {e}"))?;

        tracing::info!("Service running");

        // Spawn the IPC server on the tokio runtime
        let ipc_server = IpcServer::new(tunnel_manager.clone());
        let ipc_handle = tokio::spawn(async move {
            if let Err(e) = ipc_server.run().await {
                tracing::error!("IPC server error: {e}");
            }
        });

        // Block until SCM sends us a stop signal
        tokio::task::spawn_blocking(move || {
            let _ = stop_rx.recv();
        })
        .await
        .ok();

        tracing::info!("Stop signal received, shutting down");

        // Report STOP_PENDING
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        });

        // Abort the IPC server task — this unblocks any waiting pipe accepts
        ipc_handle.abort();

        // Disconnect all active tunnels cleanly
        {
            let mut tm = tunnel_manager.lock().unwrap();
            let profile_ids: Vec<String> = tm.status().keys().cloned().collect();
            for id in profile_ids {
                if tm.is_connected(&id) {
                    if let Err(e) = tm.disconnect(&id) {
                        tracing::warn!("Error disconnecting profile {} on shutdown: {e}", id);
                    }
                }
            }
        }

        anyhow::Ok(())
    })
}