use std::ffi::OsString;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use windows_service::{
    service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;

const SERVICE_NAME: &str = "tunnelbox-daemon";
const SERVICE_DISPLAY_NAME: &str = "Tunnelbox Daemon";
const SERVICE_DESCRIPTION: &str = "Per-app WireGuard tunnel daemon for Tunnelbox";

/// Registers tunnelbox-daemon as a Windows Service set to start automatically.
/// Must be run elevated (Administrator).
///
/// The service is registered to run as the current executable, so run this
/// from the binary you actually want to install (e.g. the release build).
pub fn install_service() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| anyhow!("Failed to open Service Manager (are you running as Administrator?): {e}"))?;

    let exe_path = std::env::current_exe()
        .map_err(|e| anyhow!("Failed to resolve current exe path: {e}"))?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        // AUTO_START — starts at boot before any user logs in
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        // None = LocalSystem account
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| anyhow!("Failed to create service: {e}"))?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| anyhow!("Failed to set service description: {e}"))?;

    println!("Service '{}' installed successfully.", SERVICE_NAME);
    println!("Start it with:  net start {}", SERVICE_NAME);
    println!("Stop it with:   net stop {}", SERVICE_NAME);

    Ok(())
}

/// Stops (if running) and removes tunnelbox-daemon from the Service Manager.
/// Must be run elevated (Administrator).
pub fn uninstall_service() -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| anyhow!("Failed to open Service Manager: {e}"))?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| anyhow!("Failed to open service '{}': {e}", SERVICE_NAME))?;

    // Mark for deletion first — this succeeds even if the service is running
    service
        .delete()
        .map_err(|e| anyhow!("Failed to mark service for deletion: {e}"))?;

    // Stop it if it's currently running
    let status = service
        .query_status()
        .map_err(|e| anyhow!("Failed to query service status: {e}"))?;

    if status.current_state != ServiceState::Stopped {
        println!("Stopping service...");
        service
            .stop()
            .map_err(|e| anyhow!("Failed to stop service: {e}"))?;
    }

    // Drop our handle so SCM can fully delete it
    drop(service);

    // Poll until the service is gone from the database (up to 10 seconds)
    let timeout = Duration::from_secs(10);
    let start = Instant::now();
    loop {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
            {
                println!("Service '{}' removed successfully.", SERVICE_NAME);
                return Ok(());
            }
            _ => {}
        }

        if start.elapsed() >= timeout {
            println!(
                "Service '{}' is marked for deletion and will be removed after the next restart.",
                SERVICE_NAME
            );
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}