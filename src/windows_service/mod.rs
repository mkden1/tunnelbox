mod install;
mod service;

pub use install::{install_service, uninstall_service};
pub use service::run_as_service;

// The define_windows_service! macro must be invoked at the crate root or a
// module that is *not* inside a function. It generates an extern "system"
// fn called ffi_service_main which SCM calls on a dedicated thread.
windows_service::define_windows_service!(ffi_service_main, service_entry);

fn service_entry(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = service::run_service(arguments) {
        tracing::error!("Service run error: {e}");
    }
}