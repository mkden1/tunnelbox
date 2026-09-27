//! FLOW-layer correlation: which `(protocol, local_port)` flows belong to a
//! target process.
//!
//! A WinDivert FLOW handle (sniff + recv-only) reports FLOW_ESTABLISHED /
//! FLOW_DELETED events carrying the owning `process_id`, local/remote ports and
//! protocol. For every event whose PID is in the tracked set (sourced from the
//! profile's Job Object) we add/remove the flow key. The NETWORK capture loop
//! then matches outbound packets against that set. Because a Job Object contains
//! all descendant processes, this also covers child processes — replacing the
//! old exe-path-polling `process_monitor`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use windivert_windows::Win32::Foundation::HANDLE;
use windivert_sys as ws;
use ws::address::WINDIVERT_ADDRESS;
use ws::{WinDivertEvent, WinDivertFlags, WinDivertLayer};

use super::nat::FlowKey;

/// Shared classification state read by the NETWORK capture loop and written by
/// the FLOW thread + the PID refresher.
#[derive(Default)]
pub struct SharedState {
    flows: RwLock<HashSet<FlowKey>>,
    pids: RwLock<HashSet<u32>>,
}

impl SharedState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// True if an outbound packet's `(proto, src_port)` belongs to a target app.
    pub fn is_tracked(&self, key: FlowKey) -> bool {
        self.flows.read().unwrap().contains(&key)
    }

    /// Replaces the set of target process IDs (called periodically from the job).
    pub fn set_pids(&self, pids: HashSet<u32>) {
        *self.pids.write().unwrap() = pids;
    }

    fn pid_is_target(&self, pid: u32) -> bool {
        self.pids.read().unwrap().contains(&pid)
    }
}

pub struct FlowTracker {
    handle: isize,
    cancel: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl FlowTracker {
    pub fn start(state: Arc<SharedState>) -> Result<Self> {
        // FLOW layer mandates sniff + recv_only.
        let flags = WinDivertFlags::new().set_sniff().set_recv_only();
        let cfilter = std::ffi::CString::new("true").unwrap();
        let handle = unsafe {
            ws::WinDivertOpen(cfilter.as_ptr(), WinDivertLayer::Flow, 0, flags)
        };
        if handle.is_invalid() {
            return Err(anyhow!(
                "WinDivertOpen(flow) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let raw = handle.0;
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_thread = cancel.clone();

        let join = std::thread::spawn(move || {
            flow_loop(raw, state, cancel_thread);
        });

        Ok(Self {
            handle: raw,
            cancel,
            join: Some(join),
        })
    }
}

impl Drop for FlowTracker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        // Unblock the blocked WinDivertRecv, then wait for the thread and close.
        unsafe { ws::WinDivertShutdown(HANDLE(self.handle), ws::WinDivertShutdownMode::Both) };
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        unsafe { ws::WinDivertClose(HANDLE(self.handle)) };
    }
}

fn flow_loop(raw: isize, state: Arc<SharedState>, cancel: Arc<AtomicBool>) {
    tracing::info!("FlowTracker thread started");
    let handle = HANDLE(raw);
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let mut addr = WINDIVERT_ADDRESS::default();
        let mut recv_len = 0u32;
        let ok = unsafe {
            ws::WinDivertRecv(handle, std::ptr::null_mut(), 0, &mut recv_len, &mut addr)
        };
        if !ok.as_bool() {
            // Shutdown or a transient error — exit on cancel, otherwise stop too.
            if !cancel.load(Ordering::Relaxed) {
                tracing::warn!(
                    "FlowTracker recv ended: {}",
                    std::io::Error::last_os_error()
                );
            }
            break;
        }

        let flow = unsafe { addr.union_field.Flow };
        if !state.pid_is_target(flow.process_id) {
            continue;
        }
        let key: FlowKey = (flow.protocol, flow.local_port);
        match addr.event() {
            WinDivertEvent::FlowStablished => {
                state.flows.write().unwrap().insert(key);
            }
            WinDivertEvent::FlowDeleted => {
                state.flows.write().unwrap().remove(&key);
            }
            _ => {}
        }
    }
    tracing::info!("FlowTracker thread stopped");
}
