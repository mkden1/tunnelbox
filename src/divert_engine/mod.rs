//! WinDivert-based per-app tunnelling engine.
//!
//! Replaces the former DLL-injection + SOCKS5 + Wintun data path. All TCP/UDP
//! traffic from a profile's processes (identified via the Job Object PID set and
//! the WinDivert FLOW layer) is captured at the packet layer, SNAT'd onto the
//! tunnel address, and driven through the in-memory boringtun WireGuard state
//! machine. Decapsulated replies are DNAT'd back and injected to the local stack.

mod capture;
mod engine;
mod flow_tracker;
mod nat;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;

use capture::{AppPacketCapture, WinDivertCapture};
use engine::{build_tunnel, run_capture_loop, run_engine_loop, run_udp_loop, EngineMsg};
use flow_tracker::{FlowTracker, SharedState};
use nat::NatTable;

/// Everything needed to bring up the engine for one profile.
pub struct DivertParams {
    pub private_key: String,
    pub peer_public_key: String,
    pub endpoint: SocketAddr,
    pub tunnel_ip: Ipv4Addr,
    /// Name of the profile's Job Object, used to poll the live target PID set.
    pub job_name: String,
}

/// A running per-profile tunnel. Dropping or calling `stop()` tears down all
/// threads and closes the WinDivert handles.
pub struct DivertEngine {
    cancel: Arc<AtomicBool>,
    capture: Arc<dyn AppPacketCapture>,
    _flow_tracker: FlowTracker,
    threads: Vec<JoinHandle<()>>,
}

impl DivertEngine {
    pub fn start(params: DivertParams) -> Result<Self> {
        let endpoint_ip = params.endpoint.ip().to_string();
        let endpoint_port = params.endpoint.port();

        // NETWORK-layer capture (outbound app packets + reinjection).
        let capture: Arc<dyn AppPacketCapture> =
            Arc::new(WinDivertCapture::open(&endpoint_ip, endpoint_port, 0)?);

        // WireGuard state machine + its UDP socket.
        let (socket, tunn) =
            build_tunnel(&params.private_key, &params.peer_public_key, params.endpoint)?;
        let socket_recv = socket.try_clone()?;

        let nat = Arc::new(NatTable::new(params.tunnel_ip));
        let state = SharedState::new();
        let flow_tracker = FlowTracker::start(state.clone())?;

        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<EngineMsg>();

        let mut threads = Vec::new();

        // Capture-classify thread.
        {
            let capture = capture.clone();
            let nat = nat.clone();
            let state = state.clone();
            let tx = tx.clone();
            let cancel = cancel.clone();
            threads.push(std::thread::spawn(move || {
                run_capture_loop(capture, nat, state, tx, cancel);
            }));
        }

        // UDP reader thread.
        {
            let tx = tx.clone();
            let cancel = cancel.clone();
            threads.push(std::thread::spawn(move || {
                run_udp_loop(socket_recv, tx, cancel);
            }));
        }

        // Engine thread (owns Tunn).
        {
            let nat = nat.clone();
            let capture = capture.clone();
            let cancel = cancel.clone();
            threads.push(std::thread::spawn(move || {
                run_engine_loop(tunn, socket, nat, capture, rx, cancel);
            }));
        }

        // PID refresher: poll the Job Object membership into the tracked set.
        {
            let job_name = params.job_name.clone();
            let state = state.clone();
            let cancel = cancel.clone();
            threads.push(std::thread::spawn(move || {
                run_pid_refresher(job_name, state, cancel);
            }));
        }

        tracing::info!(
            "DivertEngine started (endpoint {}, tunnel IP {})",
            params.endpoint,
            params.tunnel_ip
        );

        Ok(Self {
            cancel,
            capture,
            _flow_tracker: flow_tracker,
            threads,
        })
    }

    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        // Unblock the capture thread stuck in WinDivertRecvEx.
        self.capture.shutdown();
        for join in self.threads.drain(..) {
            let _ = join.join();
        }
        // FlowTracker is stopped by its Drop when `self` is dropped.
        tracing::info!("DivertEngine stopped");
    }
}

impl Drop for DivertEngine {
    fn drop(&mut self) {
        if !self.cancel.load(Ordering::Relaxed) {
            self.stop();
        }
    }
}

fn run_pid_refresher(job_name: String, state: Arc<SharedState>, cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::Relaxed) {
        let pids: HashSet<u32> =
            crate::job_tracker::query_job_pids_by_name(&job_name).into_iter().collect();
        state.set_pids(pids);
        // Responsive to cancel without polling too hard.
        for _ in 0..5 {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
