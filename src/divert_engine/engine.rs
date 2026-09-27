//! The WireGuard state machine (boringtun) and the three worker loops.
//!
//! boringtun is used purely in-memory — there is no Wintun adapter. WinDivert
//! supplies the app's raw IP packets on the outbound side and reinjects the
//! decapsulated replies on the inbound side.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::Engine as _;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use super::capture::{recalc_checksums, AppPacketCapture};
use super::flow_tracker::SharedState;
use super::nat::{clamp_tcp_mss, outbound_flow_key, NatTable, CLAMP_MSS};

/// Messages fed to the single `Tunn`-owning thread.
pub enum EngineMsg {
    /// A SNAT'd plaintext IP packet from a tracked app, ready to encapsulate.
    Outbound(Vec<u8>),
    /// An encrypted datagram received from the WireGuard peer, ready to decapsulate.
    Inbound(Vec<u8>),
}

/// Builds a boringtun `Tunn` and its bound UDP socket, and sends the initial
/// handshake. Returns the socket (for the reader thread to clone) and the tunnel.
pub fn build_tunnel(
    private_key_b64: &str,
    peer_public_key_b64: &str,
    endpoint: SocketAddr,
) -> Result<(UdpSocket, Tunn)> {
    let private_key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(private_key_b64)?
        .try_into()
        .map_err(|_| anyhow!("PrivateKey must be 32 bytes"))?;
    let peer_public_key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(peer_public_key_b64)?
        .try_into()
        .map_err(|_| anyhow!("PeerPublicKey must be 32 bytes"))?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(endpoint)?;

    let mut tunn = Tunn::new(
        StaticSecret::from(private_key),
        PublicKey::from(peer_public_key),
        None,
        Some(25),
        0,
        None,
    )
    .map_err(|e| anyhow!("Tunn::new failed: {e}"))?;

    // Kick off the handshake so the tunnel is usable promptly.
    let mut buf = vec![0u8; 2048];
    if let TunnResult::WriteToNetwork(data) = tunn.format_handshake_initiation(&mut buf, false) {
        socket.send(data)?;
        tracing::info!("WireGuard handshake initiation sent to {endpoint}");
    }

    Ok((socket, tunn))
}

/// Capture loop: pull outbound packets, tunnel the tracked ones (SNAT + MSS
/// clamp + checksum fix), and reinject the rest unchanged. Exits when
/// `capture.recv()` errors (i.e. the handle was shut down).
pub fn run_capture_loop(
    capture: Arc<dyn AppPacketCapture>,
    nat: Arc<NatTable>,
    state: Arc<SharedState>,
    tx: Sender<EngineMsg>,
    cancel: Arc<AtomicBool>,
) {
    tracing::info!("Capture loop started");
    while !cancel.load(Ordering::Relaxed) {
        let packets = match capture.recv() {
            Ok(p) => p,
            Err(e) => {
                if !cancel.load(Ordering::Relaxed) {
                    tracing::warn!("Capture recv ended: {e}");
                }
                break;
            }
        };

        for pkt in packets {
            let tracked = outbound_flow_key(&pkt.data)
                .map(|k| state.is_tracked(k))
                .unwrap_or(false);

            if !tracked {
                // Not one of our apps — put it back on the wire untouched.
                if let Err(e) = capture.reinject_outbound(&pkt.data, pkt.target) {
                    tracing::debug!("reinject_outbound failed: {e}");
                }
                continue;
            }

            let mut data = pkt.data;
            if nat.snat_outbound(&mut data, pkt.target.interface_id, pkt.target.subinterface_id) {
                clamp_tcp_mss(&mut data, CLAMP_MSS);
                recalc_checksums(&mut data);
                if tx.send(EngineMsg::Outbound(data)).is_err() {
                    break;
                }
            } else {
                // Couldn't parse/NAT it — reinject rather than black-hole.
                let _ = capture.reinject_outbound(&data, pkt.target);
            }
        }
    }
    tracing::info!("Capture loop stopped");
}

/// UDP reader loop: forward encrypted datagrams from the peer to the engine.
pub fn run_udp_loop(socket: UdpSocket, tx: Sender<EngineMsg>, cancel: Arc<AtomicBool>) {
    tracing::info!("UDP reader thread started");
    let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
    let mut buf = vec![0u8; 65535];
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match socket.recv(&mut buf) {
            Ok(len) => {
                if tx.send(EngineMsg::Inbound(buf[..len].to_vec())).is_err() {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                tracing::warn!("WireGuard UDP recv error: {e}");
                break;
            }
        }
    }
    tracing::info!("UDP reader thread stopped");
}

/// Engine loop: the sole owner of `Tunn`. Encapsulates outbound packets to the
/// peer and decapsulates inbound datagrams, DNAT'ing replies back to the app's
/// real IP and injecting them. On idle it drives boringtun's timers (handshake
/// refresh + keepalive).
pub fn run_engine_loop(
    mut tunn: Tunn,
    socket: UdpSocket,
    nat: Arc<NatTable>,
    capture: Arc<dyn AppPacketCapture>,
    rx: Receiver<EngineMsg>,
    cancel: Arc<AtomicBool>,
) {
    tracing::info!("Engine loop started");
    let mut buf = vec![0u8; 65535];

    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(EngineMsg::Outbound(pkt)) => {
                match tunn.encapsulate(&pkt, &mut buf) {
                    TunnResult::WriteToNetwork(data) => {
                        let _ = socket.send(data);
                    }
                    TunnResult::Err(e) => tracing::debug!("encapsulate error: {e:?}"),
                    _ => {}
                }
            }
            Ok(EngineMsg::Inbound(datagram)) => {
                decapsulate_all(&mut tunn, &datagram, &mut buf, &socket, &nat, &capture);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Idle: drive handshake/keepalive timers.
                match tunn.update_timers(&mut buf) {
                    TunnResult::WriteToNetwork(data) => {
                        let _ = socket.send(data);
                    }
                    _ => {}
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    tracing::info!("Engine loop stopped");
}

/// Decapsulates a datagram, flushing any queued packets boringtun returns.
fn decapsulate_all(
    tunn: &mut Tunn,
    datagram: &[u8],
    buf: &mut [u8],
    socket: &UdpSocket,
    nat: &NatTable,
    capture: &Arc<dyn AppPacketCapture>,
) {
    let mut input: &[u8] = datagram;
    loop {
        match tunn.decapsulate(None, input, buf) {
            TunnResult::WriteToNetwork(data) => {
                let _ = socket.send(data);
                // Flush any remaining queued packets with empty input.
                input = &[];
            }
            TunnResult::WriteToTunnelV4(data, _) => {
                let mut reply = data.to_vec();
                if let Some(target) = nat.dnat_inbound(&mut reply) {
                    if let Err(e) = capture.inject_inbound(&reply, target) {
                        tracing::debug!("inject_inbound failed: {e}");
                    }
                }
                input = &[];
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                // IPv6 tunnelling is a follow-up; ignore for now.
                input = &[];
            }
            TunnResult::Done => break,
            TunnResult::Err(e) => {
                tracing::debug!("decapsulate error: {e:?}");
                break;
            }
        }
    }
}
