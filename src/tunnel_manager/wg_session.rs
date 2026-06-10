use anyhow::{anyhow, Result};
use base64::Engine;
use boringtun::noise::{TunnResult, Tunn};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use super::wintun_iface::WintunInterface;

pub struct WgSession {
    pub socket: UdpSocket,
    pub tunnel: Tunn,
    pub endpoint: SocketAddr,
}

impl WgSession {
    pub fn new(
        private_key_b64: &str,
        peer_public_key_b64: &str,
        endpoint: SocketAddr,
    ) -> Result<Self> {
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
        socket.set_nonblocking(true)?;

        let tunnel = Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(peer_public_key),
            None,
            Some(25),
            0,
            None,
        )
        .map_err(|e| anyhow!(e))?;

        Ok(Self { socket, tunnel, endpoint })
    }

    pub fn send_handshake(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        match self.tunnel.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(data) => {
                self.socket.send(data)?;
                tracing::info!("Handshake initiation sent to {}", self.endpoint);
            }
            TunnResult::Err(e) => return Err(anyhow!("Handshake failed: {:?}", e)),
            _ => {}
        }
        Ok(())
    }

    pub fn run_loop_divert(
        mut self,
        iface: WintunInterface,
        cancel: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        use std::sync::mpsc;

        let socket_send = Arc::new(self.socket.try_clone()?);
        let socket_recv = self.socket;
        socket_recv.set_nonblocking(false)?;

        let (udp_tx, udp_rx) = mpsc::channel::<Vec<u8>>();
        let (wintun_tx, wintun_rx) = mpsc::channel::<Vec<u8>>();

        // ── UDP reader thread ────────────────────────────────────────────────
        let cancel_udp = cancel.clone();
        std::thread::spawn(move || {
            let mut recv_buf = vec![0u8; 65535];
            tracing::info!("UDP reader thread started");
            loop {
                if cancel_udp.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                match socket_recv.recv(&mut recv_buf) {
                    Ok(len) => {
                        let _ = udp_tx.send(recv_buf[..len].to_vec());
                    }
                    Err(e) => {
                        tracing::warn!("UDP recv error: {}", e);
                        return;
                    }
                }
            }
        });

        // ── Wintun reader thread ─────────────────────────────────────────────
        let session = iface.session.clone();
        let cancel_wintun = cancel.clone();
        std::thread::spawn(move || {
            tracing::info!("Wintun reader thread started");
            loop {
                if cancel_wintun.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                match session.receive_blocking() {
                    Ok(pkt) => {
                        let _ = wintun_tx.send(pkt.bytes().to_vec());
                    }
                    Err(e) => {
                        tracing::warn!("Wintun recv error: {}", e);
                        return;
                    }
                }
            }
        });

        // ── Main tunnel thread ───────────────────────────────────────────────
        let mut send_buf = vec![0u8; 65535];
        tracing::info!("Tunnel processing loop started");

        loop {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }

            // Outbound: Wintun → encrypt → UDP
            while let Ok(packet) = wintun_rx.try_recv() {
                tracing::info!("Wintun read {} bytes", packet.len());
                match self.tunnel.encapsulate(&packet, &mut send_buf) {
                    TunnResult::WriteToNetwork(data) => {
                        let _ = socket_send.send(data);
                        tracing::debug!("Outbound: {} encrypted bytes", data.len());
                    }
                    TunnResult::Err(e) => tracing::warn!("Encapsulate error: {:?}", e),
                    _ => {}
                }
            }

            // Inbound: UDP → decrypt → Wintun
            while let Ok(udp_data) = udp_rx.try_recv() {
                let mut input: &[u8] = &udp_data;
                loop {
                    match self.tunnel.decapsulate(None, input, &mut send_buf) {
                        TunnResult::WriteToNetwork(data) => {
                            let _ = socket_send.send(data);
                            input = &[];
                        }
                        TunnResult::WriteToTunnelV4(data, _)
                        | TunnResult::WriteToTunnelV6(data, _) => {
                            let _ = iface.write_packet(data);
                            tracing::info!("Inbound: {} bytes to Wintun", data.len());
                            input = &[];
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(e) => {
                            tracing::warn!("Decapsulate error: {:?}", e);
                            break;
                        }
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }
}