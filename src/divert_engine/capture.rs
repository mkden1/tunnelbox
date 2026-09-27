//! Packet capture/injection abstraction.
//!
//! `AppPacketCapture` is the swap point for the underlying kernel driver: today
//! it's backed by WinDivert (an author-signed, redistributable driver), but the
//! trait deliberately exposes only neutral owned IP packets so a WinpkFilter /
//! `ndisapi` backend can replace it without touching the engine or NAT logic.
//!
//! We call `windivert-sys` directly rather than the safe `windivert` wrapper:
//! the wrapper hides the raw `HANDLE` and its `shutdown`/`close` take `&mut self`,
//! which can't be reached from another thread while one is blocked in `recv`.
//! Owning the raw handle (an `isize`, trivially `Send`/`Sync`) lets the engine
//! unblock a blocked capture thread cleanly on disconnect.

use std::ffi::{c_void, CString};
use std::mem::size_of;

use anyhow::{anyhow, Result};
use windivert_windows::Win32::Foundation::HANDLE;
use windivert_sys as ws;
use ws::address::{WINDIVERT_ADDRESS, WINDIVERT_DATA_NETWORK};
use ws::{
    ChecksumFlags, WinDivertEvent, WinDivertFlags, WinDivertLayer, WinDivertShutdownMode,
};

use super::nat::{is_ipv4, InjectTarget};

/// Owned outbound IP packet plus the interface it was captured on (so an
/// unmatched packet can be reinjected on the same NIC).
pub struct RawPacket {
    pub data: Vec<u8>,
    pub target: InjectTarget,
}

pub trait AppPacketCapture: Send + Sync {
    /// Blocking receive of a batch of outbound IP packets. Returns an error when
    /// the handle is shut down (the caller treats that as "stop").
    fn recv(&self) -> Result<Vec<RawPacket>>;

    /// Reinjects an unmodified outbound packet the engine chose not to tunnel.
    fn reinject_outbound(&self, data: &[u8], target: InjectTarget) -> Result<()>;

    /// Injects a decapsulated reply as an inbound packet to the local stack.
    fn inject_inbound(&self, data: &[u8], target: InjectTarget) -> Result<()>;

    /// Unblocks any in-flight `recv` so the capture thread can exit.
    fn shutdown(&self);
}

/// Number of packets per batched `recv` and the buffer that backs them.
const BATCH: usize = 32;
const BUF_SIZE: usize = BATCH * 2048;

pub struct WinDivertCapture {
    /// Raw WinDivert handle value. `isize` is `Send`/`Sync`, so this is shareable.
    handle: isize,
}

impl WinDivertCapture {
    /// Opens a NETWORK-layer handle capturing only outbound IPv4 TCP/UDP,
    /// excluding loopback and the WireGuard endpoint (so the daemon's own
    /// encrypted UDP to the peer isn't pulled through userspace).
    pub fn open(endpoint_ip: &str, endpoint_port: u16, priority: i16) -> Result<Self> {
        let filter = format!(
            "outbound and ip and (tcp or udp) and not loopback \
             and not (ip.DstAddr == {endpoint_ip} and udp.DstPort == {endpoint_port})"
        );
        let cfilter = CString::new(filter)?;
        let handle = unsafe {
            ws::WinDivertOpen(
                cfilter.as_ptr(),
                WinDivertLayer::Network,
                priority,
                WinDivertFlags::new(),
            )
        };
        if handle.is_invalid() {
            return Err(anyhow!(
                "WinDivertOpen(network) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { handle: handle.0 })
    }

    #[inline]
    fn h(&self) -> HANDLE {
        HANDLE(self.handle)
    }

    fn inject(&self, data: &[u8], target: InjectTarget, outbound: bool) -> Result<()> {
        let mut buf = data.to_vec();
        let mut addr = WINDIVERT_ADDRESS::default();
        addr.set_layer(WinDivertLayer::Network);
        addr.set_event(WinDivertEvent::NetworkPacket);
        addr.set_outbound(outbound);
        addr.union_field.Network = WINDIVERT_DATA_NETWORK {
            interface_id: target.interface_id,
            subinterface_id: target.subinterface_id,
        };

        // Fix IPv4/TCP/UDP checksums after our header edits and set the
        // corresponding "checksum valid" flags WinDivertSend relies on.
        unsafe {
            ws::WinDivertHelperCalcChecksums(
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut addr,
                ChecksumFlags::new(),
            );
        }

        let mut send_len = 0u32;
        let ok = unsafe {
            ws::WinDivertSend(
                self.h(),
                buf.as_ptr() as *const c_void,
                buf.len() as u32,
                &mut send_len,
                &addr,
            )
        };
        if !ok.as_bool() {
            return Err(anyhow!(
                "WinDivertSend failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

impl AppPacketCapture for WinDivertCapture {
    fn recv(&self) -> Result<Vec<RawPacket>> {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut addrs = vec![WINDIVERT_ADDRESS::default(); BATCH];
        let mut recv_len = 0u32;
        let mut addr_len = (size_of::<WINDIVERT_ADDRESS>() * BATCH) as u32;

        let ok = unsafe {
            ws::WinDivertRecvEx(
                self.h(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut recv_len,
                0,
                addrs.as_mut_ptr(),
                &mut addr_len,
                std::ptr::null_mut(),
            )
        };
        if !ok.as_bool() {
            return Err(anyhow!(
                "WinDivertRecvEx failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let naddr = addr_len as usize / size_of::<WINDIVERT_ADDRESS>();
        let total = recv_len as usize;
        let mut out = Vec::with_capacity(naddr);

        // Packets are concatenated in `buf`; split them by IPv4 total-length.
        let mut offset = 0usize;
        for addr in addrs.iter().take(naddr) {
            if offset + 20 > total || !is_ipv4(&buf[offset..]) {
                break;
            }
            let tot_len =
                u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            if tot_len < 20 || offset + tot_len > total {
                break;
            }
            let net = unsafe { addr.union_field.Network };
            out.push(RawPacket {
                data: buf[offset..offset + tot_len].to_vec(),
                target: InjectTarget {
                    interface_id: net.interface_id,
                    subinterface_id: net.subinterface_id,
                },
            });
            offset += tot_len;
        }
        Ok(out)
    }

    fn reinject_outbound(&self, data: &[u8], target: InjectTarget) -> Result<()> {
        self.inject(data, target, true)
    }

    fn inject_inbound(&self, data: &[u8], target: InjectTarget) -> Result<()> {
        self.inject(data, target, false)
    }

    fn shutdown(&self) {
        unsafe { ws::WinDivertShutdown(self.h(), WinDivertShutdownMode::Both) };
    }
}

impl Drop for WinDivertCapture {
    fn drop(&mut self) {
        // Close the handle; the driver stays installed for reuse.
        unsafe { ws::WinDivertClose(self.h()) };
    }
}

/// Recalculates IPv4/TCP/UDP checksums in place on a plaintext packet, used
/// after SNAT and before handing the packet to boringtun for encapsulation.
pub fn recalc_checksums(data: &mut [u8]) {
    let mut addr = WINDIVERT_ADDRESS::default();
    unsafe {
        ws::WinDivertHelperCalcChecksums(
            data.as_mut_ptr() as *mut c_void,
            data.len() as u32,
            &mut addr,
            ChecksumFlags::new(),
        );
    }
}
