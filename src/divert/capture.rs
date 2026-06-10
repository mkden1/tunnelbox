use anyhow::{anyhow, Result};
use std::borrow::Cow;
use std::sync::Arc;
use windivert::WinDivert;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::*;

pub struct CapturedPacket {
    pub data: Vec<u8>,
    pub address: windivert::address::WinDivertAddress<NetworkLayer>,
}

pub struct DivertCapture {
    // Priority 1000 — captures outbound packets from user processes
    capture: Arc<WinDivert<NetworkLayer>>,
    // Priority 999 — injects inbound packets; sniff mode so they
    // pass through without being re-captured by the capture handle
    injector: Arc<WinDivert<NetworkLayer>>,
    pub interface_index: u32,
}

impl DivertCapture {
    pub fn open(interface_index: u32) -> Result<Self> {
        // Only capture outbound packets — not our own injected inbound ones
        let filter = format!("inbound and ifIdx == {}", interface_index);

        let capture = WinDivert::network(&filter, 1000, WinDivertFlags::new())
            .map_err(|e| anyhow!("Failed to open capture handle: {e}"))?;

        let inject = WinDivert::network("true", 999, WinDivertFlags::new().set_send_only())
            .map_err(|e| anyhow!("Failed to open injector handle: {e}"))?;

        Ok(Self {
            capture: Arc::new(capture),
            injector: Arc::new(inject),
            interface_index,
        })
    }

    pub fn get_capture(&self) -> Arc<WinDivert<NetworkLayer>> {
        self.capture.clone()
    }

    pub fn get_injector(&self) -> Arc<WinDivert<NetworkLayer>> {
        self.injector.clone()
    }

    pub fn recv(&self) -> Result<CapturedPacket> {
        let mut buf = vec![0u8; 65535];
        let pkt = self.capture.recv(Some(&mut buf))
            .map_err(|e| anyhow!("WinDivert recv failed: {e}"))?;
        Ok(CapturedPacket {
            data: pkt.data.into_owned(),
            address: pkt.address,
        })
    }

    /// Reinjects an outbound packet unchanged (after encryption failed or for passthrough)
    pub fn reinject(&self, pkt: &CapturedPacket) -> Result<()> {
        let windivert_pkt = WinDivertPacket {
            address: pkt.address.clone(),
            data: Cow::Borrowed(&pkt.data),
        };
        self.capture.send(&windivert_pkt)
            .map_err(|e| anyhow!("Reinject failed: {e}"))?;
        Ok(())
    }

    /// Injects decrypted inbound packet into the network stack via the injector handle.
    /// Uses send_only handle so it won't be re-captured by the capture handle.
    pub fn inject_inbound(&self, data: &[u8]) -> Result<()> {
        let mut pkt = unsafe { WinDivertPacket::<NetworkLayer>::new(data.to_vec()) };
        pkt.address.set_outbound(false);
        self.injector.send(&pkt)
            .map_err(|e| anyhow!("Inject inbound failed: {e}"))?;
        Ok(())
    }
}