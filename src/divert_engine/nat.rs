//! Connection-tracking NAT between an app's real source IP and the tunnel IP,
//! plus the minimal IPv4/TCP/UDP header helpers the engine needs.
//!
//! Outbound app packets are SNAT'd (real source IP → tunnel IP) before being
//! handed to boringtun, so the WireGuard peer sees them originating from the
//! tunnel address inside AllowedIPs. The reverse mapping is recorded so the
//! decapsulated replies can be DNAT'd back (tunnel IP → the app's real IP) and
//! injected to the local stack, where the app's socket 4-tuple still matches
//! (only the IP is rewritten — never the ports).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// TCP MSS to advertise on captured SYNs. WireGuard's tunnel MTU is ~1420, so
/// clamp below that to avoid post-encapsulation fragmentation.
pub const CLAMP_MSS: u16 = 1380;

/// Entries unused for longer than this are pruned to bound table growth.
const ENTRY_TTL: Duration = Duration::from_secs(600);

// ── IPv4 / L4 header accessors (all bounds-checked) ──────────────────────────

#[inline]
pub fn is_ipv4(pkt: &[u8]) -> bool {
    !pkt.is_empty() && (pkt[0] >> 4) == 4
}

#[inline]
fn ihl(pkt: &[u8]) -> usize {
    ((pkt[0] & 0x0f) as usize) * 4
}

#[inline]
pub fn protocol(pkt: &[u8]) -> Option<u8> {
    pkt.get(9).copied()
}

#[inline]
fn src_ip(pkt: &[u8]) -> Option<Ipv4Addr> {
    let b: [u8; 4] = pkt.get(12..16)?.try_into().ok()?;
    Some(Ipv4Addr::from(b))
}

#[inline]
fn dst_ip(pkt: &[u8]) -> Option<Ipv4Addr> {
    let b: [u8; 4] = pkt.get(16..20)?.try_into().ok()?;
    Some(Ipv4Addr::from(b))
}

fn set_src_ip(pkt: &mut [u8], ip: Ipv4Addr) {
    pkt[12..16].copy_from_slice(&ip.octets());
}

fn set_dst_ip(pkt: &mut [u8], ip: Ipv4Addr) {
    pkt[16..20].copy_from_slice(&ip.octets());
}

/// Returns the (src_port, dst_port) of a TCP or UDP IPv4 packet, if well-formed.
fn l4_ports(pkt: &[u8]) -> Option<(u16, u16)> {
    let l4 = ihl(pkt);
    let sp: [u8; 2] = pkt.get(l4..l4 + 2)?.try_into().ok()?;
    let dp: [u8; 2] = pkt.get(l4 + 2..l4 + 4)?.try_into().ok()?;
    Some((u16::from_be_bytes(sp), u16::from_be_bytes(dp)))
}

/// The (protocol, local_port) key used to correlate NETWORK packets against the
/// flow set from `flow_tracker`. `local_port` is the app's own port.
pub type FlowKey = (u8, u16);

/// For an outbound packet, the flow key is (proto, source port).
pub fn outbound_flow_key(pkt: &[u8]) -> Option<FlowKey> {
    if !is_ipv4(pkt) {
        return None;
    }
    let proto = protocol(pkt)?;
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let (src_port, _) = l4_ports(pkt)?;
    Some((proto, src_port))
}

// ── NAT table ────────────────────────────────────────────────────────────────

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct NatKey {
    proto: u8,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

struct NatEntry {
    original_src: Ipv4Addr,
    interface_id: u32,
    subinterface_id: u32,
    last: Instant,
}

/// Interface indices to reinject a decapsulated inbound packet with.
#[derive(Clone, Copy)]
pub struct InjectTarget {
    pub interface_id: u32,
    pub subinterface_id: u32,
}

pub struct NatTable {
    map: Mutex<HashMap<NatKey, NatEntry>>,
    tunnel_ip: Ipv4Addr,
    last_prune: Mutex<Instant>,
}

impl NatTable {
    pub fn new(tunnel_ip: Ipv4Addr) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            tunnel_ip,
            last_prune: Mutex::new(Instant::now()),
        }
    }

    /// Rewrites an outbound app packet's source IP to the tunnel IP and records
    /// the reverse mapping. Returns false if the packet isn't IPv4 TCP/UDP.
    /// `interface_id`/`subinterface_id` come from the WinDivert capture address
    /// and are stored so the matching reply can be injected on the same NIC.
    pub fn snat_outbound(
        &self,
        pkt: &mut [u8],
        interface_id: u32,
        subinterface_id: u32,
    ) -> bool {
        if !is_ipv4(pkt) {
            return false;
        }
        let (proto, remote_ip, local_port, remote_port) = match (
            protocol(pkt),
            src_ip(pkt),
            dst_ip(pkt),
            l4_ports(pkt),
        ) {
            (Some(p), Some(_src), Some(dst), Some((sp, dp)))
                if p == PROTO_TCP || p == PROTO_UDP =>
            {
                (p, dst, sp, dp)
            }
            _ => return false,
        };

        let original_src = match src_ip(pkt) {
            Some(ip) => ip,
            None => return false,
        };

        let key = NatKey {
            proto,
            local_port,
            remote_ip,
            remote_port,
        };

        {
            let mut map = self.map.lock().unwrap();
            map.insert(
                key,
                NatEntry {
                    original_src,
                    interface_id,
                    subinterface_id,
                    last: Instant::now(),
                },
            );
        }

        set_src_ip(pkt, self.tunnel_ip);
        self.maybe_prune();
        true
    }

    /// Rewrites a decapsulated inbound packet's destination IP (tunnel IP → the
    /// app's real IP) using the recorded mapping. Returns the interface to
    /// inject on, or None if there's no matching outbound flow.
    pub fn dnat_inbound(&self, pkt: &mut [u8]) -> Option<InjectTarget> {
        if !is_ipv4(pkt) {
            return None;
        }
        let proto = protocol(pkt)?;
        if proto != PROTO_TCP && proto != PROTO_UDP {
            return None;
        }
        // Inbound: src = remote server, dst = tunnel IP. The app's port is the
        // destination port; the remote endpoint is the source.
        let remote_ip = src_ip(pkt)?;
        let (remote_port, local_port) = l4_ports(pkt)?;

        let key = NatKey {
            proto,
            local_port,
            remote_ip,
            remote_port,
        };

        let (original_src, target) = {
            let mut map = self.map.lock().unwrap();
            let entry = map.get_mut(&key)?;
            entry.last = Instant::now();
            (
                entry.original_src,
                InjectTarget {
                    interface_id: entry.interface_id,
                    subinterface_id: entry.subinterface_id,
                },
            )
        };

        set_dst_ip(pkt, original_src);
        Some(target)
    }

    fn maybe_prune(&self) {
        let mut last = self.last_prune.lock().unwrap();
        if last.elapsed() < Duration::from_secs(30) {
            return;
        }
        *last = Instant::now();
        drop(last);

        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        map.retain(|_, e| now.duration_since(e.last) < ENTRY_TTL);
    }
}

// ── TCP MSS clamping ─────────────────────────────────────────────────────────

/// If the packet is a TCP SYN, clamps any MSS option down to `max_mss` so that
/// post-encapsulation segments don't exceed the tunnel MTU. No-op otherwise.
pub fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) {
    if !is_ipv4(pkt) || protocol(pkt) != Some(PROTO_TCP) {
        return;
    }
    let l4 = ihl(pkt);
    // TCP flags live at l4 + 13; SYN is 0x02.
    let flags = match pkt.get(l4 + 13) {
        Some(&f) => f,
        None => return,
    };
    if flags & 0x02 == 0 {
        return;
    }
    // Data offset (header length in 32-bit words) is the high nibble of l4 + 12.
    let data_offset = match pkt.get(l4 + 12) {
        Some(&b) => ((b >> 4) as usize) * 4,
        None => return,
    };
    let opts_start = l4 + 20;
    let opts_end = l4 + data_offset;
    if opts_end > pkt.len() || opts_start >= opts_end {
        return;
    }

    let mut i = opts_start;
    while i < opts_end {
        match pkt[i] {
            0 => break,     // End of options.
            1 => i += 1,    // NOP.
            2 => {
                // MSS option: kind(1) len(1)=4 value(2).
                if i + 4 > opts_end || pkt[i + 1] != 4 {
                    break;
                }
                let mss = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
                if mss > max_mss {
                    pkt[i + 2..i + 4].copy_from_slice(&max_mss.to_be_bytes());
                }
                i += 4;
            }
            _ => {
                // Generic option: kind(1) len(1) ...
                let len = match pkt.get(i + 1) {
                    Some(&l) if l >= 2 => l as usize,
                    _ => break,
                };
                i += len;
            }
        }
    }
}
