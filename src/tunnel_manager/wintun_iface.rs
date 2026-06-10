use anyhow::Result;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::sync::Arc;
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET};

pub struct WintunInterface {
    pub adapter: Arc<wintun::Adapter>,
    pub session: Arc<wintun::Session>,
    assigned_ip: Option<Ipv4Addr>,
}

impl WintunInterface {
    pub fn new(name: &str) -> Result<Self> {
        let wintun = unsafe { wintun::load() }?;

        let adapter = match wintun::Adapter::open(&wintun, name) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, name, name, None)?,
        };

        // Start session immediately — but set_ip and set_routes must be called
        // before the session will receive routed packets
        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

        Ok(Self {
            adapter,
            session,
            assigned_ip: None,
        })
    }

    pub fn get_luid(&self) -> u64 {
        unsafe { self.adapter.get_luid().Value }
    }

    pub fn get_adapter_index(&self) -> Result<u32> {
        Ok(self.adapter.get_adapter_index()?)
    }

    pub fn set_ip(&mut self, addr: &str) -> Result<()> {
        let ip: Ipv4Addr = addr
            .split(',')
            .map(|s| s.trim())
            .find(|s| !s.contains(':'))
            .ok_or_else(|| anyhow::anyhow!("No IPv4 address found"))?
            .split('/')
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid address format"))?
            .parse()?;

        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceIndex = self.adapter.get_adapter_index()?;
        row.OnLinkPrefixLength = 32;
        row.Address = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        };

        unsafe { CreateUnicastIpAddressEntry(&row) }
            .map_err(|e| anyhow::anyhow!("Failed to set IP: {e}"))?;

        self.assigned_ip = Some(ip);
        tracing::info!("IP assigned: {}", ip);
        Ok(())
    }

    pub fn set_routes(&self, allowed_ips: &str, _peer_endpoint_ip: &str) -> Result<()> {
        let index = self.adapter.get_adapter_index()?;

        for cidr in allowed_ips.split(',').map(|s| s.trim()) {
            if cidr.contains(':') {
                tracing::debug!("Skipping IPv6 route: {}", cidr);
                continue;
            }

            let net: Ipv4Net = cidr.parse()?;

            if net.prefix_len() == 0 {
                // High metric default route — Windows uses the real adapter's
                // lower-metric default for normal traffic, but when WFP blocks
                // an app on the real adapter it falls through to this route
                self.add_route_entry_with_metric(index, "0.0.0.0/0", 500)?;
                continue;
            }

            self.add_route_entry(index, cidr)?;
        }

        Ok(())
    }

    fn add_route_entry(&self, index: u32, cidr: &str) -> Result<()> {
        let net: Ipv4Net = cidr.parse()?;

        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = index;
        row.Metric = 1;
        row.DestinationPrefix.PrefixLength = net.prefix_len();
        row.DestinationPrefix.Prefix = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(net.network().octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        };
        row.NextHop = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: 0 },
                },
                sin_zero: [0; 8],
            },
        };

        unsafe { CreateIpForwardEntry2(&row) }
            .map_err(|e| anyhow::anyhow!("Failed to add route {cidr}: {e}"))?;

        tracing::info!("Route added: {}", cidr);
        Ok(())
    }

    fn add_route_entry_with_metric(&self, index: u32, cidr: &str, metric: u32) -> Result<()> {
        let net: Ipv4Net = cidr.parse()?;

        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = index;
        row.Metric = metric;  // high metric — only used when WFP forces Wintun
        row.DestinationPrefix.PrefixLength = net.prefix_len();
        row.DestinationPrefix.Prefix = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(net.network().octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        };
        row.NextHop = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: 0 },
                },
                sin_zero: [0; 8],
            },
        };

        unsafe { CreateIpForwardEntry2(&row) }
            .map_err(|e| anyhow::anyhow!("Failed to add route {cidr}: {e}"))?;

        tracing::info!("Route added: {} (metric {})", cidr, metric);
        Ok(())
    }

    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let len: u16 = packet
            .len()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Packet too large"))?;
        let mut tx = self.session.allocate_send_packet(len)?;
        tx.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(tx);
        Ok(())
    }

    pub fn read_packet(&self) -> Result<Option<Vec<u8>>> {
        match self.session.try_receive()? {
            Some(pkt) => Ok(Some(pkt.bytes().to_vec())),
            None => Ok(None),
        }
    }
}