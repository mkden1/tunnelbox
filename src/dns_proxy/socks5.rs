use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use socket2::{Socket, Domain, Type};

pub struct Socks5Proxy {
    bind_addr: SocketAddr,
}

impl Socks5Proxy {
    /// Creates a SOCKS5 proxy bound to the given address.
    /// Should be bound to the Wintun adapter IP so it's only
    /// reachable through the tunnel interface.
    pub fn new(bind_ip: Ipv4Addr, port: u16) -> Self {
        Self {
            bind_addr: SocketAddr::new(bind_ip.into(), port),
        }
    }

    /// Starts the proxy — blocks until `cancel` is set to true.
    /// Call on its own thread. Pass the same `cancel` flag to
    /// `TunnelEntry` so `disconnect()` can shut it down cleanly.
    pub fn run(&self, cancel: Arc<AtomicBool>) -> Result<()> {
        // Build the listener via socket2 so we can set a read timeout,
        // which allows the accept loop to wake up and check `cancel`
        // periodically rather than blocking forever.
        let socket = {
            let mut last_err = None;
            let mut sock = None;
            for _attempt in 0..20 {
                match self.try_bind() {
                    Ok(s) => { sock = Some(s); break; }
                    Err(e) => {
                        last_err = Some(e);
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
            }
            sock.ok_or_else(|| anyhow!("SOCKS5 failed to bind after retries: {:?}", last_err))?
        };

        // Wake up every 250 ms to check the cancel flag
        socket.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;

        let listener: std::net::TcpListener = socket.into();
        tracing::info!("SOCKS5 proxy listening on {}", self.bind_addr);

        let bind_ip = match self.bind_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => return Err(anyhow!("Only IPv4 supported")),
        };

        loop {
            if cancel.load(Ordering::Relaxed) {
                tracing::info!("SOCKS5 proxy shutting down on {}", self.bind_addr);
                return Ok(());
            }

            match listener.accept() {
                Ok((client, _)) => {
                    std::thread::spawn(move || {
                        if let Err(e) = handle_client(client, bind_ip) {
                            tracing::warn!("SOCKS5 client error: {e}");
                        }
                    });
                }
                // Timeout from set_read_timeout — expected, just loop back
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => tracing::warn!("SOCKS5 accept error: {e}"),
            }
        }
    }

    /// Builds and binds the socket2 listener socket.
    fn try_bind(&self) -> Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        socket.bind(&self.bind_addr.into())?;
        socket.listen(128)?;
        Ok(socket)
    }
}

fn handle_client(mut client: TcpStream, bind_ip: Ipv4Addr) -> Result<()> {
    // ── SOCKS5 handshake ─────────────────────────────────────────────────

    // Read greeting: VER NMETHODS METHODS...
    let mut buf = [0u8; 257];
    client.read_exact(&mut buf[..2])?;

    if buf[0] != 5 {
        return Err(anyhow!("Not SOCKS5"));
    }

    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods])?;

    // Reply: no authentication required
    client.write_all(&[5, 0])?;

    // ── Read CONNECT request ─────────────────────────────────────────────
    // VER CMD RSV ATYP ...
    client.read_exact(&mut buf[..4])?;

    if buf[0] != 5 || buf[1] != 1 {
        // Only support CONNECT (cmd=1)
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Err(anyhow!("Unsupported SOCKS5 command: {}", buf[1]));
    }

    let target_addr = match buf[3] {
        // IPv4
        1 => {
            client.read_exact(&mut buf[..4])?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf)?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", ip, port)
        }
        // Domain name
        3 => {
            client.read_exact(&mut buf[..1])?;
            let len = buf[0] as usize;
            client.read_exact(&mut buf[..len])?;
            let domain = std::str::from_utf8(&buf[..len])
                .map_err(|_| anyhow!("Invalid domain"))?
                .to_string();
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf)?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", domain, port)
        }
        // IPv6
        4 => {
            client.read_exact(&mut buf[..16])?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf)?;
            let port = u16::from_be_bytes(port_buf);
            format!("[{}]:{}", std::net::Ipv6Addr::from(
                TryInto::<[u8; 16]>::try_into(&buf[..16]).unwrap()
            ), port)
        }
        _ => {
            client.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return Err(anyhow!("Unsupported address type: {}", buf[3]));
        }
    };

    tracing::debug!("SOCKS5 CONNECT → {}", target_addr);

    // ── Connect to target ────────────────────────────────────────────────
    // Bind to Wintun IP so the connection goes through the tunnel
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::new(bind_ip.into(), 0).into())?;

    match socket.connect(&target_addr.parse::<SocketAddr>()
        .map_err(|_| anyhow!("Invalid target: {}", target_addr))?.into())
    {
        Ok(_) => {
            let mut server = std::net::TcpStream::from(socket);
            client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            tracing::debug!("SOCKS5 connected to {} via {}", target_addr, bind_ip);

            let mut client2 = client.try_clone()?;
            let mut server2 = server.try_clone()?;

            let t1 = std::thread::spawn(move || {
                let _ = std::io::copy(&mut client, &mut server);
                let _ = server.shutdown(std::net::Shutdown::Write);
            });
            let t2 = std::thread::spawn(move || {
                let _ = std::io::copy(&mut server2, &mut client2);
                let _ = client2.shutdown(std::net::Shutdown::Write);
            });

            t1.join().ok();
            t2.join().ok();
        }
        Err(e) => {
            tracing::warn!("SOCKS5 failed to connect to {}: {e}", target_addr);
            client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?;
        }
    }

    Ok(())
}