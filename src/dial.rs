use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tracing::debug;

/// Dial TCP bound to the physical uplink so packets never re-enter the TUN.
pub async fn dial_tcp(addr: SocketAddr, uplink_iface: &str) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    bind_device(&socket, uplink_iface)?;
    socket.set_nonblocking(true)?;
    socket.set_nodelay(true)?;
    #[cfg(target_os = "linux")]
    socket.set_keepalive(true)?;

    let tcp = TcpSocket::from_std_stream(socket.into());
    debug!(%addr, iface = uplink_iface, "dial tcp");
    tcp.connect(addr).await
}

pub async fn dial_udp(addr: SocketAddr, uplink_iface: &str) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    bind_device(&socket, uplink_iface)?;
    socket.set_nonblocking(true)?;
    let sock = UdpSocket::from_std(socket.into())?;
    sock.connect(addr).await?;
    Ok(sock)
}

fn bind_device(socket: &Socket, iface: &str) -> io::Result<()> {
    if iface.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, iface);
    }
    Ok(())
}

/// Physical uplink from the main routing table (not policy-routed via TUN/Tailscale).
pub fn detect_uplink_iface() -> io::Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "table", "main", "default"])
        .output()?;
    if out.status.success() {
        if let Some(dev) = parse_dev(&String::from_utf8_lossy(&out.stdout)) {
            if !is_virtual_uplink(&dev) {
                return Ok(dev);
            }
        }
    }

    // Fallback: first default route in any table that isn't the TUN/Tailscale path.
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other("ip route show default failed"));
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(dev) = parse_dev(line) {
            if !is_virtual_uplink(&dev) {
                return Ok(dev);
            }
        }
    }
    Err(io::Error::other("could not detect physical uplink iface"))
}

fn parse_dev(text: &str) -> Option<String> {
    let mut parts = text.split_whitespace();
    while let Some(tok) = parts.next() {
        if tok == "dev" {
            return parts.next().map(str::to_string);
        }
    }
    None
}

fn is_virtual_uplink(dev: &str) -> bool {
    dev == "lo"
        || dev.starts_with("tailscale")
        || dev.starts_with("safethrottle")
        || dev.starts_with("tun")
        || dev.starts_with("wg")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dev_from_default_route() {
        let line = "default via 10.0.0.1 dev wlp0s20f3 proto dhcp src 10.0.0.42";
        assert_eq!(parse_dev(line).as_deref(), Some("wlp0s20f3"));
    }

    #[test]
    fn skips_virtual_uplinks() {
        assert!(is_virtual_uplink("tailscale0"));
        assert!(is_virtual_uplink("safethrottle0"));
        assert!(!is_virtual_uplink("wlp0s20f3"));
    }
}
