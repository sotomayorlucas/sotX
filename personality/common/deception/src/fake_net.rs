//! Synthetic network responses for deception.
//!
//! Provides fake hostnames, interfaces, open ports, and service banners.
//! An attacker scanning the system sees a plausible Ubuntu server with
//! expected services (SSH, HTTP, MySQL).

use crate::{DeceptionError, MAX_FAKE_IFACES, MAX_FIELD_LEN, MAX_HONEYPOT_PORTS};

/// A fake network interface.
#[derive(Clone)]
pub struct FakeInterface {
    /// Interface name (e.g., "eth0").
    name: [u8; 16],
    name_len: usize,
    /// IPv4 address as 4 octets.
    pub ipv4: [u8; 4],
    /// Subnet mask as 4 octets.
    pub netmask: [u8; 4],
    /// MAC address as 6 octets.
    pub mac: [u8; 6],
    /// Interface is up.
    pub is_up: bool,
}

impl FakeInterface {
    const fn empty() -> Self {
        Self {
            name: [0u8; 16],
            name_len: 0,
            ipv4: [0; 4],
            netmask: [0; 4],
            mac: [0; 6],
            is_up: false,
        }
    }

    /// Interface name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// A honeypot port with a service banner.
#[derive(Clone)]
pub struct HoneypotPort {
    pub port: u16,
    pub protocol: Protocol,
    /// Banner returned on connection (e.g., "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4").
    banner: [u8; MAX_FIELD_LEN],
    banner_len: usize,
    /// Handler type for deeper interaction.
    pub handler: HoneypotHandler,
}

impl HoneypotPort {
    const fn empty() -> Self {
        Self {
            port: 0,
            protocol: Protocol::Tcp,
            banner: [0u8; MAX_FIELD_LEN],
            banner_len: 0,
            handler: HoneypotHandler::BannerOnly,
        }
    }

    /// Banner as a byte slice.
    pub fn banner(&self) -> &[u8] {
        &self.banner[..self.banner_len]
    }
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// How deeply the honeypot emulates the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotHandler {
    /// Send banner on connect, then close.
    BannerOnly,
    /// Minimal request-response (e.g., HTTP 200 with a static page).
    BasicResponse,
    /// Forward to a full deception proxy for deep interaction.
    ProxyToHandler,
}

/// Network deception engine.
pub struct NetworkDeception {
    /// Fake hostname for gethostname / uname.
    hostname: [u8; MAX_FIELD_LEN],
    hostname_len: usize,

    interfaces: [Option<FakeInterface>; MAX_FAKE_IFACES],
    iface_count: usize,

    ports: [Option<HoneypotPort>; MAX_HONEYPOT_PORTS],
    port_count: usize,
}

const NONE_IFACE: Option<FakeInterface> = None;
const NONE_PORT: Option<HoneypotPort> = None;

impl NetworkDeception {
    /// Create a new empty network deception.
    pub const fn new() -> Self {
        Self {
            hostname: [0u8; MAX_FIELD_LEN],
            hostname_len: 0,
            interfaces: [NONE_IFACE; MAX_FAKE_IFACES],
            iface_count: 0,
            ports: [NONE_PORT; MAX_HONEYPOT_PORTS],
            port_count: 0,
        }
    }

    /// Set the fake hostname.
    pub fn set_hostname(&mut self, h: &[u8]) -> Result<(), DeceptionError> {
        if h.len() > MAX_FIELD_LEN {
            return Err(DeceptionError::FieldTooLong);
        }
        self.hostname[..h.len()].copy_from_slice(h);
        self.hostname_len = h.len();
        Ok(())
    }

    /// Get the fake hostname.
    pub fn hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len]
    }

    /// Add a fake network interface.
    pub fn add_interface(
        &mut self,
        name: &[u8],
        ipv4: [u8; 4],
        netmask: [u8; 4],
        mac: [u8; 6],
    ) -> Result<usize, DeceptionError> {
        if name.len() > 16 {
            return Err(DeceptionError::FieldTooLong);
        }
        for (i, slot) in self.interfaces.iter_mut().enumerate() {
            if slot.is_none() {
                let mut iface = FakeInterface::empty();
                iface.name[..name.len()].copy_from_slice(name);
                iface.name_len = name.len();
                iface.ipv4 = ipv4;
                iface.netmask = netmask;
                iface.mac = mac;
                iface.is_up = true;
                *slot = Some(iface);
                self.iface_count += 1;
                return Ok(i);
            }
        }
        Err(DeceptionError::TableFull)
    }

    /// Add a honeypot port with a service banner.
    pub fn add_port(
        &mut self,
        port: u16,
        protocol: Protocol,
        banner: &[u8],
        handler: HoneypotHandler,
    ) -> Result<usize, DeceptionError> {
        if banner.len() > MAX_FIELD_LEN {
            return Err(DeceptionError::FieldTooLong);
        }
        for (i, slot) in self.ports.iter_mut().enumerate() {
            if slot.is_none() {
                let mut hp = HoneypotPort::empty();
                hp.port = port;
                hp.protocol = protocol;
                hp.banner[..banner.len()].copy_from_slice(banner);
                hp.banner_len = banner.len();
                hp.handler = handler;
                *slot = Some(hp);
                self.port_count += 1;
                return Ok(i);
            }
        }
        Err(DeceptionError::TableFull)
    }

    /// Look up the honeypot entry for a given port and protocol.
    pub fn lookup_port(&self, port: u16, protocol: Protocol) -> Option<&HoneypotPort> {
        self.ports
            .iter()
            .flatten()
            .find(|hp| hp.port == port && hp.protocol == protocol)
    }

    /// Iterate over all fake interfaces.
    pub fn iter_interfaces(&self) -> impl Iterator<Item = &FakeInterface> {
        self.interfaces.iter().flatten()
    }

    /// Iterate over all honeypot ports.
    pub fn iter_ports(&self) -> impl Iterator<Item = &HoneypotPort> {
        self.ports.iter().flatten()
    }

    /// Number of fake interfaces.
    pub fn interface_count(&self) -> usize {
        self.iface_count
    }

    /// Number of honeypot ports.
    pub fn port_count(&self) -> usize {
        self.port_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_and_interfaces() {
        let mut net = NetworkDeception::new();
        net.set_hostname(b"webserver01").unwrap();
        net.add_interface(
            b"eth0",
            [10, 0, 1, 50],
            [255, 255, 255, 0],
            [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02],
        )
        .unwrap();

        assert_eq!(net.hostname(), b"webserver01");
        assert_eq!(net.interface_count(), 1);
        let iface = net.iter_interfaces().next().unwrap();
        assert_eq!(iface.name(), b"eth0");
        assert_eq!(iface.ipv4, [10, 0, 1, 50]);
    }

    #[test]
    fn honeypot_port_lookup() {
        let mut net = NetworkDeception::new();
        net.add_port(
            22,
            Protocol::Tcp,
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
            HoneypotHandler::BannerOnly,
        )
        .unwrap();
        net.add_port(
            80,
            Protocol::Tcp,
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n",
            HoneypotHandler::BasicResponse,
        )
        .unwrap();

        let ssh = net.lookup_port(22, Protocol::Tcp).unwrap();
        assert!(ssh.banner().starts_with(b"SSH-2.0-OpenSSH_8.9p1"));

        assert!(net.lookup_port(443, Protocol::Tcp).is_none());
    }
}
