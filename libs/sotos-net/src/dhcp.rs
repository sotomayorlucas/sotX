//! DHCP client — Discover/Offer/Request/Ack protocol.
//!
//! Builds DHCP Discover and Request messages, parses Offer and Ack responses
//! to obtain dynamic IP configuration (IP, subnet, gateway, DNS).

use core::sync::atomic::{AtomicU32, Ordering};

static DHCP_XID: AtomicU32 = AtomicU32::new(0x50540001); // "PT" prefix + counter

/// DHCP message types (option 53).
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

/// DHCP magic cookie.
const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Parsed DHCP offer/ack.
#[derive(Clone, Copy)]
pub struct DhcpOffer {
    pub your_ip: u32,
    pub server_ip: u32,
    pub subnet_mask: u32,
    pub gateway: u32,
    pub dns: u32,
}

impl DhcpOffer {
    pub const fn empty() -> Self {
        Self {
            your_ip: 0,
            server_ip: 0,
            subnet_mask: 0,
            gateway: 0,
            dns: 0,
        }
    }
}

/// Build a DHCP Discover message. Returns total length.
pub fn build_discover(mac: &[u8; 6], buf: &mut [u8]) -> usize {
    if buf.len() < 300 {
        return 0;
    }

    // Zero the buffer.
    for b in buf[..300].iter_mut() {
        *b = 0;
    }

    // BOOTP header.
    buf[0] = 1;  // op: BOOTREQUEST
    buf[1] = 1;  // htype: Ethernet
    buf[2] = 6;  // hlen: MAC length
    buf[3] = 0;  // hops
    // xid (transaction ID) — counter-based for uniqueness across retries.
    let xid = DHCP_XID.fetch_add(1, Ordering::Relaxed);
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    // secs, flags = 0.
    buf[10] = 0x80; // broadcast flag
    // chaddr (client MAC).
    buf[28..34].copy_from_slice(mac);

    // DHCP magic cookie at offset 236.
    buf[236..240].copy_from_slice(&DHCP_COOKIE);

    // DHCP options.
    let mut pos = 240;

    // Option 53: DHCP Message Type = Discover.
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = DHCP_DISCOVER;
    pos += 3;

    // Option 55: Parameter Request List.
    buf[pos] = 55;
    buf[pos + 1] = 3;
    buf[pos + 2] = 1;  // Subnet mask
    buf[pos + 3] = 3;  // Router (gateway)
    buf[pos + 4] = 6;  // DNS
    pos += 5;

    // End option.
    buf[pos] = 255;
    pos += 1;

    // Pad to at least 300 bytes (BOOTP minimum).
    if pos < 300 { pos = 300; }
    pos
}

/// Build a DHCP Request message (after receiving an Offer). Returns total length.
pub fn build_request(offer: &DhcpOffer, mac: &[u8; 6], buf: &mut [u8]) -> usize {
    if buf.len() < 300 {
        return 0;
    }

    for b in buf[..300].iter_mut() {
        *b = 0;
    }

    buf[0] = 1;  // BOOTREQUEST
    buf[1] = 1;  // Ethernet
    buf[2] = 6;  // MAC len
    let xid = DHCP_XID.load(Ordering::Relaxed).wrapping_sub(1); // reuse discover's xid
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[10] = 0x80; // broadcast
    buf[28..34].copy_from_slice(mac);

    buf[236..240].copy_from_slice(&DHCP_COOKIE);

    let mut pos = 240;

    // Option 53: Message Type = Request.
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = DHCP_REQUEST;
    pos += 3;

    // Option 50: Requested IP.
    buf[pos] = 50;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&offer.your_ip.to_be_bytes());
    pos += 6;

    // Option 54: Server Identifier.
    buf[pos] = 54;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&offer.server_ip.to_be_bytes());
    pos += 6;

    // End option.
    buf[pos] = 255;
    pos += 1;

    if pos < 300 { pos = 300; }
    pos
}

/// Parse a DHCP response (Offer or Ack).
/// Returns `Some((msg_type, offer))` where msg_type is DHCP_OFFER(2) or DHCP_ACK(5).
pub fn parse_response(data: &[u8]) -> Option<(u8, DhcpOffer)> {
    if data.len() < 240 {
        return None;
    }

    // Check it's a BOOTREPLY.
    if data[0] != 2 {
        return None;
    }

    // Check magic cookie.
    if data[236..240] != DHCP_COOKIE {
        return None;
    }

    let mut offer = DhcpOffer::empty();
    offer.your_ip = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    offer.server_ip = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

    let mut msg_type: u8 = 0;

    // Parse options starting at offset 240.
    let mut pos = 240;
    while pos < data.len() {
        let opt = data[pos];
        if opt == 255 {
            break; // End
        }
        if opt == 0 {
            pos += 1; // Padding
            continue;
        }
        if pos + 1 >= data.len() {
            break;
        }
        let len = data[pos + 1] as usize;
        let opt_data = if pos + 2 + len <= data.len() {
            &data[pos + 2..pos + 2 + len]
        } else {
            break;
        };

        match opt {
            53 => {
                // DHCP Message Type.
                if len >= 1 {
                    msg_type = opt_data[0];
                }
            }
            1 => {
                // Subnet Mask.
                if len >= 4 {
                    offer.subnet_mask = u32::from_be_bytes([
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ]);
                }
            }
            3 => {
                // Router (gateway).
                if len >= 4 {
                    offer.gateway = u32::from_be_bytes([
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ]);
                }
            }
            6 => {
                // DNS server.
                if len >= 4 {
                    offer.dns = u32::from_be_bytes([
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ]);
                }
            }
            54 => {
                // Server Identifier.
                if len >= 4 {
                    offer.server_ip = u32::from_be_bytes([
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                    ]);
                }
            }
            _ => {}
        }

        pos += 2 + len;
    }

    if msg_type == DHCP_OFFER || msg_type == DHCP_ACK {
        Some((msg_type, offer))
    } else {
        None
    }
}
