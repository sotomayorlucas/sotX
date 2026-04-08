//! USB descriptor parsing and setup packet helpers.

// ---------------------------------------------------------------------------
// USB Setup Packet helpers
// ---------------------------------------------------------------------------

/// Pack a USB setup packet into a u64 (little-endian, for IDT in Setup Stage TRB).
/// Fields: bmRequestType(1), bRequest(1), wValue(2), wIndex(2), wLength(2).
pub fn setup_packet(
    bm_request_type: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
) -> u64 {
    (bm_request_type as u64)
        | ((b_request as u64) << 8)
        | ((w_value as u64) << 16)
        | ((w_index as u64) << 32)
        | ((w_length as u64) << 48)
}

// Standard requests (USB 2.0 §9.4).
/// `GET_DESCRIPTOR` — bRequest = 6.
pub const REQ_GET_DESCRIPTOR: u8 = 6;
/// `SET_CONFIGURATION` — bRequest = 9.
pub const REQ_SET_CONFIGURATION: u8 = 9;

// HID class requests (bmRequestType = 0x21 for interface OUT).
/// `SET_PROTOCOL` — HID class request, bRequest = 0x0B.
pub const REQ_SET_PROTOCOL: u8 = 0x0B;
/// `SET_IDLE` — HID class request, bRequest = 0x0A.
pub const REQ_SET_IDLE: u8 = 0x0A;

// Descriptor types (USB 2.0 §9.4, Table 9-5).
/// Device descriptor — wValue high byte = 1.
pub const DESC_DEVICE: u8 = 1;
/// Configuration descriptor — wValue high byte = 2.
pub const DESC_CONFIGURATION: u8 = 2;
/// Interface descriptor — wValue high byte = 4.
pub const DESC_INTERFACE: u8 = 4;
/// Endpoint descriptor — wValue high byte = 5.
pub const DESC_ENDPOINT: u8 = 5;

// HID class/protocol.
/// USB HID base-class code (USB HID 1.11 §4.1).
pub const HID_CLASS: u8 = 3;
/// HID boot-subclass (USB HID 1.11 §4.2).
pub const HID_SUBCLASS_BOOT: u8 = 1;
/// HID boot-protocol keyboard (USB HID 1.11 §4.3).
pub const HID_PROTOCOL_KEYBOARD: u8 = 1;

/// GET_DESCRIPTOR(Device, 18 bytes) setup packet.
pub fn get_device_descriptor() -> u64 {
    setup_packet(0x80, REQ_GET_DESCRIPTOR, (DESC_DEVICE as u16) << 8, 0, 18)
}

/// GET_DESCRIPTOR(Configuration, `length` bytes) setup packet.
pub fn get_config_descriptor(length: u16) -> u64 {
    setup_packet(0x80, REQ_GET_DESCRIPTOR, (DESC_CONFIGURATION as u16) << 8, 0, length)
}

/// SET_CONFIGURATION(config_value) setup packet.
pub fn set_configuration(config_value: u8) -> u64 {
    setup_packet(0x00, REQ_SET_CONFIGURATION, config_value as u16, 0, 0)
}

/// SET_PROTOCOL(protocol, interface) setup packet. protocol=0 for boot.
pub fn set_protocol(protocol: u8, interface: u16) -> u64 {
    setup_packet(0x21, REQ_SET_PROTOCOL, protocol as u16, interface, 0)
}

/// SET_IDLE(duration=0, interface) setup packet.
pub fn set_idle(interface: u16) -> u64 {
    setup_packet(0x21, REQ_SET_IDLE, 0, interface, 0)
}

// ---------------------------------------------------------------------------
// Configuration descriptor parsing
// ---------------------------------------------------------------------------

/// Result of parsing a configuration descriptor for a HID keyboard.
pub struct HidKbdInfo {
    /// `bConfigurationValue` from the configuration descriptor.
    pub config_value: u8,
    /// `bInterfaceNumber` of the matched HID boot keyboard interface.
    pub interface_num: u8,
    /// Endpoint address (e.g. `0x81` = EP1 IN) of the interrupt IN endpoint.
    pub ep_addr: u8,
    /// `wMaxPacketSize` from the endpoint descriptor.
    pub max_packet: u16,
    /// `bInterval` — polling interval in frames/microframes.
    pub interval: u8,
}

/// Parse a configuration descriptor buffer to find a HID boot keyboard interface
/// and its interrupt IN endpoint.
/// Returns None if no HID keyboard found.
pub fn parse_config_for_hid_kbd(buf: &[u8]) -> Option<HidKbdInfo> {
    if buf.len() < 9 {
        return None;
    }
    let config_value = buf[5];
    let total_len = (buf[2] as usize) | ((buf[3] as usize) << 8);
    let parse_len = if total_len < buf.len() { total_len } else { buf.len() };

    let mut offset = 0;
    let mut found_hid_kbd = false;
    let mut interface_num: u8 = 0;

    while offset + 1 < parse_len {
        let desc_len = buf[offset] as usize;
        let desc_type = buf[offset + 1];
        if desc_len < 2 || offset + desc_len > parse_len {
            break;
        }

        if desc_type == DESC_INTERFACE && desc_len >= 9 {
            let iface_class = buf[offset + 5];
            let iface_subclass = buf[offset + 6];
            let iface_protocol = buf[offset + 7];
            if iface_class == HID_CLASS
                && iface_subclass == HID_SUBCLASS_BOOT
                && iface_protocol == HID_PROTOCOL_KEYBOARD
            {
                found_hid_kbd = true;
                interface_num = buf[offset + 2];
            } else {
                found_hid_kbd = false;
            }
        }

        if desc_type == DESC_ENDPOINT && desc_len >= 7 && found_hid_kbd {
            let ep_addr = buf[offset + 2];
            // Check if Interrupt IN (bit 7 = IN, bits 1:0 of bmAttributes = 3 = Interrupt).
            if (ep_addr & 0x80) != 0 && (buf[offset + 3] & 0x03) == 3 {
                let max_packet = (buf[offset + 4] as u16) | ((buf[offset + 5] as u16) << 8);
                let interval = buf[offset + 6];
                return Some(HidKbdInfo {
                    config_value,
                    interface_num,
                    ep_addr,
                    max_packet,
                    interval,
                });
            }
        }

        offset += desc_len;
    }
    None
}

/// Mass storage interface info (Bulk-Only Transport).
pub struct MassStorageInfo {
    /// `bInterfaceNumber` of the matched BBB interface.
    pub interface_num: u8,
    /// Bulk-IN endpoint address (e.g. `0x81`).
    pub ep_bulk_in: u8,
    /// Bulk-OUT endpoint address (e.g. `0x02`).
    pub ep_bulk_out: u8,
    /// `wMaxPacketSize` of the Bulk-IN endpoint.
    pub max_packet_in: u16,
    /// `wMaxPacketSize` of the Bulk-OUT endpoint.
    pub max_packet_out: u16,
}

/// Parse a USB configuration descriptor for a Mass Storage interface.
/// Class=0x08 (Mass Storage), SubClass=0x06 (SCSI), Protocol=0x50 (BBB).
pub fn parse_config_for_mass_storage(buf: &[u8]) -> Option<MassStorageInfo> {
    if buf.len() < 4 || buf[1] != 2 { return None; } // DT_CONFIGURATION
    let total_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let total_len = total_len.min(buf.len());

    let mut offset = 0;
    let mut in_mass_storage = false;
    let mut iface_num = 0u8;
    let mut ep_in = 0u8;
    let mut ep_out = 0u8;
    let mut pkt_in = 0u16;
    let mut pkt_out = 0u16;

    while offset + 2 <= total_len {
        let desc_len = buf[offset] as usize;
        let desc_type = buf[offset + 1];
        if desc_len < 2 { break; }

        if desc_type == 4 && offset + 9 <= total_len {
            // Interface descriptor
            let bclass = buf[offset + 5];
            let bsubclass = buf[offset + 6];
            let bprotocol = buf[offset + 7];
            if bclass == 0x08 && bsubclass == 0x06 && bprotocol == 0x50 {
                in_mass_storage = true;
                iface_num = buf[offset + 2];
            } else {
                in_mass_storage = false;
            }
        } else if desc_type == 5 && in_mass_storage && offset + 7 <= total_len {
            // Endpoint descriptor
            let ep_addr = buf[offset + 2];
            let max_pkt = u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]);
            if ep_addr & 0x80 != 0 {
                ep_in = ep_addr;
                pkt_in = max_pkt;
            } else {
                ep_out = ep_addr;
                pkt_out = max_pkt;
            }
        }
        offset += desc_len;
    }

    if ep_in != 0 && ep_out != 0 {
        Some(MassStorageInfo {
            interface_num: iface_num,
            ep_bulk_in: ep_in,
            ep_bulk_out: ep_out,
            max_packet_in: pkt_in,
            max_packet_out: pkt_out,
        })
    } else {
        None
    }
}

/// Convert a USB endpoint address to xHCI Device Context Index (DCI).
/// IN endpoints: DCI = ep_num * 2 + 1
/// OUT endpoints: DCI = ep_num * 2
pub fn ep_addr_to_dci(ep_addr: u8) -> u8 {
    let ep_num = ep_addr & 0x0F;
    if ep_addr & 0x80 != 0 {
        ep_num * 2 + 1  // IN
    } else {
        ep_num * 2      // OUT
    }
}

/// Convert a USB bInterval to xHCI interval encoding.
/// For FS/LS interrupt endpoints, xHCI interval = bInterval + 3 (mapped to 125us frames).
/// For HS/SS, xHCI interval = bInterval - 1.
pub fn convert_interval(b_interval: u8, speed: u8) -> u8 {
    match speed {
        1 | 2 => {
            // Full/Low speed: interval in ms (1-255). Convert to 125us frames.
            // xHCI wants exponent: 2^(interval) * 125us. Closest: interval + 3.
            let mut val = b_interval as u32;
            if val == 0 { val = 1; }
            // Find closest power of 2 >= val ms in 125us frames (8 frames = 1ms).
            let frames = val * 8;
            let mut exp: u8 = 0;
            let mut f = 1u32;
            while f < frames && exp < 15 {
                f *= 2;
                exp += 1;
            }
            exp
        }
        _ => {
            // High/SuperSpeed: already in 125us exponent form.
            if b_interval > 0 { b_interval - 1 } else { 0 }
        }
    }
}
