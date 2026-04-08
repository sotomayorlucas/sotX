//! USB Hub support for xHCI.
//!
//! Implements USB hub descriptor parsing, port status reading, and
//! recursive device enumeration through hubs.

use crate::controller::{XhciController, WaitFn};
use crate::trb::TrbRing;
use crate::usb;

// ---------------------------------------------------------------
// USB Hub Descriptor
// ---------------------------------------------------------------

/// USB Hub Descriptor (variable length, minimum 7 bytes).
#[derive(Clone, Copy)]
pub struct HubDescriptor {
    /// Length of this descriptor.
    pub length: u8,
    /// Descriptor type (0x29 for USB 2.0 hub, 0x2A for USB 3.0 hub).
    pub desc_type: u8,
    /// Number of downstream facing ports.
    pub num_ports: u8,
    /// Hub characteristics (16-bit).
    pub characteristics: u16,
    /// Time from port power-on to power-good (in 2ms units).
    pub power_on_to_good: u8,
    /// Maximum current requirements (mA).
    pub max_current: u8,
}

impl HubDescriptor {
    /// All-zeros descriptor — placeholder before a real
    /// `GET_DESCRIPTOR(HUB)` response has been parsed.
    pub const fn empty() -> Self {
        HubDescriptor {
            length: 0,
            desc_type: 0,
            num_ports: 0,
            characteristics: 0,
            power_on_to_good: 0,
            max_current: 0,
        }
    }

    /// Parse a hub descriptor from raw bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 7 {
            return None;
        }
        Some(HubDescriptor {
            length: buf[0],
            desc_type: buf[1],
            num_ports: buf[2],
            characteristics: (buf[3] as u16) | ((buf[4] as u16) << 8),
            power_on_to_good: buf[5],
            max_current: buf[6],
        })
    }

    /// Check if this is a valid hub descriptor.
    pub fn is_valid(&self) -> bool {
        self.desc_type == DESC_HUB || self.desc_type == DESC_SS_HUB
    }
}

/// USB 2.0 Hub Descriptor type.
pub const DESC_HUB: u8 = 0x29;
/// USB 3.0 SuperSpeed Hub Descriptor type.
pub const DESC_SS_HUB: u8 = 0x2A;

// ---------------------------------------------------------------
// Hub Port Status
// ---------------------------------------------------------------

// `wPortStatus` bits (USB 2.0 §11.24.2.7.1).
/// A device is present on the port.
pub const HUB_PORT_CONNECTION: u16 = 1 << 0;
/// The port is enabled (device can issue transactions).
pub const HUB_PORT_ENABLE: u16 = 1 << 1;
/// The port has been suspended.
pub const HUB_PORT_SUSPEND: u16 = 1 << 2;
/// The port has asserted over-current.
pub const HUB_PORT_OVER_CURRENT: u16 = 1 << 3;
/// The hub is currently resetting the port.
pub const HUB_PORT_RESET: u16 = 1 << 4;
/// The port's Vbus is powered.
pub const HUB_PORT_POWER: u16 = 1 << 8;
/// Low-speed device attached.
pub const HUB_PORT_LOW_SPEED: u16 = 1 << 9;
/// High-speed device attached.
pub const HUB_PORT_HIGH_SPEED: u16 = 1 << 10;

// `wPortChange` bits (USB 2.0 §11.24.2.7.2).
/// Connection status has changed since last cleared.
pub const HUB_C_PORT_CONNECTION: u16 = 1 << 0;
/// Port enable/disable status has changed.
pub const HUB_C_PORT_ENABLE: u16 = 1 << 1;
/// Suspend status has changed.
pub const HUB_C_PORT_SUSPEND: u16 = 1 << 2;
/// Over-current status has changed.
pub const HUB_C_PORT_OVER_CURRENT: u16 = 1 << 3;
/// Reset has completed.
pub const HUB_C_PORT_RESET: u16 = 1 << 4;

/// Combined port status and change (returned by GET_PORT_STATUS).
#[derive(Clone, Copy)]
pub struct HubPortStatus {
    /// `wPortStatus` word — see the `HUB_PORT_*` constants.
    pub status: u16,
    /// `wPortChange` word — see the `HUB_C_PORT_*` constants.
    pub change: u16,
}

impl HubPortStatus {
    /// `true` iff `HUB_PORT_CONNECTION` is set (device attached).
    pub fn is_connected(&self) -> bool {
        self.status & HUB_PORT_CONNECTION != 0
    }

    /// `true` iff `HUB_PORT_ENABLE` is set.
    pub fn is_enabled(&self) -> bool {
        self.status & HUB_PORT_ENABLE != 0
    }

    /// `true` iff `HUB_PORT_POWER` is set.
    pub fn is_powered(&self) -> bool {
        self.status & HUB_PORT_POWER != 0
    }

    /// `true` iff the connection-change bit is set (requires
    /// `CLEAR_FEATURE(C_PORT_CONNECTION)` to acknowledge).
    pub fn connection_changed(&self) -> bool {
        self.change & HUB_C_PORT_CONNECTION != 0
    }

    /// `true` iff the port-reset completion bit is set.
    pub fn reset_changed(&self) -> bool {
        self.change & HUB_C_PORT_RESET != 0
    }

    /// Parse from 4-byte GET_PORT_STATUS response.
    pub fn from_bytes(buf: &[u8]) -> Self {
        let status = if buf.len() >= 2 {
            (buf[0] as u16) | ((buf[1] as u16) << 8)
        } else { 0 };
        let change = if buf.len() >= 4 {
            (buf[2] as u16) | ((buf[3] as u16) << 8)
        } else { 0 };
        HubPortStatus { status, change }
    }
}

// ---------------------------------------------------------------
// Hub Class Requests
// ---------------------------------------------------------------

/// Hub class request: bmRequestType for hub requests.
const HUB_RT_PORT: u8 = 0x23; // Class, Other, Host-to-Device
const HUB_RT_PORT_IN: u8 = 0xA3; // Class, Other, Device-to-Host
const HUB_RT_HUB_IN: u8 = 0xA0; // Class, Device, Device-to-Host

/// Hub class request codes.
const HUB_REQ_GET_STATUS: u8 = 0;
const HUB_REQ_CLEAR_FEATURE: u8 = 1;
const HUB_REQ_SET_FEATURE: u8 = 3;
const HUB_REQ_GET_DESCRIPTOR: u8 = 6;

// Hub port features (USB 2.0 §11.24.2 Table 11-17).
/// `PORT_RESET` — assert reset on the downstream port.
pub const HUB_FEAT_PORT_RESET: u16 = 4;
/// `PORT_POWER` — enable Vbus on the downstream port.
pub const HUB_FEAT_PORT_POWER: u16 = 8;
/// `C_PORT_CONNECTION` — clear the connection-status change bit.
pub const HUB_FEAT_C_PORT_CONNECTION: u16 = 16;
/// `C_PORT_RESET` — clear the reset-complete change bit.
pub const HUB_FEAT_C_PORT_RESET: u16 = 20;

// ---------------------------------------------------------------
// Setup packet builders for hub requests
// ---------------------------------------------------------------

/// GET_HUB_DESCRIPTOR setup packet.
pub fn get_hub_descriptor(length: u16) -> u64 {
    usb::setup_packet(HUB_RT_HUB_IN, HUB_REQ_GET_DESCRIPTOR, (DESC_HUB as u16) << 8, 0, length)
}

/// GET_PORT_STATUS(port) setup packet. Port is 1-based.
pub fn get_port_status(port: u8) -> u64 {
    usb::setup_packet(HUB_RT_PORT_IN, HUB_REQ_GET_STATUS, 0, port as u16, 4)
}

/// SET_PORT_FEATURE(feature, port) setup packet.
pub fn set_port_feature(feature: u16, port: u8) -> u64 {
    usb::setup_packet(HUB_RT_PORT, HUB_REQ_SET_FEATURE, feature, port as u16, 0)
}

/// CLEAR_PORT_FEATURE(feature, port) setup packet.
pub fn clear_port_feature(feature: u16, port: u8) -> u64 {
    usb::setup_packet(HUB_RT_PORT, HUB_REQ_CLEAR_FEATURE, feature, port as u16, 0)
}

// ---------------------------------------------------------------
// Hub operations via xHCI control transfers
// ---------------------------------------------------------------

/// Read the hub descriptor from a hub device.
///
/// - `ctrl`: xHCI controller.
/// - `slot_id`: xHCI slot of the hub device.
/// - `ep0_ring`: EP0 transfer ring for the hub.
/// - `buf_phys`: Physical address of a data buffer (at least 16 bytes).
/// - `buf_virt`: Virtual address of the same buffer.
/// - `wait`: Wait/yield function.
pub unsafe fn read_hub_descriptor(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    buf_phys: u64,
    buf_virt: *const u8,
    wait: WaitFn,
) -> Result<HubDescriptor, &'static str> {
    // Zero the buffer.
    core::ptr::write_bytes(buf_virt as *mut u8, 0, 16);

    let setup = get_hub_descriptor(16);
    let _evt = ctrl.control_transfer_in(slot_id, ep0_ring, setup, buf_phys, 16, wait)?;

    let buf = core::slice::from_raw_parts(buf_virt, 16);
    HubDescriptor::from_bytes(buf).ok_or("hub: invalid descriptor")
}

/// Read port status from a hub device.
pub unsafe fn read_port_status(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    port: u8,
    buf_phys: u64,
    buf_virt: *const u8,
    wait: WaitFn,
) -> Result<HubPortStatus, &'static str> {
    core::ptr::write_bytes(buf_virt as *mut u8, 0, 4);

    let setup = get_port_status(port);
    let _evt = ctrl.control_transfer_in(slot_id, ep0_ring, setup, buf_phys, 4, wait)?;

    let buf = core::slice::from_raw_parts(buf_virt, 4);
    Ok(HubPortStatus::from_bytes(buf))
}

/// Power on a hub port.
pub unsafe fn power_port(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    port: u8,
    wait: WaitFn,
) -> Result<(), &'static str> {
    let setup = set_port_feature(HUB_FEAT_PORT_POWER, port);
    let _evt = ctrl.control_transfer_no_data(slot_id, ep0_ring, setup, wait)?;
    Ok(())
}

/// Reset a hub port (issues SET_FEATURE(PORT_RESET)).
pub unsafe fn reset_port(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    port: u8,
    wait: WaitFn,
) -> Result<(), &'static str> {
    let setup = set_port_feature(HUB_FEAT_PORT_RESET, port);
    let _evt = ctrl.control_transfer_no_data(slot_id, ep0_ring, setup, wait)?;
    Ok(())
}

/// Clear the connection change bit on a hub port.
pub unsafe fn clear_connection_change(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    port: u8,
    wait: WaitFn,
) -> Result<(), &'static str> {
    let setup = clear_port_feature(HUB_FEAT_C_PORT_CONNECTION, port);
    let _evt = ctrl.control_transfer_no_data(slot_id, ep0_ring, setup, wait)?;
    Ok(())
}

/// Clear the port reset change bit on a hub port.
pub unsafe fn clear_reset_change(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    port: u8,
    wait: WaitFn,
) -> Result<(), &'static str> {
    let setup = clear_port_feature(HUB_FEAT_C_PORT_RESET, port);
    let _evt = ctrl.control_transfer_no_data(slot_id, ep0_ring, setup, wait)?;
    Ok(())
}

/// Enumerate devices on a hub's downstream ports.
///
/// For each connected port:
/// 1. Power the port
/// 2. Read port status
/// 3. If connected, reset the port
/// 4. Wait for reset to complete
///
/// Returns a bitmask of ports that have connected devices ready for address assignment.
pub unsafe fn enumerate_hub_ports(
    ctrl: &mut XhciController,
    slot_id: u8,
    ep0_ring: &mut TrbRing,
    num_ports: u8,
    buf_phys: u64,
    buf_virt: *const u8,
    wait: WaitFn,
) -> u32 {
    let mut connected_mask: u32 = 0;

    for port in 1..=num_ports {
        // Power the port.
        if power_port(ctrl, slot_id, ep0_ring, port, wait).is_err() {
            continue;
        }

        // Small delay for power stabilization.
        for _ in 0..10_000 { wait(); }

        // Read status.
        let status = match read_port_status(ctrl, slot_id, ep0_ring, port, buf_phys, buf_virt, wait) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if !status.is_connected() {
            continue;
        }

        // Clear connection change.
        let _ = clear_connection_change(ctrl, slot_id, ep0_ring, port, wait);

        // Reset the port.
        if reset_port(ctrl, slot_id, ep0_ring, port, wait).is_err() {
            continue;
        }

        // Wait for reset to complete (poll port status).
        let mut reset_ok = false;
        for _ in 0..100 {
            for _ in 0..1_000 { wait(); }
            let ps = match read_port_status(ctrl, slot_id, ep0_ring, port, buf_phys, buf_virt, wait) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if ps.reset_changed() {
                let _ = clear_reset_change(ctrl, slot_id, ep0_ring, port, wait);
                if ps.is_enabled() {
                    reset_ok = true;
                }
                break;
            }
        }

        if reset_ok {
            connected_mask |= 1 << port;
        }
    }

    connected_mask
}
