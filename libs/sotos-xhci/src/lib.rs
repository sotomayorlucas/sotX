//! sotos-xhci — Userspace xHCI USB host-controller driver for sotOS.
//!
//! Implements enough of the *eXtensible Host Controller Interface
//! Specification 1.2* to bring up an emulated xHCI controller (QEMU
//! `-device qemu-xhci`), enumerate root-hub ports, address USB 2.0/3.0
//! devices, run the HID-keyboard boot protocol, and walk a USB hub one
//! level deep. Designed for the sotOS userspace driver model: the
//! kernel hands the driver an `IoMem` capability for BAR0 plus a small
//! pool of caller-allocated DMA pages, and the driver does the rest.
//!
//! # Modules
//! - [`regs`]: capability/operational/runtime register offsets, bit
//!   constants, doorbell geometry helpers and volatile MMIO accessors.
//! - [`trb`]: 16-byte [`trb::Trb`] layout, command builders, and the
//!   producer/consumer [`trb::TrbRing`] / [`trb::EventRing`] state.
//! - [`controller`]: the [`controller::XhciController`] type and the
//!   10-step bring-up sequence (halt → reset → DCBAA → cmd ring →
//!   ERST → run).
//! - [`port`]: PORTSC poking, root-hub port reset, and Input Context
//!   builders for *Address Device* / *Configure Endpoint*.
//! - [`usb`]: USB setup-packet helpers and config-descriptor parsers
//!   for HID boot keyboards and Mass-Storage BBB interfaces.
//! - [`hid`]: HID boot-protocol report → PS/2 Set 1 scancode
//!   translator that drives the existing sotOS keyboard ring buffer.
//! - [`hub`]: USB hub class requests and downstream-port enumeration.
//!
//! # Constraints
//! - `no_std`, no heap. All rings live in caller-supplied 4 KiB pages.
//! - 32-byte device contexts only (CSZ = 0); HCCPARAMS1.CSZ = 1
//!   controllers are not supported.
//! - One command ring, one event ring, one interrupter (IR0). MSI-X is
//!   driven via a notification cap installed by the wrapping service.
//! - Up to [`controller::MAX_DEVICES`] tracked USB devices.
//!
//! # References
//! eXtensible Host Controller Interface for USB Specification 1.2 —
//! register layout ([`regs`]), TRB rings ([`trb`]), 10-step
//! initialization ([`controller::XhciController::init`]). USB 2.0 / 3.x
//! standard requests ([`usb`]) and HID class spec 1.11 ([`hid`]).

#![no_std]

pub mod regs;
pub mod trb;
pub mod controller;
pub mod port;
pub mod usb;
pub mod hid;
pub mod hub;
