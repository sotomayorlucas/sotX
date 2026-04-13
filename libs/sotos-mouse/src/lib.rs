//! Mouse driver library for sotX.
//!
//! Supports both PS/2 mice (3-byte and 4-byte IntelliMouse protocol)
//! and USB HID boot protocol mice. Provides a unified `MouseEvent`
//! structure and shared ring buffer for mouse events.

#![no_std]

pub mod event;
pub mod ps2;
pub mod usb_hid;
pub mod ring;

pub use event::MouseEvent;
