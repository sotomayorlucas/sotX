//! USB Mass Storage (Bulk-Only Transport) driver library for sotX.
//!
//! Implements the USB Mass Storage Class Bulk-Only Transport (BBB) protocol
//! with SCSI Transparent Command Set for block I/O on USB drives.

#![no_std]

pub mod bbb;
pub mod scsi;
pub mod device;
