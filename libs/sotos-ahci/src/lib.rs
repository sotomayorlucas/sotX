//! AHCI (Advanced Host Controller Interface) SATA driver library for sotX.
//!
//! Implements the AHCI 1.3.1 specification for SATA disk I/O via MMIO registers
//! (PCI BAR5). Supports port enumeration, IDENTIFY DEVICE, and 48-bit LBA
//! DMA read/write commands.

#![no_std]

pub mod regs;
pub mod fis;
pub mod cmd;
pub mod port;
pub mod controller;
pub mod io;
