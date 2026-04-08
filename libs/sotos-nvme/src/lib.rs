//! sotos-nvme — NVMe SSD driver library for sotOS.
//!
//! Implements the NVM Express base specification 1.4 in userspace for a
//! single-controller, single-namespace block device. Built on top of an
//! MMIO BAR0 mapping (UC) and a small set of caller-provided DMA pages.
//! Designed for the sotOS userspace driver model: the kernel hands the
//! driver an `IoMem` capability for the BAR plus a few physical frames
//! for queues, and the driver does the rest.
//!
//! # Modules
//! - [`regs`]: MMIO register offsets, bitfield constants, doorbell
//!   geometry helpers, and `read32`/`write32` volatile accessors.
//! - [`queue`]: 64-byte [`queue::SqEntry`] / 16-byte [`queue::CqEntry`]
//!   layouts and the [`queue::SubmissionQueue`] /
//!   [`queue::CompletionQueue`] ring state.
//! - [`cmd`]: builders for the admin and NVM-IO commands the driver
//!   actually issues (Identify, Create I/O CQ/SQ, Read, Write).
//! - [`controller`]: the [`controller::NvmeController`] type and the
//!   `init` sequence (CC.EN handshake → AQA/ASQ/ACQ → Identify → I/O
//!   queue creation).
//! - [`io`]: high-level `read_sectors` / `write_sectors` plus the
//!   PRP-list variants for multi-page transfers.
//!
//! # Constraints
//! - `no_std`, no heap. Queues live in pages supplied by the caller via
//!   [`controller::DmaPages`].
//! - Single admin queue + single I/O queue (QID 1). No MSI-X vector
//!   table; interrupts are routed via a notification cap optionally set
//!   through [`controller::NvmeController::enable_interrupt_mode`].
//! - 4 KiB MPS only. PRP transfers are limited to a single PRP-list
//!   page ([`io::MAX_PRP_LIST_ENTRIES`] = 512 pages = 2 MiB).
//!
//! # References
//! NVM Express Base Specification revision 1.4 — register layout
//! ([`regs`]), command set encoding ([`cmd`]), queue mechanics
//! ([`queue`]), controller initialization sequence
//! ([`controller::NvmeController::init`]).

#![no_std]

pub mod regs;
pub mod queue;
pub mod cmd;
pub mod controller;
pub mod io;
