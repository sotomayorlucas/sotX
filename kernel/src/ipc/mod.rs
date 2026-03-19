//! Inter-Process Communication.
//!
//! Four IPC mechanisms:
//! - **Endpoints**: Per-core synchronous, register-based message passing (L4-style).
//!   For control messages and capability transfers. Small messages (≤64 bytes)
//!   are passed in registers during context switch — zero memory overhead.
//!   Each core has its own endpoint pool (no global lock).
//!
//! - **Channels**: Bounded ring buffers for high-throughput async data transfer.
//!   Senders enqueue without blocking (unless full); receivers dequeue without
//!   blocking (unless empty).
//!
//! - **Mailbox**: Per-core message queues for cross-core IPC delivery.
//!   Uses IPI (Inter-Processor Interrupt) for immediate wake signaling.
//!
//! - **Route**: Network-transparent IPC routing layer ("Swarm OS").
//!   Extends IPC to work across physical nodes in a distributed system.

pub mod channel;
pub mod endpoint;
pub mod mailbox;
pub mod notify;
pub mod route;
pub mod typed_payload;

#[cfg(feature = "ipc-audit")]
pub mod audit;

#[allow(unused_imports)]
pub use channel::ChannelId;
#[allow(unused_imports)]
pub use endpoint::{EndpointId, Message};
#[allow(unused_imports)]
pub use notify::NotifyId;
