//! Inter-Process Communication.
//!
//! Two IPC mechanisms:
//! - **Endpoints**: Synchronous, register-based message passing (L4-style).
//!   For control messages and capability transfers. Small messages (≤64 bytes)
//!   are passed in registers during context switch — zero memory overhead.
//!
//! - **Channels**: Bounded ring buffers for high-throughput async data transfer.
//!   Senders enqueue without blocking (unless full); receivers dequeue without
//!   blocking (unless empty).

pub mod channel;
pub mod endpoint;
pub mod notify;

pub use channel::ChannelId;
pub use endpoint::{EndpointId, Message};
pub use notify::NotifyId;
