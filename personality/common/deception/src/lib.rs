//! # sot-deception -- Deception Engine for sotOS
//!
//! Provides adversary-aware computing through capability interposition.
//! An attacker who compromises a domain sees a fabricated environment:
//! fake filesystems, spoofed process listings, synthetic network responses.
//!
//! The deception is invisible because it operates at the capability layer --
//! every SO access the domain makes passes through interposition rules that
//! can redirect, fabricate, or inspect the operation before (or instead of)
//! forwarding to the real service object.

#![no_std]

extern crate alloc;

pub mod fake_fs;
pub mod fake_net;
pub mod fake_proc;
pub mod interpose;
pub mod migration;
pub mod profile;
pub mod profiles;

/// Maximum interposition rules per engine instance.
pub const MAX_INTERPOSITIONS: usize = 64;

/// Maximum path length for filesystem overlays.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum number of fake processes in a deception profile.
pub const MAX_FAKE_PROCS: usize = 32;

/// Maximum number of filesystem overlay entries.
pub const MAX_FS_OVERLAYS: usize = 64;

/// Maximum number of hidden paths.
pub const MAX_HIDDEN_PATHS: usize = 32;

/// Maximum number of fake network interfaces.
pub const MAX_FAKE_IFACES: usize = 8;

/// Maximum number of honeypot port entries.
pub const MAX_HONEYPOT_PORTS: usize = 16;

/// Maximum length of a static string field (banner, hostname, etc.).
pub const MAX_FIELD_LEN: usize = 128;

/// Maximum content size for a filesystem overlay entry.
pub const MAX_CONTENT_LEN: usize = 512;

/// Result of an interception attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptResult {
    /// No rule matched -- forward to real service object unchanged.
    NotInterposed,
    /// Rule matched with Passthrough -- forward but log the access.
    Passthrough { rule_index: usize },
    /// Rule matched with Inspect -- send to proxy domain for decision.
    Inspect { rule_index: usize, proxy_domain: u32 },
    /// Rule matched with Redirect -- route to alternative service object.
    Redirect { rule_index: usize, proxy_domain: u32 },
    /// Rule matched with Fabricate -- proxy generates synthetic response.
    Fabricate { rule_index: usize, proxy_domain: u32 },
}

/// Errors from the deception subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeceptionError {
    /// No free slot in the rule/entry table.
    TableFull,
    /// The specified index or capability was not found.
    NotFound,
    /// A path string exceeded MAX_PATH_LEN.
    PathTooLong,
    /// Content exceeded MAX_CONTENT_LEN.
    ContentTooLong,
    /// A string field exceeded MAX_FIELD_LEN.
    FieldTooLong,
    /// The migration transaction failed.
    MigrationFailed,
    /// Duplicate entry (e.g., two rules for the same capability).
    Duplicate,
}
