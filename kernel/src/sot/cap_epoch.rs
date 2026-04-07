//! Epoch-based capability revocation and interposition policies.
//!
//! Capabilities carry an epoch stamp set at creation time. Advancing the
//! global epoch invalidates all capabilities minted before the new epoch
//! in O(1) — callers simply compare `cap.epoch < current_epoch`.
//!
//! Interposition policies control how proxied capabilities route IPC
//! through an intermediary domain before reaching the real kernel object.

/// Interposition policies for capability proxying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InterpositionPolicy {
    /// Forward to real SO, log only (~50 cycle overhead).
    Passthrough = 0,
    /// Full IPC to proxy domain (~500-1000 cycles).
    Inspect = 1,
    /// Always route to alternative SO.
    Redirect = 2,
    /// Proxy generates synthetic response.
    Fabricate = 3,
}

impl InterpositionPolicy {
    /// Convert from raw u8 value. Returns `None` for unknown policies.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Passthrough),
            1 => Some(Self::Inspect),
            2 => Some(Self::Redirect),
            3 => Some(Self::Fabricate),
            _ => None,
        }
    }
}

/// Epoch-based revocation context.
///
/// Tracks the current global epoch and provides helpers for checking
/// whether a capability is still valid under a given epoch threshold.
pub struct EpochContext {
    /// The minimum epoch a capability must have to be considered valid.
    pub min_epoch: u64,
}

impl EpochContext {
    /// Create a new epoch context with the given minimum epoch.
    pub const fn new(min_epoch: u64) -> Self {
        Self { min_epoch }
    }

    /// Check whether a capability's epoch satisfies this context.
    pub const fn is_valid(&self, cap_epoch: u64) -> bool {
        cap_epoch >= self.min_epoch
    }
}
