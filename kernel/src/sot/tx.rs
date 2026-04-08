//! Transaction manager for the SOT exokernel.
//!
//! Manages transaction lifecycles across three tiers:
//! - Tier 0 (ReadOnly): epoch snapshot, commit/abort are no-ops (~2ns)
//! - Tier 1 (SingleObject): WAL-backed single-object mutations (~300ns)
//! - Tier 2 (MultiObject): 2PC stub (not yet implemented)

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::tx_wal::Wal;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Transaction identifier -- globally unique per-domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxId(pub u64);

/// Transaction state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    /// Transaction in progress.
    Active,
    /// Successfully committed.
    Committed,
    /// Rolled back.
    Aborted,
    /// Tier 2: in 2PC prepare phase.
    Preparing,
}

/// Transaction tier -- determines overhead and guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxTier {
    /// Tier 0: Epoch-based RCU for read-only paths (~2ns overhead).
    /// Just bumps a per-CPU epoch counter. No logging.
    ReadOnly = 0,
    /// Tier 1: Per-object WAL for single-object mutations (~300ns).
    /// Logs old value before write. Rollback = replay WAL backwards.
    SingleObject = 1,
    /// Tier 2: Two-phase commit for multi-object operations (us-ms).
    /// Coordinator + participant protocol.
    MultiObject = 2,
}

/// Errors returned by the transaction manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    /// Active transaction table is full.
    TableFull,
    /// The supplied TxId does not match any active transaction.
    NotFound,
    /// The transaction is not in a state that allows this operation.
    InvalidState,
    /// Tier 2 (multi-object 2PC) is not yet implemented.
    NotImplemented,
    /// WAL error during Tier 1 operation.
    WalFull,
}

// ---------------------------------------------------------------------------
// Internal slot
// ---------------------------------------------------------------------------

/// Per-transaction bookkeeping stored in the active table.
#[derive(Clone, Copy)]
struct TxSlot {
    id: u64,
    domain_id: u32,
    tier: TxTier,
    state: TxState,
    /// Tier 0 only: epoch snapshot captured at begin.
    epoch_snapshot: u64,
}

// ---------------------------------------------------------------------------
// Transaction manager
// ---------------------------------------------------------------------------

const MAX_ACTIVE_TX: usize = 256;

/// Global monotonic epoch counter (Tier 0 reads snapshot this).
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Monotonic transaction id counter (offset added at handout time).
static NEXT_TX_ID: AtomicU64 = AtomicU64::new(0);

/// Tier 5 KARL: returns the next tx id using the per-boot offset
/// from `karl::tx_id_offset`. This makes IDs drift across reboots
/// so attackers can't predict them by counting.
fn alloc_tx_id() -> u64 {
    let n = NEXT_TX_ID.fetch_add(1, Ordering::Relaxed);
    crate::karl::tx_id_offset().wrapping_add(n)
}

pub struct TxManager {
    slots: [Option<TxSlot>; MAX_ACTIVE_TX],
    wal: Wal,
}

impl TxManager {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_ACTIVE_TX],
            wal: Wal::new(),
        }
    }

    /// Begin a new transaction in the given domain at the requested tier.
    pub fn tx_begin(&mut self, domain_id: u32, tier: TxTier) -> Result<TxId, TxError> {
        // Find a free slot.
        let free = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(TxError::TableFull)?;

        let id = alloc_tx_id();
        let epoch_snapshot = if matches!(tier, TxTier::ReadOnly) {
            GLOBAL_EPOCH.load(Ordering::Acquire)
        } else {
            0
        };

        self.slots[free] = Some(TxSlot {
            id,
            domain_id,
            tier,
            state: TxState::Active,
            epoch_snapshot,
        });

        Ok(TxId(id))
    }

    /// Tier 2 (MultiObject) two-phase commit: PREPARE phase.
    ///
    /// Transitions an `Active` MultiObject transaction into the
    /// `Preparing` state. After this point, the transaction is
    /// "decided once committed" -- the only valid follow-ups are
    /// `tx_commit` (which moves it to `Committed`) or `tx_abort`
    /// (rollback). ReadOnly / SingleObject transactions reject
    /// `tx_prepare` -- they go straight from Active to Committed
    /// via `tx_commit`.
    pub fn tx_prepare(&mut self, tx_id: TxId) -> Result<(), TxError> {
        let idx = self.find_index(tx_id.0).ok_or(TxError::NotFound)?;
        let slot = self.slots[idx].as_mut().unwrap();

        if slot.state != TxState::Active {
            return Err(TxError::InvalidState);
        }
        if !matches!(slot.tier, TxTier::MultiObject) {
            return Err(TxError::InvalidState);
        }
        slot.state = TxState::Preparing;
        Ok(())
    }

    /// Commit a transaction.
    pub fn tx_commit(&mut self, tx_id: TxId) -> Result<(), TxError> {
        let idx = self.find_index(tx_id.0).ok_or(TxError::NotFound)?;
        let slot = self.slots[idx].as_ref().unwrap();

        match slot.tier {
            TxTier::ReadOnly => {
                if slot.state != TxState::Active {
                    return Err(TxError::InvalidState);
                }
            }
            TxTier::SingleObject => {
                if slot.state != TxState::Active {
                    return Err(TxError::InvalidState);
                }
                self.wal.commit(tx_id.0);
            }
            TxTier::MultiObject => {
                // Tier 2 requires a PREPARE before COMMIT.
                if slot.state != TxState::Preparing {
                    return Err(TxError::InvalidState);
                }
            }
        }

        self.slots[idx] = None;
        Ok(())
    }

    /// Abort (roll back) a transaction.
    pub fn tx_abort(&mut self, tx_id: TxId) -> Result<(), TxError> {
        let idx = self.find_index(tx_id.0).ok_or(TxError::NotFound)?;
        let slot = self.slots[idx].as_ref().unwrap();

        // Tier 2 abort is allowed from Active OR Preparing (so a
        // participant that fails after PREPARE can still rollback).
        match slot.state {
            TxState::Active | TxState::Preparing => {}
            _ => return Err(TxError::InvalidState),
        }

        match slot.tier {
            TxTier::ReadOnly => {} // no-op
            TxTier::SingleObject => self.wal.rollback(tx_id.0),
            TxTier::MultiObject => {} // 2PC abort: just drop the slot
        }

        self.slots[idx] = None;
        Ok(())
    }

    /// Query the current state of a transaction.
    /// Returns `None` if the id is not in the active table (already completed).
    pub fn tx_state(&self, tx_id: TxId) -> Option<TxState> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|s| s.id == tx_id.0)
            .map(|s| s.state)
    }

    /// Bump the global epoch counter (called periodically or on quiescent state).
    pub fn advance_epoch() {
        GLOBAL_EPOCH.fetch_add(1, Ordering::Release);
    }

    /// Read the current global epoch.
    pub fn current_epoch() -> u64 {
        GLOBAL_EPOCH.load(Ordering::Acquire)
    }

    /// Provide mutable access to the WAL (for Tier 1 callers that need to
    /// append entries before commit).
    pub fn wal_mut(&mut self) -> &mut Wal {
        &mut self.wal
    }

    /// Run WAL garbage collection to reclaim committed entries.
    pub fn gc(&mut self) {
        self.wal.gc();
    }

    // -- helpers --

    fn find_index(&self, id: u64) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| matches!(s, Some(slot) if slot.id == id))
    }
}

/// Global transaction manager instance, behind a spinlock.
pub static TX_MANAGER: Mutex<TxManager> = Mutex::new(TxManager::new());
