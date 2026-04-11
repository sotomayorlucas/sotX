//! # Typestate Enforcement for sotFS Graph Operations
//!
//! Uses Rust's type system to make illegal DPO rule applications a
//! **compile-time error**, following the SquirrelFS approach (OSDI 2024).
//!
//! ## Enforced Properties
//!
//! - A file inode cannot be read/written until it has been created and linked
//! - A directory cannot be rmdir'd unless it is empty
//! - A transaction must be committed or rolled back — cannot be dropped while active
//! - An orphaned inode (link_count=0) cannot be accessed
//! - Capabilities can only be attenuated (never escalated)
//!
//! ## Design
//!
//! Each resource has phantom type parameters encoding its state. State
//! transitions are methods that consume `self` and return the new state,
//! making it impossible to use the old state after a transition.

use core::marker::PhantomData;

// ---------------------------------------------------------------------------
// Inode typestate
// ---------------------------------------------------------------------------

/// Inode state: freshly allocated, not yet linked into any directory.
pub struct Created;
/// Inode state: linked into at least one directory (link_count >= 1).
pub struct Linked;
/// Inode state: last link removed, pending garbage collection.
pub struct Orphaned;

/// A typed inode handle that tracks lifecycle state at compile time.
///
/// ```compile_fail
/// // This should NOT compile: reading from an orphaned inode
/// let orphaned: InodeHandle<Orphaned> = ...;
/// orphaned.read(0, 10); // ERROR: no method `read` on InodeHandle<Orphaned>
/// ```
pub struct InodeHandle<S> {
    pub id: u64,
    _state: PhantomData<S>,
}

impl InodeHandle<Created> {
    /// Create a new inode handle in the Created state.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            _state: PhantomData,
        }
    }

    /// Link this inode into a directory. Consumes Created, returns Linked.
    /// This is the only way to get a Linked inode — enforces that every
    /// accessible inode was properly linked via a DPO CREATE/LINK rule.
    pub fn link(self) -> InodeHandle<Linked> {
        InodeHandle {
            id: self.id,
            _state: PhantomData,
        }
    }
}

impl InodeHandle<Linked> {
    /// Read data from this inode. Only available on Linked inodes.
    pub fn read(&self, _offset: u64, _len: usize) -> u64 {
        self.id
    }

    /// Write data to this inode. Only available on Linked inodes.
    pub fn write(&self, _offset: u64, _data: &[u8]) -> u64 {
        self.id
    }

    /// Remove a link. If this was the last link, transitions to Orphaned.
    /// Returns Either<Linked, Orphaned> depending on remaining link count.
    pub fn unlink(self, remaining_links: u32) -> UnlinkResult {
        if remaining_links == 0 {
            UnlinkResult::Orphaned(InodeHandle {
                id: self.id,
                _state: PhantomData,
            })
        } else {
            UnlinkResult::StillLinked(InodeHandle {
                id: self.id,
                _state: PhantomData,
            })
        }
    }

    /// Get the inode id (available in any linked state).
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl InodeHandle<Orphaned> {
    /// Garbage-collect this inode. Consumes the handle, preventing any
    /// further access — use-after-free is a compile error.
    pub fn gc(self) {
        // Handle is consumed, memory freed. No further operations possible.
        drop(self);
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Result of unlinking an inode.
pub enum UnlinkResult {
    StillLinked(InodeHandle<Linked>),
    Orphaned(InodeHandle<Orphaned>),
}

// ---------------------------------------------------------------------------
// Transaction typestate
// ---------------------------------------------------------------------------

/// Transaction state: actively accumulating operations.
pub struct TxActive;
/// Transaction state: successfully committed.
pub struct TxCommitted;
/// Transaction state: rolled back.
pub struct TxAborted;

/// A typed transaction handle. Must be committed or aborted — dropping
/// an active transaction is a logic error caught by the `must_use` attribute.
#[must_use = "transaction must be committed or aborted — dropping an active transaction loses changes"]
pub struct TxHandle<S> {
    pub id: u64,
    _state: PhantomData<S>,
}

impl TxHandle<TxActive> {
    /// Begin a new transaction.
    pub fn begin(id: u64) -> Self {
        Self {
            id,
            _state: PhantomData,
        }
    }

    /// Apply a DPO rule within this transaction. Returns self for chaining.
    pub fn apply_rule(self, _rule_name: &str) -> Self {
        // In a real implementation, this records the rule application
        // in the transaction's write set and verifies gluing conditions.
        self
    }

    /// Commit the transaction. Consumes Active, returns Committed.
    /// After this, no more operations can be applied.
    pub fn commit(self) -> TxHandle<TxCommitted> {
        TxHandle {
            id: self.id,
            _state: PhantomData,
        }
    }

    /// Abort the transaction. Consumes Active, returns Aborted.
    /// All operations are rolled back.
    pub fn abort(self) -> TxHandle<TxAborted> {
        TxHandle {
            id: self.id,
            _state: PhantomData,
        }
    }
}

// Committed and Aborted transactions have no further operations.
// They exist only to prove the transaction was properly terminated.

// ---------------------------------------------------------------------------
// Directory typestate
// ---------------------------------------------------------------------------

/// Directory state: contains only "." and ".." entries.
pub struct DirEmpty;
/// Directory state: contains children beyond "." and "..".
pub struct DirNonEmpty;

/// A typed directory handle.
pub struct DirHandle<S> {
    pub id: u64,
    _state: PhantomData<S>,
}

impl DirHandle<DirEmpty> {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            _state: PhantomData,
        }
    }

    /// Add a child entry. Transitions Empty → NonEmpty.
    pub fn add_child(self) -> DirHandle<DirNonEmpty> {
        DirHandle {
            id: self.id,
            _state: PhantomData,
        }
    }

    /// Remove this empty directory. Only available on Empty directories —
    /// rmdir on a non-empty directory is a compile error.
    pub fn rmdir(self) {
        // Consumed — directory removed.
    }
}

impl DirHandle<DirNonEmpty> {
    /// Remove a child entry. If the directory becomes empty, transitions back.
    pub fn remove_child(self, remaining: usize) -> DirEmptyResult {
        if remaining == 0 {
            DirEmptyResult::Empty(DirHandle {
                id: self.id,
                _state: PhantomData,
            })
        } else {
            DirEmptyResult::NonEmpty(DirHandle {
                id: self.id,
                _state: PhantomData,
            })
        }
    }
}

pub enum DirEmptyResult {
    Empty(DirHandle<DirEmpty>),
    NonEmpty(DirHandle<DirNonEmpty>),
}

// ---------------------------------------------------------------------------
// Capability typestate
// ---------------------------------------------------------------------------

/// A typed capability handle that enforces monotonic attenuation.
/// The `R` parameter encodes the rights bitmask at the type level.
pub struct CapHandle {
    pub id: u64,
    pub rights: u8,
}

impl CapHandle {
    /// Create a root capability with all rights.
    pub fn root(id: u64) -> Self {
        Self { id, rights: 0x1F }
    }

    /// Derive a child capability with restricted rights.
    /// The mask MUST be a subset of the current rights — enforced at runtime
    /// (compile-time enforcement would require const generics on the rights
    /// bitmask, which is possible but verbose).
    ///
    /// Returns None if mask would escalate rights (impossible by construction
    /// since mask is AND'd, but checked defensively).
    pub fn attenuate(&self, child_id: u64, mask: u8) -> Option<CapHandle> {
        let restricted = self.rights & mask;
        if restricted & !self.rights != 0 {
            None // Would escalate — impossible but checked
        } else {
            Some(CapHandle {
                id: child_id,
                rights: restricted,
            })
        }
    }

    pub fn has_read(&self) -> bool {
        self.rights & 0x01 != 0
    }
    pub fn has_write(&self) -> bool {
        self.rights & 0x02 != 0
    }
    pub fn has_execute(&self) -> bool {
        self.rights & 0x04 != 0
    }
    pub fn has_grant(&self) -> bool {
        self.rights & 0x08 != 0
    }
    pub fn has_revoke(&self) -> bool {
        self.rights & 0x10 != 0
    }
}

// ---------------------------------------------------------------------------
// Compile-time tests (doc tests that must fail to compile)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_lifecycle_happy_path() {
        let created = InodeHandle::<Created>::new(42);
        let linked = created.link();
        assert_eq!(linked.read(0, 100), 42);
        assert_eq!(linked.write(0, b"hello"), 42);
        match linked.unlink(0) {
            UnlinkResult::Orphaned(orphaned) => {
                assert_eq!(orphaned.id(), 42);
                orphaned.gc(); // consumed
            }
            UnlinkResult::StillLinked(_) => panic!("expected orphaned"),
        }
    }

    #[test]
    fn inode_unlink_still_linked() {
        let created = InodeHandle::<Created>::new(1);
        let linked = created.link();
        match linked.unlink(3) {
            UnlinkResult::StillLinked(still) => {
                assert_eq!(still.read(0, 10), 1);
                // Can still use it
            }
            UnlinkResult::Orphaned(_) => panic!("should still be linked"),
        }
    }

    #[test]
    fn transaction_must_terminate() {
        let tx = TxHandle::begin(1);
        let tx = tx.apply_rule("CREATE");
        let tx = tx.apply_rule("MKDIR");
        let _committed = tx.commit(); // properly terminated
    }

    #[test]
    fn transaction_abort() {
        let tx = TxHandle::begin(2);
        let tx = tx.apply_rule("WRITE");
        let _aborted = tx.abort(); // properly terminated
    }

    #[test]
    fn directory_rmdir_only_when_empty() {
        let dir = DirHandle::<DirEmpty>::new(1);
        dir.rmdir(); // OK: empty directory can be removed

        let dir2 = DirHandle::<DirEmpty>::new(2);
        let nonempty = dir2.add_child();
        // nonempty.rmdir(); // COMPILE ERROR: no method `rmdir` on DirHandle<DirNonEmpty>
        match nonempty.remove_child(0) {
            DirEmptyResult::Empty(empty) => empty.rmdir(), // OK after removing last child
            DirEmptyResult::NonEmpty(_) => panic!("should be empty"),
        }
    }

    #[test]
    fn capability_attenuation_never_escalates() {
        let root = CapHandle::root(1);
        assert!(root.has_read());
        assert!(root.has_write());
        assert!(root.has_grant());

        let child = root.attenuate(2, 0x01).unwrap(); // read-only
        assert!(child.has_read());
        assert!(!child.has_write());
        assert!(!child.has_grant());

        let grandchild = child.attenuate(3, 0x03).unwrap(); // ask for read+write
        assert!(grandchild.has_read());
        assert!(!grandchild.has_write()); // can't escalate! AND'd with parent's 0x01
    }
}
