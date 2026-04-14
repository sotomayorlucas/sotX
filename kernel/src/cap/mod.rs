//! Capability-based security system.
//!
//! Every kernel object is accessed through capabilities — opaque handles
//! with associated rights. Capabilities can be delegated (with reduced
//! rights) and revoked (invalidating all derivatives via the CDT).
//!
//! CapId embeds a generation counter, so stale (revoked/recycled) caps
//! are rejected automatically.

pub mod table;

use crate::kdebug;
use sotos_common::SysError;
pub use table::{CapId, CapObject, CapabilityTable, Rights};

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static CAP_TABLE: Mutex<CapabilityTable> = Mutex::new(CapabilityTable::new());

/// Global monotonic epoch counter for O(1) capability revocation.
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    // Tier 5 KARL: burn `karl::cap_pool_offset()` slots in the cap
    // pool before the first real allocation, so userspace-visible cap
    // ids drift across reboots. The slots are filled with Null caps
    // and never freed -- they're cheap padding (16 max).
    let burn = (crate::karl::boot_seed() & 0xF) as usize;
    {
        let mut table = CAP_TABLE.lock();
        for _ in 0..burn {
            let _ = table.insert(CapObject::Null, Rights::ALL, None, 0);
        }
    }
    kdebug!(
        "  capability table ready (dynamic pool, generation-checked, KARL burn={})",
        burn
    );
}

/// Insert a new capability and return its ID.
///
/// The capability is stamped with the current global epoch.
pub fn insert(object: CapObject, rights: Rights, parent: Option<CapId>) -> Option<CapId> {
    let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
    CAP_TABLE.lock().insert(object, rights, parent, epoch)
}

/// Look up a capability by ID.
pub fn lookup(id: CapId) -> Option<(CapObject, Rights)> {
    CAP_TABLE.lock().lookup(id)
}

/// Revoke a capability and all its derivatives.
pub fn revoke(id: CapId) {
    CAP_TABLE.lock().revoke(id);
}

/// Validate a capability: check existence, liveness, and required rights.
/// Takes raw u32 from userspace — generation bits are embedded.
pub fn validate(cap_id: u32, required: Rights) -> Result<CapObject, SysError> {
    CAP_TABLE.lock().validate(CapId::new(cap_id), required)
}

/// Grant (delegate) a capability with restricted rights.
/// Validates GRANT right on source, creates a child cap with rights = src & mask.
pub fn grant(source_id: u32, rights_mask: u32) -> Result<CapId, SysError> {
    let mut table = CAP_TABLE.lock();
    let src = CapId::new(source_id);
    let _obj = table.validate(src, Rights::GRANT)?;
    let (obj, src_rights) = table.lookup(src).ok_or(SysError::InvalidCap)?;
    let new_rights = src_rights.restrict(Rights::from_raw(rights_mask));
    let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
    table
        .insert(obj, new_rights, Some(src), epoch)
        .ok_or(SysError::OutOfResources)
}

/// Attenuate: create a derived cap with narrowed rights (child in CDT).
pub fn attenuate(cap_id: u32, rights_mask: u32) -> Result<CapId, SysError> {
    CAP_TABLE
        .lock()
        .attenuate(CapId::new(cap_id), Rights::from_raw(rights_mask))
        .ok_or(SysError::InvalidCap)
}

/// Interpose: create a proxied cap that routes through `proxy_domain`.
pub fn interpose(cap_id: u32, proxy_domain: u32, policy: u8) -> Result<CapId, SysError> {
    CAP_TABLE
        .lock()
        .interpose(CapId::new(cap_id), proxy_domain, policy)
        .ok_or(SysError::InvalidCap)
}

/// Return the current global epoch value.
pub fn current_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// Advance the global epoch and return the new value.
///
/// All capabilities minted before this new epoch can be rejected
/// via `check_epoch(cap, new_epoch)` in O(1).
pub fn advance_epoch() -> u64 {
    GLOBAL_EPOCH.fetch_add(1, Ordering::Release) + 1
}

/// Read-only snapshot of occupied cap-table slots, used by `SYS_CAP_LIST`.
///
/// Invokes `visit(cap_id, kind_discriminant, rights_raw)` for each live entry
/// until `visit` returns false or the table is exhausted. The callback runs
/// under the table spinlock — keep it short and non-blocking. `kind` matches
/// the `CapInfo::KIND_*` constants in `sotos_common`.
pub fn for_each<F: FnMut(u32, u32, u32) -> bool>(mut visit: F) {
    let table = CAP_TABLE.lock();
    for (handle, obj, rights) in table.iter_entries() {
        let kind = kind_of(&obj);
        if !visit(handle.raw(), kind, rights.raw()) {
            break;
        }
    }
}

/// Map a `CapObject` to its `CapInfo::KIND_*` discriminant. Kept centralized
/// so the kernel and `sotos_common::CapInfo` can't drift out of sync.
fn kind_of(obj: &CapObject) -> u32 {
    use sotos_common::CapInfo as K;
    match obj {
        CapObject::Null => K::KIND_NULL,
        CapObject::Memory { .. } => K::KIND_MEMORY,
        CapObject::Endpoint { .. } => K::KIND_ENDPOINT,
        CapObject::Channel { .. } => K::KIND_CHANNEL,
        CapObject::Thread { .. } => K::KIND_THREAD,
        CapObject::Irq { .. } => K::KIND_IRQ,
        CapObject::IoPort { .. } => K::KIND_IOPORT,
        CapObject::Notification { .. } => K::KIND_NOTIFICATION,
        CapObject::Domain { .. } => K::KIND_DOMAIN,
        CapObject::AddrSpace { .. } => K::KIND_ADDR_SPACE,
        CapObject::Interposed { .. } => K::KIND_INTERPOSED,
        CapObject::Vm { .. } => K::KIND_VM,
        CapObject::Msi { .. } => K::KIND_MSI,
    }
}
