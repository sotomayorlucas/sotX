//! Capability-based security system.
//!
//! Every kernel object is accessed through capabilities — opaque handles
//! with associated rights. Capabilities can be delegated (with reduced
//! rights) and revoked (invalidating all derivatives via the CDT).

pub mod table;

pub use table::{CapId, CapObject, CapabilityTable, Rights};
use crate::kprintln;
use sotos_common::SysError;

use spin::Mutex;

static CAP_TABLE: Mutex<CapabilityTable> = Mutex::new(CapabilityTable::new());

pub fn init() {
    // The root capability table is ready — it starts empty.
    // Pool-backed: grows dynamically as capabilities are created.
    kprintln!("  capability table ready (dynamic pool)");
}

/// Insert a new capability and return its ID.
pub fn insert(object: CapObject, rights: Rights, parent: Option<CapId>) -> Option<CapId> {
    CAP_TABLE.lock().insert(object, rights, parent)
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
    table.insert(obj, new_rights, Some(src)).ok_or(SysError::OutOfResources)
}
