//! SOT Domain Model — the fundamental isolation and execution unit.
//!
//! A SOT Domain combines three things:
//!   1. **CSpace** — a per-domain capability slot array (indices into the global cap table).
//!   2. **Address Space** — a page table root (CR3 physical address).
//!   3. **Scheduling Context** — an optional link to a `sched::domain::SchedDomain`.
//!
//! Domains form a tree: a parent can create children with attenuated policies
//! (never more permissive than itself). A domain can enter "deception mode",
//! an irreversible state used by the STYX security model.

use spin::Mutex;

/// Maximum capabilities per domain.
pub const MAX_DOMAIN_CAPS: usize = 256;
/// Maximum child domains.
pub const MAX_CHILD_DOMAINS: usize = 16;
/// Maximum domains in the system.
pub const MAX_DOMAINS: usize = 64;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by domain operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    /// The domain table (or a per-domain slot array) is full.
    Full,
    /// The operation violates the domain's policy.
    PolicyViolation,
    /// The referenced domain does not exist.
    NotFound,
    /// The domain is in a state that disallows this operation.
    InvalidState,
}

// ---------------------------------------------------------------------------
// Domain policy
// ---------------------------------------------------------------------------

/// Domain policy -- restrictions applied at domain creation.
/// A child's policy may be equal to or more restrictive than its parent's
/// but never more permissive.
#[derive(Debug, Clone, Copy)]
pub struct DomainPolicy {
    /// Maximum number of capabilities this domain can hold.
    pub max_capabilities: u32,
    /// Maximum child domains this domain can create.
    pub max_children: u32,
    /// Bitmask of allowed SOType values this domain can create.
    pub allowed_so_types: u32,
    /// Whether network access is permitted.
    pub network_allowed: bool,
    /// Whether filesystem write access is permitted.
    pub fs_write_allowed: bool,
    /// Whether this domain can be migrated to deception mode.
    pub deception_eligible: bool,
    /// Scheduling quantum in ticks.
    pub quantum_ticks: u32,
    /// Scheduling period in ticks.
    pub period_ticks: u32,
}

impl DomainPolicy {
    /// Restrictive defaults: no network, no fs writes, 256 cap slots.
    pub const fn default() -> Self {
        Self {
            max_capabilities: MAX_DOMAIN_CAPS as u32,
            max_children: MAX_CHILD_DOMAINS as u32,
            allowed_so_types: 0,
            network_allowed: false,
            fs_write_allowed: false,
            deception_eligible: false,
            quantum_ticks: 100,
            period_ticks: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain state
// ---------------------------------------------------------------------------

/// Lifecycle state of a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// Created but not yet entered.
    Created,
    /// Actively running.
    Running,
    /// Suspended (budget depleted or explicit).
    Suspended,
    /// Terminated.
    Dead,
}

// ---------------------------------------------------------------------------
// SotDomain
// ---------------------------------------------------------------------------

/// SOT Domain -- the fundamental isolation and execution unit.
/// Combines a capability space, address space, and scheduling context.
pub struct SotDomain {
    /// Unique domain identifier.
    pub id: u32,
    /// Domain policy (set at creation, can be attenuated but never expanded).
    pub policy: DomainPolicy,
    /// Per-domain capability slots (indices into global cap table).
    pub caps: [u32; MAX_DOMAIN_CAPS],
    /// Number of capabilities held.
    pub cap_count: u32,
    /// Address space (page table root physical address / CR3).
    pub cr3: u64,
    /// Scheduling domain index (into the scheduler's domain pool).
    pub sched_domain_idx: Option<u32>,
    /// Parent domain (`None` for root/init domain).
    pub parent: Option<u32>,
    /// Child domain IDs.
    pub children: [Option<u32>; MAX_CHILD_DOMAINS],
    /// Number of children.
    pub child_count: u32,
    /// Whether this domain is in deception mode.
    pub in_deception: bool,
    /// Entry point capability (for domain_enter).
    pub entry_cap: Option<u32>,
    /// Domain state.
    pub state: DomainState,
}

impl SotDomain {
    /// Create a new domain with the given policy and address space.
    pub fn new(id: u32, policy: DomainPolicy, cr3: u64) -> Self {
        Self {
            id,
            policy,
            caps: [0; MAX_DOMAIN_CAPS],
            cap_count: 0,
            cr3,
            sched_domain_idx: None,
            parent: None,
            children: [None; MAX_CHILD_DOMAINS],
            child_count: 0,
            in_deception: false,
            entry_cap: None,
            state: DomainState::Created,
        }
    }

    /// Add a capability index to this domain's CSpace.
    pub fn add_cap(&mut self, cap_id: u32) -> Result<(), DomainError> {
        if self.cap_count >= self.policy.max_capabilities {
            return Err(DomainError::Full);
        }
        // Avoid duplicates.
        for i in 0..self.cap_count as usize {
            if self.caps[i] == cap_id {
                return Ok(());
            }
        }
        self.caps[self.cap_count as usize] = cap_id;
        self.cap_count += 1;
        Ok(())
    }

    /// Remove a capability index from this domain's CSpace.
    pub fn remove_cap(&mut self, cap_id: u32) {
        for i in 0..self.cap_count as usize {
            if self.caps[i] == cap_id {
                // Swap with last to keep the array compact.
                let last = self.cap_count as usize - 1;
                self.caps[i] = self.caps[last];
                self.caps[last] = 0;
                self.cap_count -= 1;
                return;
            }
        }
    }

    /// Check whether this domain holds a given capability index.
    pub fn has_cap(&self, cap_id: u32) -> bool {
        for i in 0..self.cap_count as usize {
            if self.caps[i] == cap_id {
                return true;
            }
        }
        false
    }

    /// Register a child domain ID under this domain.
    pub fn create_child(&mut self, child_id: u32) -> Result<(), DomainError> {
        if self.child_count >= self.policy.max_children {
            return Err(DomainError::PolicyViolation);
        }
        for slot in self.children.iter_mut() {
            if slot.is_none() {
                *slot = Some(child_id);
                self.child_count += 1;
                return Ok(());
            }
        }
        Err(DomainError::Full)
    }

    /// Transition this domain into deception mode (irreversible).
    pub fn enter_deception(&mut self) -> Result<(), DomainError> {
        if !self.policy.deception_eligible {
            return Err(DomainError::PolicyViolation);
        }
        if self.state == DomainState::Dead {
            return Err(DomainError::InvalidState);
        }
        self.in_deception = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Global domain table
// ---------------------------------------------------------------------------

/// Domain table and monotonic ID counter, behind a single lock.
struct DomainTable {
    slots: [Option<SotDomain>; MAX_DOMAINS],
    next_id: u32,
}

static DOMAINS: Mutex<DomainTable> = Mutex::new(DomainTable {
    slots: [const { None }; MAX_DOMAINS],
    next_id: 0,
});

/// Create a new domain, insert it into the global table, and return its ID.
///
/// If `parent` is `Some(pid)`, the child is registered under the parent.
pub fn domain_create(
    policy: DomainPolicy,
    cr3: u64,
    parent: Option<u32>,
) -> Result<u32, DomainError> {
    let mut table = DOMAINS.lock();

    // Find a free slot.
    let slot_idx = table.slots.iter().position(|s| s.is_none()).ok_or(DomainError::Full)?;

    let id = table.next_id;
    table.next_id = id.wrapping_add(1);

    let mut domain = SotDomain::new(id, policy, cr3);

    // If this is a child, register it under the parent.
    if let Some(pid) = parent {
        domain.parent = Some(pid);
        let parent_slot = table
            .slots
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |d| d.id == pid))
            .ok_or(DomainError::NotFound)?;
        parent_slot.as_mut().unwrap().create_child(id)?;
    }

    table.slots[slot_idx] = Some(domain);
    Ok(id)
}

/// Check whether a domain with the given ID exists in the table.
pub fn domain_lookup(id: u32) -> bool {
    let table = DOMAINS.lock();
    table.slots.iter().any(|s| s.as_ref().map_or(false, |d| d.id == id))
}
