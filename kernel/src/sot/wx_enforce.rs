//! Write XOR Execute (W^X) enforcement for SOT domains.
//!
//! Inspired by OpenBSD's strict W^X policy: no memory page may be both
//! writable and executable simultaneously. This module provides per-domain
//! policy tracking with three levels -- Strict, Relaxed (for JIT), and
//! Disabled (legacy compatibility).
//!
//! Complements the existing per-address-space W^X bitmap in `mm::paging`
//! by adding structured policy and per-page relaxation tracking at the
//! domain level.

/// Linux mmap protection flags (matching sotos-common::linux_abi).
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

const PAGE_SHIFT: u64 = 12;
const BITMAP_WORDS: usize = 16;
const BITS_PER_WORD: usize = 64;
/// Maximum pages tracked for relaxation (16 * 64 = 1024).
const MAX_RELAXED_PAGES: usize = BITMAP_WORDS * BITS_PER_WORD;

/// Check if a protection request violates W^X (write + execute simultaneously).
pub const fn violates_wx(prot: u64) -> bool {
    let write = prot & PROT_WRITE != 0;
    let exec = prot & PROT_EXEC != 0;
    write && exec
}

/// W^X policy levels per domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WxPolicy {
    /// Strict: W^X always enforced, no exceptions.
    Strict,
    /// Relaxed: W^X enforced but individual pages can be opted out (for JIT).
    Relaxed,
    /// Disabled: No W^X enforcement (legacy compatibility).
    Disabled,
}

/// W^X violation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WxViolation {
    /// Protection flags include both WRITE and EXEC.
    WriteExecConflict { addr: u64, prot: u64 },
    /// Tried to relax a page under Strict policy.
    StrictPolicyDenied { page_addr: u64 },
    /// Relaxation bitmap is full.
    RelaxationLimitReached,
}

/// Per-domain W^X state tracking.
///
/// Each domain (process/address space) gets its own `WxEnforcer` that
/// tracks the W^X policy and which pages have been granted relaxation
/// (only under `Relaxed` policy).
pub struct WxEnforcer {
    policy: WxPolicy,
    /// Bitmap of pages with W^X relaxation (only meaningful for Relaxed policy).
    /// Bit N set means the page at index N in the tracked range is relaxed.
    relaxed_pages: [u64; BITMAP_WORDS],
    /// Number of currently relaxed pages.
    relaxed_count: u32,
    /// Base address for the relaxation bitmap (set on first relaxation).
    relaxed_base: u64,
}

impl WxEnforcer {
    /// Create a new enforcer with the given policy.
    pub const fn new(policy: WxPolicy) -> Self {
        Self {
            policy,
            relaxed_pages: [0u64; BITMAP_WORDS],
            relaxed_count: 0,
            relaxed_base: 0,
        }
    }

    /// Create a strict enforcer (default for new domains).
    pub const fn strict() -> Self {
        Self::new(WxPolicy::Strict)
    }

    /// Get the current policy.
    pub const fn policy(&self) -> WxPolicy {
        self.policy
    }

    /// Set the policy level.
    pub fn set_policy(&mut self, policy: WxPolicy) {
        self.policy = policy;
        // Clear relaxation state when switching away from Relaxed
        if policy != WxPolicy::Relaxed {
            self.relaxed_pages = [0u64; BITMAP_WORDS];
            self.relaxed_count = 0;
        }
    }

    /// Check whether an mmap request is allowed under the current W^X policy.
    pub fn check_mmap(&self, addr: u64, _len: u64, prot: u64) -> Result<(), WxViolation> {
        match self.policy {
            WxPolicy::Disabled => Ok(()),
            WxPolicy::Strict => {
                if violates_wx(prot) {
                    Err(WxViolation::WriteExecConflict { addr, prot })
                } else {
                    Ok(())
                }
            }
            WxPolicy::Relaxed => {
                if violates_wx(prot) && !self.is_page_relaxed(addr) {
                    Err(WxViolation::WriteExecConflict { addr, prot })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Check whether an mprotect request is allowed under the current W^X policy.
    pub fn check_mprotect(&self, addr: u64, _len: u64, prot: u64) -> Result<(), WxViolation> {
        // Same logic as mmap -- mprotect is the more common W^X bypass vector
        self.check_mmap(addr, _len, prot)
    }

    /// Grant W^X relaxation to a specific page (Relaxed policy only).
    ///
    /// Under Strict policy this always fails. Under Disabled policy it is a no-op.
    pub fn relax_page(&mut self, page_addr: u64) -> Result<(), WxViolation> {
        match self.policy {
            WxPolicy::Strict => Err(WxViolation::StrictPolicyDenied { page_addr }),
            WxPolicy::Disabled => Ok(()),
            WxPolicy::Relaxed => {
                let aligned = page_addr & !(0xFFF);

                // Set base on first relaxation
                if self.relaxed_count == 0 {
                    self.relaxed_base = aligned;
                }

                let offset_pages =
                    ((aligned.wrapping_sub(self.relaxed_base)) >> PAGE_SHIFT) as usize;
                if offset_pages >= MAX_RELAXED_PAGES {
                    return Err(WxViolation::RelaxationLimitReached);
                }

                let word = offset_pages / BITS_PER_WORD;
                let bit = offset_pages % BITS_PER_WORD;

                if self.relaxed_pages[word] & (1u64 << bit) == 0 {
                    self.relaxed_pages[word] |= 1u64 << bit;
                    self.relaxed_count += 1;
                }

                Ok(())
            }
        }
    }

    /// Revoke W^X relaxation for a specific page.
    pub fn unrelax_page(&mut self, page_addr: u64) {
        if self.policy != WxPolicy::Relaxed || self.relaxed_count == 0 {
            return;
        }
        let aligned = page_addr & !(0xFFF);
        let offset_pages = ((aligned.wrapping_sub(self.relaxed_base)) >> PAGE_SHIFT) as usize;
        if offset_pages >= MAX_RELAXED_PAGES {
            return;
        }
        let word = offset_pages / BITS_PER_WORD;
        let bit = offset_pages % BITS_PER_WORD;
        if self.relaxed_pages[word] & (1u64 << bit) != 0 {
            self.relaxed_pages[word] &= !(1u64 << bit);
            self.relaxed_count = self.relaxed_count.saturating_sub(1);
        }
    }

    /// Check if a specific page has W^X relaxation.
    fn is_page_relaxed(&self, addr: u64) -> bool {
        if self.relaxed_count == 0 {
            return false;
        }
        let aligned = addr & !(0xFFF);
        let offset_pages = ((aligned.wrapping_sub(self.relaxed_base)) >> PAGE_SHIFT) as usize;
        if offset_pages >= MAX_RELAXED_PAGES {
            return false;
        }
        let word = offset_pages / BITS_PER_WORD;
        let bit = offset_pages % BITS_PER_WORD;
        self.relaxed_pages[word] & (1u64 << bit) != 0
    }
}
