//! sot-lkl: Domain wrapper for Linux Kernel Library (LKL) fallback.
//!
//! # Purpose
//!
//! Some Linux syscalls have no clean SOT equivalent and are too complex to
//! reimplement (AIO, io_uring, xattrs, NUMA policy, etc.). For these, we
//! forward the syscall to an LKL instance running inside an isolated SOT
//! domain. LKL provides a full Linux kernel in library form, handling the
//! long tail of syscalls that would otherwise return -ENOSYS.
//!
//! # Architecture
//!
//! ```text
//! Linux binary
//!    |  unsupported syscall
//!    v
//! Process Server
//!    |  translate() -> ForwardToLkl
//!    v
//! LklDomain (this crate)
//!    |  IPC message to LKL domain
//!    v
//! LKL domain (isolated process)
//!    |  lkl_syscall(nr, args)
//!    v
//! Linux kernel (libOS)
//!    |  result
//!    v
//! Deception filter (optional)
//!    |  modified result
//!    v
//! Back to Linux binary
//! ```
//!
//! # Legal Isolation
//!
//! LKL is derived from the Linux kernel and is GPL-licensed. SOT isolates
//! LKL in a separate domain communicating only via IPC messages (capability-
//! protected endpoints). No GPL code is linked into the SOT kernel or process
//! server. The IPC boundary provides both legal separation (no derived work)
//! and security isolation (LKL bugs cannot corrupt the kernel).
//!
//! # Deception Layer
//!
//! LKL responses can be intercepted and modified before returning to the
//! calling domain. This is used for:
//! - Masking LKL-specific artifacts (e.g., /proc paths that leak LKL internals)
//! - Injecting fake hardware info for DRM/anti-cheat compatibility
//! - Filtering sensitive kernel data from untrusted domains

#![no_std]

/// IPC command codes for the LKL domain protocol.
///
/// The process server sends these as the IPC message tag to the LKL endpoint.
pub mod cmd {
    /// Forward a Linux syscall: tag=CMD_SYSCALL, regs=[nr, a0..a5, 0].
    pub const CMD_SYSCALL: u64 = 0x4C4B_4C00;
    /// Query LKL status: tag=CMD_STATUS, regs unused.
    pub const CMD_STATUS: u64 = 0x4C4B_4C01;
    /// Shut down the LKL instance gracefully.
    pub const CMD_SHUTDOWN: u64 = 0x4C4B_4C02;
}

/// LKL domain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LklState {
    /// LKL domain has not been started yet.
    NotStarted,
    /// LKL is initializing (booting the Linux kernel).
    Booting,
    /// LKL is ready to accept syscall forwards.
    Ready,
    /// LKL has encountered a fatal error.
    Failed,
    /// LKL is shutting down.
    ShuttingDown,
}

/// Result of forwarding a syscall to LKL.
#[derive(Debug, Clone, Copy)]
pub struct LklResult {
    /// Linux return value (negative errno on error).
    pub ret: i64,
    /// Whether the deception layer modified this result.
    pub deception_applied: bool,
}

/// Deception filter applied to LKL responses.
///
/// Each rule specifies a syscall number to intercept and a transformation
/// to apply to the result before returning it to the caller.
#[derive(Debug, Clone, Copy)]
pub struct DeceptionRule {
    /// Linux syscall number to intercept (0 = match all).
    pub syscall_nr: u64,
    /// Action to take.
    pub action: DeceptionAction,
}

/// What to do with an LKL response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeceptionAction {
    /// Pass through unmodified.
    PassThrough,
    /// Replace the return value with a fixed value.
    ReplaceReturn(i64),
    /// Return -ENOSYS (pretend the syscall doesn't exist).
    BlockWithEnosys,
    /// Suppress: return success (0) regardless of actual result.
    SuppressToZero,
}

/// Maximum number of deception rules per domain.
pub const MAX_DECEPTION_RULES: usize = 32;

/// Handle to an LKL domain, used by the process server to forward syscalls.
///
/// This struct does not contain the actual LKL instance -- that lives in a
/// separate isolated SOT domain. This is the client-side handle that sends
/// IPC messages to that domain.
#[derive(Debug)]
pub struct LklDomain {
    /// Current state of the LKL domain.
    state: LklState,
    /// SOT endpoint capability for sending IPC to the LKL domain.
    /// Zero means not connected.
    endpoint_cap: u64,
    /// Deception rules to apply to LKL responses.
    deception_rules: [Option<DeceptionRule>; MAX_DECEPTION_RULES],
    /// Number of active deception rules.
    deception_count: usize,
    /// Total syscalls forwarded (for diagnostics).
    forward_count: u64,
    /// Total deception modifications applied.
    deception_hit_count: u64,
}

impl LklDomain {
    /// Create a new LKL domain handle (not yet connected).
    pub const fn new() -> Self {
        Self {
            state: LklState::NotStarted,
            endpoint_cap: 0,
            deception_rules: [None; MAX_DECEPTION_RULES],
            deception_count: 0,
            forward_count: 0,
            deception_hit_count: 0,
        }
    }

    /// Connect to an LKL domain via its IPC endpoint capability.
    ///
    /// The caller must have already spawned the LKL domain and obtained
    /// its endpoint through the service registry.
    pub fn connect(&mut self, endpoint_cap: u64) {
        self.endpoint_cap = endpoint_cap;
        self.state = LklState::Ready;
    }

    /// Current state of the LKL domain.
    pub fn state(&self) -> LklState {
        self.state
    }

    /// Forward a Linux syscall to the LKL domain.
    ///
    /// Returns `None` if the LKL domain is not ready. Otherwise returns
    /// the (possibly deception-filtered) result.
    ///
    /// # IPC Protocol
    ///
    /// The message sent to LKL:
    /// - tag: `CMD_SYSCALL`
    /// - regs[0]: syscall number
    /// - regs[1..7]: arguments a0..a5
    ///
    /// The reply:
    /// - tag: 0 on success, nonzero on LKL internal error
    /// - regs[0]: Linux return value
    pub fn forward_syscall(&mut self, nr: u64, _args: &[u64; 6]) -> Option<LklResult> {
        if self.state != LklState::Ready {
            return None;
        }

        // In a real implementation, this would do:
        //   let msg = IpcMessage { tag: cmd::CMD_SYSCALL, regs: [nr, args[0..5], 0, 0] };
        //   let reply = sys::call(self.endpoint_cap, msg);
        //   let ret = reply.regs[0] as i64;
        //
        // For now, we return -ENOSYS as a placeholder since we cannot
        // perform actual IPC from a standalone no_std library crate.
        let raw_ret: i64 = -38; // -ENOSYS

        self.forward_count += 1;

        // Apply deception filter
        let result = self.apply_deception(nr, raw_ret);

        Some(result)
    }

    /// Add a deception rule. Returns false if the rule table is full.
    pub fn add_deception_rule(&mut self, rule: DeceptionRule) -> bool {
        if self.deception_count >= MAX_DECEPTION_RULES {
            return false;
        }
        self.deception_rules[self.deception_count] = Some(rule);
        self.deception_count += 1;
        true
    }

    /// Clear all deception rules.
    pub fn clear_deception_rules(&mut self) {
        self.deception_rules = [None; MAX_DECEPTION_RULES];
        self.deception_count = 0;
    }

    /// Number of syscalls forwarded so far.
    pub fn forward_count(&self) -> u64 {
        self.forward_count
    }

    /// Number of deception modifications applied.
    pub fn deception_hit_count(&self) -> u64 {
        self.deception_hit_count
    }

    /// Apply deception rules to an LKL response.
    fn apply_deception(&mut self, nr: u64, raw_ret: i64) -> LklResult {
        for i in 0..self.deception_count {
            if let Some(rule) = &self.deception_rules[i] {
                if rule.syscall_nr == 0 || rule.syscall_nr == nr {
                    let ret = match rule.action {
                        DeceptionAction::PassThrough => raw_ret,
                        DeceptionAction::ReplaceReturn(v) => v,
                        DeceptionAction::BlockWithEnosys => -38, // -ENOSYS
                        DeceptionAction::SuppressToZero => 0,
                    };
                    if ret != raw_ret {
                        self.deception_hit_count += 1;
                    }
                    return LklResult {
                        ret,
                        deception_applied: ret != raw_ret,
                    };
                }
            }
        }

        LklResult {
            ret: raw_ret,
            deception_applied: false,
        }
    }
}
