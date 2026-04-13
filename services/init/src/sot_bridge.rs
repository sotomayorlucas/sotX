//! SOT Bridge -- connects LUCAS process server to SOT exokernel primitives.
//!
//! This module wraps SOT syscalls (300-310) in high-level functions
//! that the existing child_handler can call instead of raw sotX primitives.
//!
//! Each function:
//! 1. Calls the appropriate SOT syscall(s) via `sotos_common::sys::*`
//! 2. Maps kernel error codes to Linux errno
//! 3. Optionally records provenance via `sot_provenance_record`

use crate::sot_types::*;
use sotos_common::linux_abi;
use sotos_common::sys;

/// Map a kernel SysError code to a negated Linux errno.
fn map_kernel_err(err: i64) -> i64 {
    match err {
        -1 => -(linux_abi::EBADF),  // InvalidCap
        -2 => -(linux_abi::EACCES), // NoRights
        -3 => -(linux_abi::ENOMEM), // OutOfResources
        -4 => -(linux_abi::EINVAL), // InvalidArg
        -5 => -(linux_abi::EAGAIN), // WouldBlock
        -6 => -(linux_abi::ESRCH),  // NotFound
        -7 => -(linux_abi::EAGAIN), // Timeout
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Domain lifecycle
// ---------------------------------------------------------------------------

/// Create a new SOT domain for a child process.
///
/// Wraps `sot_domain_create(305)` to create an isolation domain,
/// then copies the parent's capabilities into the child domain via
/// `so_grant(302)`.
pub fn sot_fork(parent_cr3: u64, parent_caps: &[u64]) -> Result<SotChildDomain, i64> {
    let policy =
        DOMAIN_POLICY_NET | DOMAIN_POLICY_FS_WRITE | DOMAIN_POLICY_FORK | DOMAIN_POLICY_EXEC;

    let domain_id = sys::sot_domain_create(policy, parent_cr3).map_err(map_kernel_err)? as u32;

    let mut caps = [0u64; MAX_DOMAIN_CAPS];
    let mut cap_count = 0u32;
    for &cap in parent_caps {
        if cap == 0 || cap_count as usize >= MAX_DOMAIN_CAPS {
            break;
        }
        if sys::so_grant(cap, domain_id as u64, 0xFFFF_FFFF).is_ok() {
            caps[cap_count as usize] = cap;
            cap_count += 1;
        }
    }

    sot_provenance_record(domain_id, OP_FORK, 0);

    Ok(SotChildDomain {
        domain_id,
        caps,
        cap_count,
        cr3: parent_cr3,
    })
}

// ---------------------------------------------------------------------------
// Exec with transactional semantics
// ---------------------------------------------------------------------------

/// Execute a binary in a domain with transactional semantics.
///
/// Wraps: `tx_begin(308)` -> load binary -> `tx_commit(309)`.
/// On failure, calls `tx_abort(310)` to roll back domain state.
pub fn sot_exec(
    domain_id: u32,
    binary_path: &[u8],
    _argv: &[&[u8]],
    _policy: &ExecPolicy,
) -> Result<(), i64> {
    let tx_id = sys::tx_begin(domain_id as u64).map_err(map_kernel_err)?;

    // Create a file SO for the binary, then invoke read to load it.
    match sys::so_create(SO_TYPE_FILE, 0) {
        Ok(cap) => {
            let path_ptr = binary_path.as_ptr() as u64;
            let path_len = binary_path.len() as u64;
            if let Err(e) = sys::so_invoke(cap, SO_METHOD_READ, path_ptr, path_len) {
                let _ = sys::tx_abort(tx_id);
                let _ = sys::so_revoke(cap);
                return Err(map_kernel_err(e));
            }
        }
        Err(e) => {
            let _ = sys::tx_abort(tx_id);
            return Err(map_kernel_err(e));
        }
    }

    sot_provenance_record(domain_id, OP_EXEC, 0);

    sys::tx_commit(tx_id).map_err(|e| {
        let _ = sys::tx_abort(tx_id);
        map_kernel_err(e)
    })
}

// ---------------------------------------------------------------------------
// Typed IPC channels (pipe replacement)
// ---------------------------------------------------------------------------

/// Create a typed byte-stream channel (replaces raw pipe).
/// Returns `(read_cap, write_cap)`.
pub fn sot_pipe() -> Result<(u64, u64), i64> {
    let packed = sys::sot_channel_create(CHANNEL_TYPE_STREAM).map_err(map_kernel_err)?;

    let read_cap = packed & 0xFFFF_FFFF;
    let write_cap = packed >> 32;

    sot_provenance_record(0, OP_PIPE, packed);

    Ok((read_cap, write_cap))
}

// ---------------------------------------------------------------------------
// File operations via SO invocation
// ---------------------------------------------------------------------------

/// Open a file through the VFS domain via SO invocation.
/// `vfs_cap`: capability for the VFS Secure Object.
/// `path`: file path bytes.
/// `flags`: Linux open flags (O_RDONLY, O_WRONLY, etc.).
pub fn sot_open(vfs_cap: u64, path: &[u8], flags: u32) -> Result<u64, i64> {
    let path_ptr = path.as_ptr() as u64;
    let arg1 = (path.len() as u64) | ((flags as u64) << 32);

    let file_cap =
        sys::so_invoke(vfs_cap, SO_METHOD_READ, path_ptr, arg1).map_err(map_kernel_err)?;

    sot_provenance_record(0, OP_OPEN, file_cap);
    Ok(file_cap)
}

/// Read from a file capability via SO invocation.
/// Returns the number of bytes read.
pub fn sot_read(file_cap: u64, buf: &mut [u8]) -> Result<usize, i64> {
    let bytes_read = sys::so_invoke(
        file_cap,
        SO_METHOD_READ,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
    .map_err(map_kernel_err)?;

    Ok(bytes_read as usize)
}

/// Write to a file capability via SO invocation.
/// Returns the number of bytes written.
pub fn sot_write(file_cap: u64, buf: &[u8]) -> Result<usize, i64> {
    let bytes_written = sys::so_invoke(
        file_cap,
        SO_METHOD_WRITE,
        buf.as_ptr() as u64,
        buf.len() as u64,
    )
    .map_err(map_kernel_err)?;

    Ok(bytes_written as usize)
}

/// Close a file by revoking its capability.
pub fn sot_close(file_cap: u64) -> Result<(), i64> {
    sot_provenance_record(0, OP_CLOSE, file_cap);
    sys::so_revoke(file_cap).map_err(map_kernel_err)
}

// ---------------------------------------------------------------------------
// Signal delivery
// ---------------------------------------------------------------------------

/// Send a signal to a domain via its signal channel.
/// `signal_cap`: capability for the target domain's signal SO.
pub fn sot_kill(target_domain: u32, signal: i32, signal_cap: u64) -> Result<(), i64> {
    sys::so_invoke(signal_cap, SO_METHOD_SIGNAL, signal as u64, 0)
        .map(|_| ())
        .map_err(map_kernel_err)?;

    sot_provenance_record(target_domain, OP_KILL, signal as u64);
    Ok(())
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

const PROVENANCE_LOG_SIZE: usize = 256;

#[repr(C)]
struct ProvenanceEntry {
    timestamp: u64,
    domain_id: u32,
    operation: u16,
    _pad: u16,
    so_id: u64,
}

static mut PROVENANCE_LOG: [ProvenanceEntry; PROVENANCE_LOG_SIZE] = {
    const EMPTY: ProvenanceEntry = ProvenanceEntry {
        timestamp: 0,
        domain_id: 0,
        operation: 0,
        _pad: 0,
        so_id: 0,
    };
    [EMPTY; PROVENANCE_LOG_SIZE]
};
static mut PROVENANCE_IDX: usize = 0;

/// Record a provenance entry (best-effort circular log, single-writer).
pub fn sot_provenance_record(domain_id: u32, operation: u16, so_id: u64) {
    unsafe {
        let idx = PROVENANCE_IDX % PROVENANCE_LOG_SIZE;
        PROVENANCE_LOG[idx] = ProvenanceEntry {
            timestamp: sys::rdtsc(),
            domain_id,
            operation,
            _pad: 0,
            so_id,
        };
        PROVENANCE_IDX = PROVENANCE_IDX.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Domain enter helper
// ---------------------------------------------------------------------------

/// Enter a domain (switch the current thread's active domain context).
pub fn sot_domain_enter(domain_id: u32) -> Result<(), i64> {
    sys::sot_domain_enter(domain_id as u64, 0).map_err(map_kernel_err)
}
