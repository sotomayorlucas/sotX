//! Capability management syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapId, Rights};
use sotos_common::{CapInfo, SysError, CAP_LIST_MAX};

use super::{SYS_CAP_GRANT, SYS_CAP_LIST, SYS_CAP_REVOKE, SYS_CHMOD, SYS_CHOWN, USER_ADDR_LIMIT};

/// Handle capability syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_CAP_GRANT — delegate a capability with restricted rights
        // rdi = source cap_id, rsi = rights mask
        SYS_CAP_GRANT => match cap::grant(frame.rdi as u32, frame.rsi as u32) {
            Ok(cap_id) => frame.rax = cap_id.raw() as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_CAP_REVOKE — revoke a capability and all derivatives
        // rdi = cap_id (requires REVOKE right)
        SYS_CAP_REVOKE => match cap::validate(frame.rdi as u32, Rights::REVOKE) {
            Ok(_) => {
                cap::revoke(CapId::new(frame.rdi as u32));
                frame.rax = 0;
            }
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_CAP_LIST — enumerate occupied cap-table slots.
        // rdi = userspace *mut CapInfo, rsi = max entry count (clamped to CAP_LIST_MAX).
        // Returns number of entries written, or negative SysError.
        //
        // Validates: pointer is non-null, user-range, 8-byte aligned, and the
        // full buffer [ptr, ptr + count*sizeof(CapInfo)) stays below
        // USER_ADDR_LIMIT. Walks `cap::for_each` under the table lock.
        SYS_CAP_LIST => {
            let out_ptr = frame.rdi;
            let max_count = (frame.rsi as usize).min(CAP_LIST_MAX);
            let entry_size = core::mem::size_of::<CapInfo>() as u64;

            if out_ptr == 0
                || out_ptr >= USER_ADDR_LIMIT
                || (out_ptr & 0x7) != 0
                || max_count == 0
            {
                frame.rax = SysError::InvalidArg as i64 as u64;
                return true;
            }

            // Overflow-safe end-of-buffer check.
            let total_bytes = match (max_count as u64).checked_mul(entry_size) {
                Some(n) => n,
                None => {
                    frame.rax = SysError::InvalidArg as i64 as u64;
                    return true;
                }
            };
            let end = match out_ptr.checked_add(total_bytes) {
                Some(e) => e,
                None => {
                    frame.rax = SysError::InvalidArg as i64 as u64;
                    return true;
                }
            };
            if end > USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
                return true;
            }

            let base = out_ptr as *mut CapInfo;
            let mut written: usize = 0;
            cap::for_each(|cap_id, kind, rights| {
                if written >= max_count {
                    return false;
                }
                let info = CapInfo {
                    cap_id: cap_id as u64,
                    kind,
                    rights,
                };
                // SAFETY: bounds-checked above — `base.add(written)` is
                // within a user-writable `[CapInfo; max_count]` span that
                // lives entirely below `USER_ADDR_LIMIT`. CapInfo is
                // `#[repr(C)]` + `Copy`, so a direct write is well-defined
                // under the lock we're holding.
                unsafe {
                    core::ptr::write_volatile(base.add(written), info);
                }
                written += 1;
                true
            });
            frame.rax = written as u64;
        }

        // SYS_CHMOD — change file permissions
        // rdi = path_ptr, rsi = path_len, rdx = mode
        // Forwarded to LUCAS interceptor for threads with redirect set.
        // For non-redirected threads, returns InvalidArg (FS lives in userspace).
        SYS_CHMOD => {
            let path_ptr = frame.rdi;
            let path_len = frame.rsi as usize;
            let _mode = frame.rdx;

            if path_len == 0 || path_len > 255 || path_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Non-redirected thread — FS operations require LUCAS.
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_CHOWN — change file ownership
        // rdi = path_ptr, rsi = path_len, rdx = uid, r8 = gid
        // Forwarded to LUCAS interceptor for threads with redirect set.
        // For non-redirected threads, returns InvalidArg (FS lives in userspace).
        SYS_CHOWN => {
            let path_ptr = frame.rdi;
            let path_len = frame.rsi as usize;
            let _uid = frame.rdx;
            let _gid = frame.r8;

            if path_len == 0 || path_len > 255 || path_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Non-redirected thread — FS operations require LUCAS.
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        _ => return false,
    }
    true
}
