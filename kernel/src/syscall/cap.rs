//! Capability management syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapId, Rights};
use sotos_common::SysError;

use super::{
    USER_ADDR_LIMIT,
    SYS_CAP_GRANT, SYS_CAP_REVOKE, SYS_CHMOD, SYS_CHOWN,
};

/// Handle capability syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_CAP_GRANT — delegate a capability with restricted rights
        // rdi = source cap_id, rsi = rights mask
        SYS_CAP_GRANT => {
            match cap::grant(frame.rdi as u32, frame.rsi as u32) {
                Ok(cap_id) => frame.rax = cap_id.raw() as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CAP_REVOKE — revoke a capability and all derivatives
        // rdi = cap_id (requires REVOKE right)
        SYS_CAP_REVOKE => {
            match cap::validate(frame.rdi as u32, Rights::REVOKE) {
                Ok(_) => {
                    cap::revoke(CapId::new(frame.rdi as u32));
                    frame.rax = 0;
                }
                Err(e) => frame.rax = e as i64 as u64,
            }
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
