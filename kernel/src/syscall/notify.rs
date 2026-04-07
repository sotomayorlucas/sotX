//! Notification syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::ipc::notify;
use crate::pool::PoolHandle;
use sotos_common::SysError;

use super::{SYS_NOTIFY_CREATE, SYS_NOTIFY_WAIT, SYS_NOTIFY_SIGNAL};

/// Handle notification syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_NOTIFY_CREATE — create a new notification object, return cap_id
        SYS_NOTIFY_CREATE => {
            match notify::create() {
                Some(n) => {
                    match cap::insert(CapObject::Notification { id: n.0.raw() }, Rights::ALL, None) {
                        Some(cap_id) => frame.rax = cap_id.raw() as u64,
                        None => frame.rax = SysError::OutOfResources as i64 as u64,
                    }
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

        // SYS_NOTIFY_WAIT — wait on notification (cap_id in rdi, requires READ)
        SYS_NOTIFY_WAIT => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Notification { id }) => {
                    match notify::wait(PoolHandle::from_raw(id)) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_NOTIFY_SIGNAL — signal notification (cap_id in rdi, requires WRITE)
        SYS_NOTIFY_SIGNAL => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => {
                    match notify::signal(PoolHandle::from_raw(id)) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        _ => return false,
    }
    true
}
