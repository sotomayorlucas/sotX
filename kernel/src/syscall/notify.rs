//! Notification syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::ipc::notify;
use crate::pool::PoolHandle;
use crate::sched::{self, ThreadId};
use sotos_common::SysError;

use super::{
    SYS_NOTIFY_CREATE, SYS_NOTIFY_WAIT, SYS_NOTIFY_SIGNAL,
    SYS_THREAD_NOTIFY, SYS_NOTIFY_POLL,
};

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

        // SYS_THREAD_NOTIFY — register a death notification for a target thread.
        // rdi = thread_cap (READ), rsi = notification_cap (WRITE).
        // When the target thread transitions to Dead, the kernel calls
        // notify::signal() on the registered notification. Multiple registrations
        // per thread are allowed (table holds up to 64 entries globally).
        //
        // Returns 0 on success, -OutOfResources if the table is full,
        // -InvalidCap if either cap is the wrong type.
        SYS_THREAD_NOTIFY => {
            // Validate the thread cap and extract the tid.
            let tid = match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Thread { id }) => ThreadId(id),
                Ok(_) => {
                    frame.rax = SysError::InvalidCap as i64 as u64;
                    return true;
                }
                Err(e) => {
                    frame.rax = e as i64 as u64;
                    return true;
                }
            };
            // Validate the notification cap and extract the pool handle.
            let notify_handle = match cap::validate(frame.rsi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => PoolHandle::from_raw(id),
                Ok(_) => {
                    frame.rax = SysError::InvalidCap as i64 as u64;
                    return true;
                }
                Err(e) => {
                    frame.rax = e as i64 as u64;
                    return true;
                }
            };
            match sched::register_thread_notify(tid, notify_handle) {
                Ok(()) => frame.rax = 0,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_NOTIFY_POLL — non-blocking check of a notification's pending bit.
        // rdi = notify_cap (READ). Returns 1 if pending (and clears), 0 otherwise.
        // Used by supervisors that need to poll many notifications without blocking.
        SYS_NOTIFY_POLL => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Notification { id }) => {
                    frame.rax = notify::take_pending(PoolHandle::from_raw(id)) as u64;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        _ => return false,
    }
    true
}
