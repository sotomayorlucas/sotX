//! Scheduling domain syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::pool::PoolHandle;
use crate::sched::{self, ThreadId};
use sotos_common::SysError;

use super::{
    SYS_DOMAIN_CREATE, SYS_DOMAIN_ATTACH, SYS_DOMAIN_DETACH,
    SYS_DOMAIN_ADJUST, SYS_DOMAIN_INFO,
};

/// Handle scheduling domain syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_DOMAIN_CREATE — create a scheduling domain
        // rdi = quantum_ms, rsi = period_ms; returns domain cap_id
        SYS_DOMAIN_CREATE => {
            let quantum_ms = frame.rdi;
            let period_ms = frame.rsi;
            if quantum_ms == 0 || period_ms == 0 || quantum_ms > period_ms {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Convert ms to ticks: 1 tick = 10ms (100 Hz timer).
                let quantum_ticks = core::cmp::max(1, (quantum_ms / 10) as u32);
                let period_ticks = core::cmp::max(1, (period_ms / 10) as u32);
                match sched::create_domain(quantum_ticks, period_ticks) {
                    Some(handle) => {
                        match cap::insert(CapObject::Domain { id: handle.raw() }, Rights::ALL, None) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => frame.rax = SysError::OutOfResources as i64 as u64,
                        }
                    }
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

        // SYS_DOMAIN_ATTACH — attach thread to domain
        // rdi = domain_cap, rsi = thread_cap; requires WRITE on both
        SYS_DOMAIN_ATTACH => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    match cap::validate(frame.rsi as u32, Rights::WRITE) {
                        Ok(CapObject::Thread { id: tid }) => {
                            match sched::attach_to_domain(PoolHandle::from_raw(dom_id), ThreadId(tid)) {
                                Ok(()) => frame.rax = 0,
                                Err(e) => frame.rax = e as i64 as u64,
                            }
                        }
                        Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_DOMAIN_DETACH — detach thread from domain
        // rdi = domain_cap, rsi = thread_cap; requires WRITE on both
        SYS_DOMAIN_DETACH => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    match cap::validate(frame.rsi as u32, Rights::WRITE) {
                        Ok(CapObject::Thread { id: tid }) => {
                            match sched::detach_from_domain(PoolHandle::from_raw(dom_id), ThreadId(tid)) {
                                Ok(()) => frame.rax = 0,
                                Err(e) => frame.rax = e as i64 as u64,
                            }
                        }
                        Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_DOMAIN_ADJUST — adjust domain quantum
        // rdi = domain_cap (WRITE), rsi = new_quantum_ms
        SYS_DOMAIN_ADJUST => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    let new_quantum_ms = frame.rsi;
                    if new_quantum_ms == 0 {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let new_quantum_ticks = core::cmp::max(1, (new_quantum_ms / 10) as u32);
                        match sched::adjust_domain(PoolHandle::from_raw(dom_id), new_quantum_ticks) {
                            Ok(()) => frame.rax = 0,
                            Err(e) => frame.rax = e as i64 as u64,
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_DOMAIN_INFO — query domain budget info
        // rdi = domain_cap (READ); returns rdi=quantum, rsi=consumed, rdx=period
        SYS_DOMAIN_INFO => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    match sched::domain_info(PoolHandle::from_raw(dom_id)) {
                        Some((quantum, consumed, period)) => {
                            frame.rax = 0;
                            frame.rdi = quantum as u64;
                            frame.rsi = consumed as u64;
                            frame.rdx = period as u64;
                        }
                        None => frame.rax = SysError::InvalidArg as i64 as u64,
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
